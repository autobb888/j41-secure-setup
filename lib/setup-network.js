import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

/** Directory for J41 config files */
const J41_DIR = path.join(os.homedir(), '.j41');

/** Name of the custom iptables chain */
const CHAIN = 'J41_AGENT_OUT';

/** Name of the Docker network */
const DOCKER_NETWORK = 'j41-isolated';

/**
 * Fixed Linux bridge interface name for the j41-isolated network, so the
 * egress firewall can match on the interface (survives container churn) rather
 * than per-container IPs. Set via `-o com.docker.network.bridge.name`.
 */
const BRIDGE_IF = 'br-j41iso';

/**
 * Host-side egress proxy port — MUST match the dispatcher's EGRESS_PROXY_PORT.
 * The sandbox (gVisor container) has zero direct external egress; it may reach
 * ONLY this port on the bridge gateway. The proxy (a host process) owns the
 * per-job domain allowlist and handles DNS.
 */
export const EGRESS_PROXY_PORT = 9847;

/**
 * Ensure ~/.j41/ exists.
 */
function ensureJ41Dir() {
  fs.mkdirSync(J41_DIR, { recursive: true, mode: 0o700 });
}

/**
 * Return true if the Docker network already exists.
 * @returns {boolean}
 */
function networkExists() {
  try {
    execFileSync('docker', ['network', 'inspect', DOCKER_NETWORK], { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Run a v4 iptables command (must succeed).
 * @param {string[]} args
 */
function iptables4(args) {
  execFileSync('sudo', ['iptables', ...args], { stdio: 'pipe', timeout: 10000 });
}

/**
 * Run an iptables command on BOTH v4 and v6 (v6 non-fatal — may be unavailable
 * or Docker IPv6 disabled). Use for structural rules that should apply to both
 * families (chain create, established-accept, default-drop, the DOCKER-USER hook).
 * @param {string[]} args
 */
function iptablesBoth(args) {
  execFileSync('sudo', ['iptables', ...args], { stdio: 'pipe', timeout: 10000 });
  try {
    execFileSync('sudo', ['ip6tables', ...args], { stdio: 'pipe', timeout: 10000 });
  } catch { /* ip6tables may not be available */ }
}

/**
 * Read the bridge gateway IP from `docker network inspect j41-isolated`.
 * Falls back to 172.18.0.1 if inspection fails or the field is absent.
 * @returns {string}
 */
function getGatewayIp() {
  try {
    const out = execFileSync('docker', ['network', 'inspect', DOCKER_NETWORK], { stdio: 'pipe', timeout: 10000 }).toString();
    const info = JSON.parse(out)[0] || {};
    const config = (info.IPAM && info.IPAM.Config) || [];
    for (const c of config) {
      if (c.Gateway && /^(\d{1,3}\.){3}\d{1,3}$/.test(c.Gateway)) return c.Gateway;
    }
  } catch { /* ignore */ }
  return '172.18.0.1';
}

/**
 * Ordered iptables argv arrays for the proxy-only egress firewall.
 *
 * Sandbox egress is fully default-denied; the sandbox may reach ONLY
 * gatewayIp:proxyPort (the host egress proxy). No direct external egress,
 * no DNS out the bridge — the proxy handles DNS and the per-job domain allowlist.
 *
 * Structural rules (first three) apply to both v4 and v6 (iptablesBoth).
 * INPUT rules (last two) are v4-specific (iptables4) — gateway IP is an A record.
 *
 * @param {{ bridgeIf: string, gatewayIp: string, proxyPort: number }} opts
 * @returns {string[][]}
 */
export function buildRulePlan({ bridgeIf, gatewayIp, proxyPort }) {
  return [
    // FORWARD egress chain: allow return traffic, deny everything else.
    ['-A', CHAIN, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
    ['-A', CHAIN, '-j', 'DROP'],
    // Hook the chain for bridge egress only (before Docker's default RETURN).
    ['-I', 'DOCKER-USER', '-i', bridgeIf, '-j', CHAIN],
    // Host INPUT: sandbox may reach ONLY the egress proxy on the gateway.
    ['-A', 'INPUT', '-i', bridgeIf, '-p', 'tcp', '-d', gatewayIp, '--dport', String(proxyPort), '-j', 'ACCEPT'],
    // Everything else from the bridge is dropped at the INPUT level.
    ['-A', 'INPUT', '-i', bridgeIf, '-j', 'DROP'],
  ];
}

/**
 * Remove the DOCKER-USER hook, the custom chain, and the INPUT rules
 * (both families), idempotently. Deletes each rule repeatedly in case
 * duplicates accumulated from prior runs.
 *
 * @param {string} [gatewayIp] - same IP used when the INPUT accept was added;
 *   if omitted, skips the gateway-specific accept delete (safe on first run).
 */
function teardownChain(gatewayIp) {
  for (const bin of ['iptables', 'ip6tables']) {
    // Delete the DOCKER-USER jump (repeat until it's gone — clears duplicates)
    for (let i = 0; i < 10; i++) {
      try {
        execFileSync('sudo', [bin, '-D', 'DOCKER-USER', '-i', BRIDGE_IF, '-j', CHAIN], { stdio: 'pipe', timeout: 10000 });
      } catch { break; }
    }
    try { execFileSync('sudo', [bin, '-F', CHAIN], { stdio: 'pipe', timeout: 10000 }); } catch { /* no chain */ }
    try { execFileSync('sudo', [bin, '-X', CHAIN], { stdio: 'pipe', timeout: 10000 }); } catch { /* no chain */ }

    // Remove INPUT rules added by buildRulePlan — must match the exact argv used
    // when they were inserted (including -d gatewayIp on the ACCEPT rule).
    if (gatewayIp) {
      for (let i = 0; i < 10; i++) {
        try {
          execFileSync('sudo', [bin, '-D', 'INPUT', '-i', BRIDGE_IF, '-p', 'tcp', '-d', gatewayIp, '--dport', String(EGRESS_PROXY_PORT), '-j', 'ACCEPT'], { stdio: 'pipe', timeout: 10000 });
        } catch { break; }
      }
    }
    for (let i = 0; i < 10; i++) {
      try {
        execFileSync('sudo', [bin, '-D', 'INPUT', '-i', BRIDGE_IF, '-j', 'DROP'], { stdio: 'pipe', timeout: 10000 });
      } catch { break; }
    }
  }
}

/**
 * Rebuild the egress firewall for the j41-isolated bridge as DEFAULT-DENY,
 * allowing ONLY the host egress proxy port on the gateway. The proxy handles
 * DNS and per-job domain allowlisting.
 *
 * Model (traffic from containers on br-j41iso):
 *   FORWARD: ESTABLISHED,RELATED → ACCEPT; everything else → DROP (via J41_AGENT_OUT)
 *   INPUT:   tcp to gatewayIp:EGRESS_PROXY_PORT → ACCEPT; everything else → DROP
 */
function rebuildIptables() {
  const gatewayIp = getGatewayIp();
  teardownChain(gatewayIp);

  // Create the chain (v4 + v6).
  iptablesBoth(['-N', CHAIN]);

  const plan = buildRulePlan({ bridgeIf: BRIDGE_IF, gatewayIp, proxyPort: EGRESS_PROXY_PORT });

  for (const args of plan) {
    // INPUT ACCEPT for the proxy port is IPv4-only (gateway IP is an A record).
    // INPUT catch-all DROP applies to both families — if Docker has IPv6 on
    // br-j41iso, containers must not reach host services over IPv6 either.
    // All structural chain rules (FORWARD) apply to both families.
    const isInputAccept = args[1] === 'INPUT' && args[args.length - 1] === 'ACCEPT';
    if (isInputAccept) {
      iptables4(args);
    } else {
      iptablesBoth(args);
    }
  }
}

/**
 * Inspect the existing network; return true if it is NOT in the shape we want
 * (i.e. it is `--internal`, or lacks our fixed bridge interface name) and must
 * be recreated.
 * @returns {boolean}
 */
function networkNeedsRecreate() {
  try {
    const out = execFileSync('docker', ['network', 'inspect', DOCKER_NETWORK], { stdio: 'pipe', timeout: 10000 }).toString();
    const info = JSON.parse(out)[0] || {};
    const internal = info.Internal === true;
    const bridgeName = (info.Options || {})['com.docker.network.bridge.name'];
    return internal || bridgeName !== BRIDGE_IF;
  } catch {
    return false;
  }
}

/**
 * Create the egress-capable j41-isolated bridge (idempotent). Recreates it if a
 * previous version was `--internal` (air-gapped) or lacked the fixed bridge name.
 */
function ensureNetwork() {
  if (networkExists()) {
    if (!networkNeedsRecreate()) return;
    // Recreate: remove the old (air-gapped / unnamed) network first. This fails
    // if containers are still attached — surface that clearly to the operator.
    try {
      execFileSync('docker', ['network', 'rm', DOCKER_NETWORK], { stdio: 'pipe', timeout: 15000 });
    } catch (e) {
      throw new Error(
        `Cannot recreate ${DOCKER_NETWORK}: 'docker network rm' failed — ` +
        `disconnect any attached containers first (stop the dispatcher / running jobs). ${e.message}`,
      );
    }
  }
  // Egress-capable bridge (NOT --internal); egress is restricted by the
  // DOCKER-USER default-deny firewall in rebuildIptables(), not by air-gapping.
  // Fixed bridge name so the firewall can match the interface.
  execFileSync('docker', [
    'network', 'create', '--driver', 'bridge',
    '-o', 'com.docker.network.bridge.enable_icc=false',
    '-o', `com.docker.network.bridge.name=${BRIDGE_IF}`,
    DOCKER_NETWORK,
  ], { stdio: 'inherit', timeout: 30000 });
}

/**
 * Set up the J41 Docker network and configure the proxy-only egress firewall.
 *
 * Creates:
 *   - Docker network `j41-isolated` (egress-capable bridge, ICC disabled,
 *     fixed bridge iface `br-j41iso`)
 *   - DOCKER-USER default-deny egress firewall for the bridge (chain `J41_AGENT_OUT`)
 *     allowing ONLY tcp to gatewayIp:EGRESS_PROXY_PORT (the host egress proxy)
 *
 * NOTE: `~/.j41/network-allowlist.json` is no longer written here; the proxy
 * manages per-job domain allowlists independently.
 */
export function setupNetwork() {
  ensureJ41Dir();
  ensureNetwork();
  rebuildIptables();
}

/**
 * Rebuild the iptables chain with the current proxy-only firewall plan.
 * Previously this re-resolved DNS and rebuilt per-IP allowlists; now the
 * proxy owns the allowlist, so this is a simple idempotent rebuild.
 */
export function resolveAndPinDNS() {
  rebuildIptables();
}
