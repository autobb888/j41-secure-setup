import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync, execFileSync } from 'node:child_process';

/** Directory for J41 config files */
const J41_DIR = path.join(os.homedir(), '.j41');

/** Path to the network allowlist file */
const ALLOWLIST_PATH = path.join(J41_DIR, 'network-allowlist.json');

/** Default endpoints allowed outbound from agent containers */
const DEFAULT_ENDPOINTS = [
  { host: 'api.junction41.io', port: 443, required: true },
  { host: 'api.openai.com', port: 443 },
  { host: 'api.anthropic.com', port: 443 },
  { host: 'api.groq.com', port: 443 },
];

// Audit 2026-06-02 H1: the set of hosts allowed by DEFAULT_ENDPOINTS is the
// signed baseline. resolveAndPinDNS() now refuses to honor an entry not in
// this baseline UNLESS the operator passes J41_ALLOWLIST_EXTRA=<host:port,...>
// — in which case the addition shows up in stderr with a clear warning.
// This stops "attacker writes ~/.j41/network-allowlist.json with an extra
// host → next setup adds an iptables ACCEPT for the attacker IP" (audit H1).
const DEFAULT_ENDPOINT_KEYS = new Set(DEFAULT_ENDPOINTS.map(e => `${e.host}:${e.port}`));

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
 * Public DNS resolvers the egress firewall permits on :53 from the bridge.
 * On modern Docker, the embedded resolver (127.0.0.11) forwards its UPSTREAM
 * query out the container bridge, so with a default-deny egress chain those
 * forwards are dropped and name resolution fails. We therefore allow :53 ONLY
 * to these exact resolvers — they MUST match the Docker daemon's configured
 * upstreams (/etc/docker/daemon.json "dns"). This is a bounded channel (two
 * fixed public resolvers, not arbitrary): bulk data egress stays locked to the
 * :443 allowlist. Residual: DNS to these resolvers is a low-bandwidth exfil
 * vector (recursive lookups to an attacker-controlled authoritative NS). The
 * fully-tight fix is a local filtering resolver that only answers allowlisted
 * names — tracked as future hardening.
 */
const DNS_RESOLVERS = ['8.8.8.8', '1.1.1.1'];

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
 * Resolve a hostname to its IPv4 addresses using `dig +short`.
 * Returns an empty array if resolution fails or dig is not available.
 * @param {string} host
 * @returns {string[]}
 */
function resolveHost(host) {
  try {
    const out = execFileSync('dig', ['+short', host, 'A'], { stdio: 'pipe', timeout: 10000 })
      .toString()
      .trim();
    if (!out) return [];
    return out
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => /^(\d{1,3}\.){3}\d{1,3}$/.test(l));
  } catch {
    return [];
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
 * Remove the DOCKER-USER hook and the custom chain (both families), idempotently.
 * Deletes the jump repeatedly in case duplicates accumulated from prior runs.
 */
function teardownChain() {
  for (const bin of ['iptables', 'ip6tables']) {
    // Delete the DOCKER-USER jump (repeat until it's gone — clears duplicates)
    for (let i = 0; i < 10; i++) {
      try {
        execFileSync('sudo', [bin, '-D', 'DOCKER-USER', '-i', BRIDGE_IF, '-j', CHAIN], { stdio: 'pipe', timeout: 10000 });
      } catch { break; }
    }
    try { execFileSync('sudo', [bin, '-F', CHAIN], { stdio: 'pipe', timeout: 10000 }); } catch { /* no chain */ }
    try { execFileSync('sudo', [bin, '-X', CHAIN], { stdio: 'pipe', timeout: 10000 }); } catch { /* no chain */ }
  }
}

/**
 * Rebuild the egress firewall for the j41-isolated bridge as a DEFAULT-DENY
 * allowlist, hooked into DOCKER-USER (evaluated before Docker's own FORWARD
 * ACCEPTs) and scoped to the bridge interface so OTHER Docker networks are
 * untouched.
 *
 * Model (traffic egressing containers on br-j41iso):
 *   - ESTABLISHED,RELATED   → ACCEPT   (return path for allowed connections)
 *   - tcp :<port> to each allowlisted, freshly-resolved IP → ACCEPT
 *   - everything else       → DROP     (default deny — no arbitrary egress,
 *                                        no DNS-tunnel exfil out the bridge)
 *
 * DNS is intentionally NOT allowed out the bridge: job containers must use
 * Docker's embedded resolver (127.0.0.11), whose upstream is set at the daemon
 * (/etc/docker/daemon.json "dns"). The embedded resolver's own upstream query
 * leaves via the host, not br-j41iso, so it is unaffected by these rules — while
 * a container trying to reach an external :53 directly is dropped here.
 * NOTE: the dispatcher must NOT set a per-container `Dns:[public]` override
 * (that traffic would egress the bridge and be dropped). See the dispatcher fix.
 *
 * @param {Array<{host: string, port: number}>} endpoints
 */
function rebuildIptables(endpoints) {
  teardownChain();

  // Create the chain (v4 + v6).
  iptablesBoth(['-N', CHAIN]);

  // 1) Allow return traffic for already-permitted connections.
  iptablesBoth(['-A', CHAIN, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']);

  // 1b) Allow :53 ONLY to the fixed daemon DNS resolvers (v4). Needed because
  // Docker's embedded resolver forwards upstream out the bridge; without this,
  // name resolution fails under default-deny. Bounded exfil channel — see
  // DNS_RESOLVERS docstring.
  for (const dns of DNS_RESOLVERS) {
    iptables4(['-A', CHAIN, '-p', 'udp', '-d', dns, '--dport', '53', '-j', 'ACCEPT']);
    iptables4(['-A', CHAIN, '-p', 'tcp', '-d', dns, '--dport', '53', '-j', 'ACCEPT']);
  }

  // 2) Per-endpoint ACCEPT for each resolved IPv4 (v4 only — IPs are A records).
  for (const endpoint of endpoints) {
    const port = parseInt(endpoint.port, 10);
    if (isNaN(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid port: ${endpoint.port}`);
    }
    const ips = resolveHost(endpoint.host);
    for (const ip of ips) {
      iptables4(['-A', CHAIN, '-p', 'tcp', '-d', ip, '--dport', String(port), '-j', 'ACCEPT']);
    }
  }

  // 3) Default deny — everything not explicitly accepted above (v4 + v6).
  iptablesBoth(['-A', CHAIN, '-j', 'DROP']);

  // Hook: send ONLY j41-bridge egress through our chain, at the TOP of
  // DOCKER-USER (before Docker's default RETURN). Other interfaces/networks
  // are never matched, so they behave normally.
  iptablesBoth(['-I', 'DOCKER-USER', '-i', BRIDGE_IF, '-j', CHAIN]);
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
  // DOCKER-USER default-deny allowlist in rebuildIptables(), not by air-gapping.
  // Fixed bridge name so the firewall can match the interface.
  execFileSync('docker', [
    'network', 'create', '--driver', 'bridge',
    '-o', 'com.docker.network.bridge.enable_icc=false',
    '-o', `com.docker.network.bridge.name=${BRIDGE_IF}`,
    DOCKER_NETWORK,
  ], { stdio: 'inherit', timeout: 30000 });
}

/**
 * Set up the J41 Docker network and default network allowlist, then configure iptables.
 *
 * Creates:
 *   - Docker network `j41-isolated` (egress-capable bridge, ICC disabled,
 *     fixed bridge iface `br-j41iso`)
 *   - `~/.j41/network-allowlist.json` with default endpoints
 *   - DOCKER-USER default-deny egress allowlist for the bridge (chain `J41_AGENT_OUT`)
 */
export function setupNetwork() {
  ensureJ41Dir();

  ensureNetwork();

  // Write default allowlist only if it doesn't already exist (preserve user edits)
  if (!fs.existsSync(ALLOWLIST_PATH)) {
    fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify(DEFAULT_ENDPOINTS, null, 2), { encoding: 'utf8', mode: 0o600 });
  }

  // Configure iptables
  rebuildIptables(DEFAULT_ENDPOINTS);
}

/**
 * Re-read `~/.j41/network-allowlist.json` and rebuild the iptables chain with
 * freshly-resolved IP addresses for every entry.
 *
 * Audit 2026-06-02 H1: filter to the baseline DEFAULT_ENDPOINTS unless the
 * operator opts in to extras via J41_ALLOWLIST_EXTRA. An attacker who writes
 * extra hosts to ~/.j41/network-allowlist.json cannot get them pinned into
 * iptables without that explicit opt-in.
 */
export function resolveAndPinDNS() {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf8'));
  } catch {
    raw = DEFAULT_ENDPOINTS;
  }

  if (!Array.isArray(raw)) raw = DEFAULT_ENDPOINTS;

  const allowExtras = (process.env.J41_ALLOWLIST_EXTRA || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  const allowExtraKeys = new Set(allowExtras);

  const endpoints = [];
  for (const e of raw) {
    if (!e || typeof e.host !== 'string' || typeof e.port !== 'number') continue;
    const key = `${e.host}:${e.port}`;
    if (DEFAULT_ENDPOINT_KEYS.has(key)) {
      endpoints.push(e);
    } else if (allowExtraKeys.has(key)) {
      process.stderr.write(
        `[setup-network] Accepting extra endpoint ${key} (J41_ALLOWLIST_EXTRA opt-in)\n`,
      );
      endpoints.push(e);
    } else {
      process.stderr.write(
        `[setup-network] REFUSING endpoint ${key} from ${ALLOWLIST_PATH} — ` +
        `not in default baseline. Add to J41_ALLOWLIST_EXTRA to allow.\n`,
      );
    }
  }
  // Re-add any required defaults that got filtered out
  for (const def of DEFAULT_ENDPOINTS) {
    if (def.required && !endpoints.some(e => e.host === def.host && e.port === def.port)) {
      endpoints.push(def);
    }
  }

  rebuildIptables(endpoints);
}
