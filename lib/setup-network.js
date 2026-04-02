import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';

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

/** Name of the custom iptables chain */
const CHAIN = 'J41_AGENT_OUT';

/** Name of the Docker network */
const DOCKER_NETWORK = 'j41-isolated';

/**
 * Ensure ~/.j41/ exists.
 */
function ensureJ41Dir() {
  fs.mkdirSync(J41_DIR, { recursive: true });
}

/**
 * Return true if the Docker network already exists.
 * @returns {boolean}
 */
function networkExists() {
  try {
    execSync(`docker network inspect ${DOCKER_NETWORK}`, { stdio: 'pipe', timeout: 10000 });
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
    const out = execSync(`dig +short "${host}" A`, { stdio: 'pipe', timeout: 10000 })
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
 * Flush and re-create the J41_AGENT_OUT iptables chain.
 * @param {Array<{host: string, port: number}>} endpoints
 */
function rebuildIptables(endpoints) {
  // Flush existing chain (ignore errors if chain doesn't exist yet)
  try {
    execSync(`sudo iptables -F ${CHAIN}`, { stdio: 'pipe', timeout: 10000 });
    execSync(`sudo iptables -X ${CHAIN}`, { stdio: 'pipe', timeout: 10000 });
  } catch {
    // Chain didn't exist — fine
  }

  // Create chain
  execSync(`sudo iptables -N ${CHAIN}`, { stdio: 'pipe', timeout: 10000 });

  // Allow DNS (udp/tcp port 53)
  execSync(`sudo iptables -A ${CHAIN} -p udp --dport 53 -j ACCEPT`, {
    stdio: 'pipe',
    timeout: 10000,
  });
  execSync(`sudo iptables -A ${CHAIN} -p tcp --dport 53 -j ACCEPT`, {
    stdio: 'pipe',
    timeout: 10000,
  });

  // Per-endpoint: resolve → add ACCEPT rules
  for (const endpoint of endpoints) {
    const ips = resolveHost(endpoint.host);
    for (const ip of ips) {
      execSync(
        `sudo iptables -A ${CHAIN} -p tcp -d "${ip}" --dport ${endpoint.port} -j ACCEPT`,
        { stdio: 'pipe', timeout: 10000 },
      );
    }
  }

  // DROP everything else
  execSync(`sudo iptables -A ${CHAIN} -j DROP`, { stdio: 'pipe', timeout: 10000 });
}

/**
 * Set up the J41 Docker network and default network allowlist, then configure iptables.
 *
 * Creates:
 *   - Docker network `j41-isolated` (internal bridge, ICC disabled)
 *   - `~/.j41/network-allowlist.json` with default endpoints
 *   - iptables chain `J41_AGENT_OUT`
 */
export function setupNetwork() {
  ensureJ41Dir();

  // Create Docker network if it doesn't exist
  if (!networkExists()) {
    execSync(
      `docker network create --internal --driver bridge -o com.docker.network.bridge.enable_icc=false ${DOCKER_NETWORK}`,
      { stdio: 'inherit', timeout: 30000 },
    );
  }

  // Write default allowlist (overwrite to reset)
  fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify(DEFAULT_ENDPOINTS, null, 2), 'utf8');

  // Configure iptables
  rebuildIptables(DEFAULT_ENDPOINTS);
}

/**
 * Re-read `~/.j41/network-allowlist.json` and rebuild the iptables chain with
 * freshly-resolved IP addresses for every entry.
 */
export function resolveAndPinDNS() {
  let endpoints = DEFAULT_ENDPOINTS;

  try {
    const raw = fs.readFileSync(ALLOWLIST_PATH, 'utf8');
    endpoints = JSON.parse(raw);
  } catch {
    // Allowlist not found or corrupt — fall back to defaults
  }

  rebuildIptables(endpoints);
}
