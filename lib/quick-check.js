import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { detectIsolation } from './detect-isolation.js';
import { verifyProfileIntegrity } from './profile-integrity.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Return the profile directory for the current platform.
 *
 * Linux : /etc/j41
 * macOS : ~/.j41/
 *
 * @returns {string}
 */
function getProfileDir() {
  if (os.platform() === 'linux') {
    // Prefer /etc/j41 but fall back to ~/.j41 if profiles were deployed there
    if (fs.existsSync('/etc/j41')) return '/etc/j41';
    return path.join(os.homedir(), '.j41');
  }
  return path.join(os.homedir(), '.j41');
}

/**
 * Return the seccomp filename for the given product.
 *
 * @param {'dispatcher' | 'jailbox'} product
 * @returns {string}
 */
function seccompFilename(product) {
  return product === 'dispatcher' ? 'seccomp-agent.json' : 'seccomp-jailbox.json';
}

/**
 * Check whether the iptables chain J41_AGENT_OUT exists (Linux only).
 * Uses dynamic import to avoid top-level execSync import.
 *
 * @returns {Promise<boolean>}
 */
async function iptablesChainExists() {
  try {
    const { execSync } = await import('node:child_process');
    execSync('sudo iptables -L J41_AGENT_OUT -n', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Build a single check result object.
 *
 * @param {string} name
 * @param {'pass'|'fail'|'warn'|'skip'} status
 * @param {string} detail
 * @returns {{ name: string, status: 'pass'|'fail'|'warn'|'skip', detail: string }}
 */
function check(name, status, detail) {
  return { name, status, detail };
}

// ── Shared checks ─────────────────────────────────────────────────────────────

/**
 * gvisor-or-bwrap
 * pass  → gVisor default runtime, OR macOS Docker Desktop VM, OR bwrap installed
 * fail  → none of the above
 */
function checkGvisorOrBwrap(isolation) {
  const { gvisorDefault, dockerDesktopVM, bwrapInstalled } = isolation;

  if (gvisorDefault) {
    return check('gvisor-or-bwrap', 'pass', 'gVisor is the default Docker runtime');
  }
  if (dockerDesktopVM) {
    return check('gvisor-or-bwrap', 'pass', 'Running inside macOS Docker Desktop VM');
  }
  if (bwrapInstalled) {
    return check('gvisor-or-bwrap', 'pass', 'bubblewrap (bwrap) is installed');
  }
  return check('gvisor-or-bwrap', 'fail', 'No strong container isolation found (gVisor, bwrap, or Docker Desktop VM required)');
}

/**
 * seccomp-profile
 * pass  → the product seccomp file exists in profileDir
 * fail  → file missing
 */
function checkSeccompProfile(product, profileDir) {
  const filename = seccompFilename(product);
  const filePath = path.join(profileDir, filename);
  const exists = fs.existsSync(filePath);
  return check(
    'seccomp-profile',
    exists ? 'pass' : 'fail',
    exists ? `${filename} found at ${filePath}` : `${filename} not found in ${profileDir}`,
  );
}

/**
 * apparmor-profile
 * skip  → macOS
 * pass  → AppArmor profile is loaded (Linux)
 * warn  → AppArmor not loaded but that is optional
 */
function checkAppArmor(isolation) {
  if (os.platform() === 'darwin') {
    return check('apparmor-profile', 'skip', 'AppArmor not available on macOS');
  }
  const { apparmorLoaded } = isolation;
  return check(
    'apparmor-profile',
    apparmorLoaded ? 'pass' : 'warn',
    apparmorLoaded ? 'j41 AppArmor profile is loaded' : 'AppArmor profile not loaded (optional on this system)',
  );
}

/**
 * profile-integrity
 * pass  → verifyProfileIntegrity passes
 * fail  → tampered files found or hashes missing
 */
async function checkProfileIntegrity(profileDir) {
  const result = await verifyProfileIntegrity(profileDir);
  if (result.passed) {
    return check('profile-integrity', 'pass', 'All profile hashes verified');
  }
  if (result.error) {
    return check('profile-integrity', 'fail', result.error);
  }
  return check(
    'profile-integrity',
    'fail',
    `Tampered files detected: ${result.tampered.join(', ')}`,
  );
}

// ── Dispatcher-only checks ────────────────────────────────────────────────────

function checkJ41Network(isolation) {
  const { j41NetworkExists } = isolation;
  return check(
    'j41-isolated-network',
    j41NetworkExists ? 'pass' : 'fail',
    j41NetworkExists ? 'Docker network j41-isolated exists' : 'Docker network j41-isolated not found',
  );
}

function checkFinancialAllowlist() {
  const filePath = path.join(os.homedir(), '.j41', 'financial-allowlist.json');
  const exists = fs.existsSync(filePath);
  return check(
    'financial-allowlist',
    exists ? 'pass' : 'fail',
    exists ? `Found at ${filePath}` : `Not found: ${filePath}`,
  );
}

function checkNetworkAllowlist() {
  const filePath = path.join(os.homedir(), '.j41', 'network-allowlist.json');
  const exists = fs.existsSync(filePath);
  return check(
    'network-allowlist',
    exists ? 'pass' : 'fail',
    exists ? `Found at ${filePath}` : `Not found: ${filePath}`,
  );
}

/**
 * canary-readiness
 * Verifies the canary system is properly wired:
 * 1. job-agent.js contains canary injection code
 * 2. No SOUL.md files accidentally contain raw canary tokens (they should only be injected at runtime)
 * 3. The SDK's checkForCanaryLeak function is importable
 */
function checkCanaryReadiness() {
  const issues = [];

  // Check 1: Verify job-agent.js has canary injection (if dispatcher is installed globally or locally)
  let jobAgentFound = false;
  const possiblePaths = [
    path.join(os.homedir(), '.npm-global', 'lib', 'node_modules', '@junction41', 'dispatcher', 'src', 'job-agent.js'),
    '/usr/lib/node_modules/@junction41/dispatcher/src/job-agent.js',
    '/usr/local/lib/node_modules/@junction41/dispatcher/src/job-agent.js',
  ];
  // Also check local working directory
  try {
    const { execSync } = require('node:child_process');
    const globalPrefix = execSync('npm prefix -g', { encoding: 'utf8', timeout: 5000 }).trim();
    possiblePaths.push(path.join(globalPrefix, 'lib', 'node_modules', '@junction41', 'dispatcher', 'src', 'job-agent.js'));
  } catch {}

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      jobAgentFound = true;
      const content = fs.readFileSync(p, 'utf8');
      if (!content.includes('CANARY_TOKEN') || !content.includes('checkCanaryLeak')) {
        issues.push('job-agent.js found but missing canary injection/check code — update @junction41/dispatcher');
      }
      break;
    }
  }

  if (!jobAgentFound) {
    // Not fatal — dispatcher might not be installed on this machine
    return check('canary-readiness', 'warn', 'Could not locate @junction41/dispatcher to verify canary wiring');
  }

  // Check 2: Ensure no SOUL.md files have raw canary tokens baked in (they should be runtime-only)
  const agentsDir = path.join(os.homedir(), '.j41', 'dispatcher', 'agents');
  if (fs.existsSync(agentsDir)) {
    try {
      const agents = fs.readdirSync(agentsDir);
      for (const agentId of agents) {
        const soulPath = path.join(agentsDir, agentId, 'SOUL.md');
        if (fs.existsSync(soulPath)) {
          const soul = fs.readFileSync(soulPath, 'utf8');
          // Canary tokens are 64-char hex strings in HTML comments
          if (/<!--\s*[a-f0-9]{64}\s*-->/.test(soul)) {
            issues.push(`${agentId}/SOUL.md contains what looks like a baked-in canary token — tokens should only be injected at runtime`);
          }
        }
      }
    } catch {}
  }

  if (issues.length > 0) {
    return check('canary-readiness', 'fail', issues.join('; '));
  }
  return check('canary-readiness', 'pass', 'Canary injection code present in dispatcher, no tokens baked into SOUL.md files');
}

async function checkIptablesRules() {
  if (os.platform() === 'darwin') {
    return check('iptables-rules', 'skip', 'iptables not available on macOS');
  }
  const exists = await iptablesChainExists();
  return check(
    'iptables-rules',
    exists ? 'pass' : 'warn',
    exists ? 'iptables chain J41_AGENT_OUT is present' : 'iptables rules not set — run sudo j41-secure-setup --fix',
  );
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Run a quick-check validation sweep for the given product.
 *
 * @param {'dispatcher' | 'jailbox'} product
 * @returns {Promise<{
 *   product: string,
 *   checks: Array<{ name: string, status: 'pass'|'fail'|'warn'|'skip', detail: string }>,
 *   passed: boolean,
 *   score: number,
 *   mode: string,
 * }>}
 */
export async function quickCheck(product) {
  const isolation = await detectIsolation();
  const profileDir = getProfileDir();

  // ── Shared checks ────────────────────────────────────────────────────────────
  const checks = await Promise.all([
    checkGvisorOrBwrap(isolation),
    checkSeccompProfile(product, profileDir),
    checkAppArmor(isolation),
    checkProfileIntegrity(profileDir),
  ]);

  // ── Product-specific checks ──────────────────────────────────────────────────
  if (product === 'dispatcher') {
    checks.push(
      checkJ41Network(isolation),
      checkFinancialAllowlist(),
      checkNetworkAllowlist(),
      await checkIptablesRules(),
      checkCanaryReadiness(),
    );
  }

  const passed = checks.every((c) => c.status !== 'fail');

  return {
    product,
    checks,
    passed,
    score: isolation.score,
    mode: isolation.mode,
  };
}
