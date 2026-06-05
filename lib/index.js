import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';

import { detectPlatform } from './detect-platform.js';
import { detectIsolation } from './detect-isolation.js';
import { installGvisor } from './install-gvisor.js';
import { installBwrap } from './install-bwrap.js';
import { deployProfiles } from './deploy-profiles.js';
import { setupNetwork } from './setup-network.js';
import { setupAllowlist } from './setup-allowlist.js';
import { selfTest } from './self-test.js';
import { quickCheck } from './quick-check.js';

export { quickCheck, selfTest, detectIsolation, detectPlatform };

// ── Constants ─────────────────────────────────────────────────────────────────

// Resolve the user whose ~/.j41 we should write per-user state (markers) into.
// When run under sudo (root with SUDO_USER set), that's the INVOKING user, not
// root — otherwise the marker lands in /root/.j41 while the user-run jailbox
// checks /home/<user>/.j41 and the first-run gate re-fires forever.
function resolveInvokingUser() {
  const sudoUser = process.env.SUDO_USER;
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  if (sudoUser && isRoot) {
    try {
      const fields = execSync(`getent passwd ${sudoUser}`, { encoding: 'utf8' }).trim().split(':');
      return { home: fields[5] || `/home/${sudoUser}`, uid: Number(fields[2]), gid: Number(fields[3]) };
    } catch {
      return { home: `/home/${sudoUser}`, uid: null, gid: null };
    }
  }
  return { home: os.homedir(), uid: null, gid: null };
}
const INVOKING_USER = resolveInvokingUser();
const J41_DIR = path.join(INVOKING_USER.home, '.j41');

// Best-effort chown of a path back to the invoking user (so root-created files
// in the user's home stay readable/owned by them). No-op when not under sudo.
function chownToInvokingUser(p) {
  if (INVOKING_USER.uid != null && INVOKING_USER.gid != null) {
    try { fs.chownSync(p, INVOKING_USER.uid, INVOKING_USER.gid); } catch { /* best effort */ }
  }
}

const PASS = '\u2713';
const FAIL = '\u2717';

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Return the product's display name.
 * @param {'dispatcher'|'jailbox'} product
 * @returns {string}
 */
function displayName(product) {
  return product === 'dispatcher' ? 'Dispatcher' : 'Jailbox';
}

/**
 * Return the security profile target directory for the current platform.
 * Linux: /etc/j41  |  macOS: ~/.j41
 * @param {string} platformOs
 * @returns {string}
 */
function profileTargetDir(platformOs) {
  // Audit 2026-06-02 M-SECURE-SETUP-funds-1: explicit mode 0o700 on /etc/j41
  // — was relying on default umask which may have left it group/world
  // readable on some distros.
  if (platformOs === 'linux') {
    try {
      // 0711 (not 0700): files inside stay 0600 root (content protected) but the
      // non-root jailbox/dispatcher CLI must be able to existsSync the profile by
      // name, else it fail-closes on a profile that is actually deployed.
      fs.mkdirSync('/etc/j41', { recursive: true, mode: 0o711 });
      try { fs.chmodSync('/etc/j41', 0o711); } catch { /* may not be ours */ }
      return '/etc/j41';
    } catch (e) {
      // Fail closed: the jailbox/dispatcher load seccomp ONLY from /etc/j41 on
      // Linux. Silently deploying to ~/.j41 would leave the container running
      // Docker-default seccomp while quickCheck reports the profile active —
      // exactly the false-confidence gap we are closing. Require root instead.
      throw new Error(
        'Cannot create /etc/j41 (need root). On Linux the runtime loads seccomp only from ' +
        '/etc/j41; deploying elsewhere would not be applied. Re-run with sudo:  ' +
        'sudo npx @junction41/secure-setup --jailbox   (original error: ' +
        (e && e.message ? e.message : String(e)) + ')',
      );
    }
  }
  return J41_DIR;
}

// ── Main exports ──────────────────────────────────────────────────────────────

/**
 * Check whether the security setup has been completed for the given product.
 *
 * @param {'dispatcher'|'jailbox'} product
 * @returns {boolean}
 */
export function isInitialized(product) {
  // Audit 2026-06-02 L-SECURE-SETUP-funds-2: file-existence alone is forgeable
  // (a co-tenant can `touch` the path; an attacker can create the file to
  // suppress re-runs and freeze isolation in a partially-applied state).
  // Treat existence as advisory; validate the file is a parseable marker
  // and was written by us within the last 90 days.
  const markerPath = path.join(J41_DIR, `${product}-security-initialized`);
  try {
    const raw = fs.readFileSync(markerPath, 'utf8');
    const data = JSON.parse(raw);
    if (!data || typeof data !== 'object') return false;
    if (typeof data.timestamp !== 'string') return false;
    const age = Date.now() - Date.parse(data.timestamp);
    if (!Number.isFinite(age) || age < 0) return false;
    const NINETY_DAYS = 90 * 24 * 60 * 60 * 1000;
    if (age > NINETY_DAYS) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * Run the first-run security setup for the given product.
 *
 * @param {'dispatcher'|'jailbox'} product
 * @returns {Promise<{ success: boolean, log: string[], score: number, mode: string }>}
 */
export async function setup(product) {
  const log = [];

  function out(msg) {
    console.log(msg);
    log.push(msg);
  }

  // ── Step 1: ensure ~/.j41/ exists ─────────────────────────────────────────
  fs.mkdirSync(J41_DIR, { recursive: true, mode: 0o700 });
  chownToInvokingUser(J41_DIR); // under sudo, keep it owned by the real user

  // ── Step 2: detect platform and print banner ───────────────────────────────
  const platform = await detectPlatform();

  out('');
  out(`J41 ${displayName(product)} Security Setup`);
  out('='.repeat(40));
  out(`Platform : ${platform.os} / ${platform.arch}`);
  out(`Distro   : ${platform.distro}`);
  out(`Docker   : ${platform.hasDocker ? 'available' : 'NOT FOUND'}`);
  out(`KVM      : ${platform.hasKVM ? 'available' : 'not available'}`);
  out('');

  // ── Step 3: require Docker ─────────────────────────────────────────────────
  if (!platform.hasDocker) {
    const msg = '[setup] Docker is not available. Please install Docker and ensure the daemon is running.';
    out(msg);
    return { success: false, log, score: 0, mode: 'none' };
  }

  // ── Step 4: isolation layer (Linux or macOS) ───────────────────────────────
  let isolationMode = 'docker-only';

  if (platform.os === 'linux') {
    // Try gVisor first if KVM is available
    let gvisorOk = false;

    // gVisor runs WITHOUT KVM via its systrap platform — KVM only selects a
    // faster platform, it is not a prerequisite. Always attempt gVisor first so
    // KVM-less cloud VMs still get real kernel isolation (Wall 1); fall back to
    // bubblewrap only if the install genuinely fails.
    out(platform.hasKVM
      ? '[setup] Attempting to install gVisor (KVM available → kvm platform)...'
      : '[setup] Attempting to install gVisor (no KVM → systrap platform, no KVM required)...');
    try {
      const gvisorResult = await installGvisor({
        distro: platform.distro,
        arch: platform.arch,
        hasKVM: platform.hasKVM,
      });
      if (gvisorResult.success) {
        out(`[setup] gVisor installed and configured successfully (platform=${gvisorResult.platform}).`);
        gvisorOk = true;
        isolationMode = 'gvisor';
      } else {
        out('[setup] gVisor installation failed — falling back to bubblewrap.');
      }
    } catch (err) {
      out(`[setup] gVisor installation error: ${err.message} — falling back to bubblewrap.`);
    }

    // Fall back to bubblewrap if gVisor not installed
    if (!gvisorOk) {
      out('[setup] Installing bubblewrap...');
      try {
        const bwrapResult = await installBwrap({ distro: platform.distro });
        if (bwrapResult.success) {
          out(bwrapResult.alreadyInstalled
            ? '[setup] bubblewrap is already installed.'
            : '[setup] bubblewrap installed successfully.');
          isolationMode = 'bwrap';
        } else {
          const errDetail = bwrapResult.error ?? 'unknown error';
          out(`[setup] bubblewrap installation failed: ${errDetail}`);
          out('[setup] No isolation layer could be installed. Aborting.');
          return { success: false, log, score: 0, mode: 'none' };
        }
      } catch (err) {
        out(`[setup] bubblewrap installation error: ${err.message}. Aborting.`);
        return { success: false, log, score: 0, mode: 'none' };
      }
    }
  } else {
    // ── macOS: verify Docker Desktop VM ─────────────────────────────────────
    if (!platform.dockerDesktopVM) {
      out('[setup] Docker Desktop VM does not appear to be active on macOS.');
      out('[setup] Please ensure Docker Desktop is running and try again.');
      return { success: false, log, score: 0, mode: 'none' };
    }
    out('[setup] macOS Docker Desktop VM is active.');
    isolationMode = 'macos-vm';
  }

  // ── Step 5: deploy security profiles ──────────────────────────────────────
  const targetDir = profileTargetDir(platform.os);
  const skipAppArmor = platform.os !== 'linux';

  out(`[setup] Deploying security profiles to ${targetDir}...`);
  try {
    const deployResult = deployProfiles({ product, targetDir, skipAppArmor });
    out(`[setup] Deployed: ${deployResult.profilesDeployed.join(', ')}`);
  } catch (err) {
    out(`[setup] Profile deployment failed: ${err.message}`);
    return { success: false, log, score: 0, mode: isolationMode };
  }

  // ── Step 6: dispatcher-only network setup ─────────────────────────────────
  if (product === 'dispatcher') {
    out('[setup] Setting up j41 Docker network and iptables rules...');
    try {
      setupNetwork();
      out('[setup] Network configured.');
    } catch (err) {
      out(`[setup] Network setup warning: ${err.message}`);
      out('[setup] iptables rules may require sudo — run "sudo j41-secure-setup --fix" to complete.');
      // Non-fatal: Docker network may have been created, iptables just needs elevated permissions
    }

    out('[setup] Setting up financial allowlist...');
    try {
      const allowlistResult = setupAllowlist();
      out(`[setup] Financial allowlist: ${allowlistResult.status} at ${allowlistResult.path}`);
    } catch (err) {
      out(`[setup] Allowlist setup failed: ${err.message}`);
      return { success: false, log, score: 0, mode: isolationMode };
    }
  }

  // ── Step 7: run self-test ──────────────────────────────────────────────────
  out('[setup] Running self-test...');
  let testResults;
  let score = 0;
  let finalMode = isolationMode;

  try {
    testResults = await selfTest(product);
    score = testResults.score;
    finalMode = testResults.mode;
  } catch (err) {
    out(`[setup] Self-test threw an unexpected error: ${err.message}`);
    return { success: false, log, score, mode: finalMode };
  }

  // ── Step 8: write marker file ──────────────────────────────────────────────
  const markerPath = path.join(J41_DIR, `${product}-security-initialized`);
  const markerData = {
    date: new Date().toISOString(),
    platform: platform.os,
    arch: platform.arch,
    distro: platform.distro,
    mode: finalMode,
    score,
    product,
  };

  try {
    fs.writeFileSync(markerPath, JSON.stringify(markerData, null, 2), { encoding: 'utf8', mode: 0o600 });
    chownToInvokingUser(markerPath); // so the user-run product can read its own marker
    out(`[setup] Marker written to ${markerPath}`);
  } catch (err) {
    out(`[setup] Warning: could not write marker file: ${err.message}`);
    // Non-fatal — continue to report
  }

  // ── Step 9: print report card ──────────────────────────────────────────────
  out('');
  out('Security Self-Test Results');
  out('-'.repeat(40));

  for (const result of testResults.results) {
    const icon = result.passed ? PASS : FAIL;
    const errSuffix = result.error ? ` — ${result.error}` : '';
    out(`  ${icon} ${result.name}${errSuffix}`);
  }

  out('');
  out(`Score : ${score}/10`);
  out(`Mode  : ${finalMode}`);
  out(`Status: ${testResults.passed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED'}`);
  out('');

  return {
    success: testResults.passed,
    log,
    score,
    mode: finalMode,
  };
}
