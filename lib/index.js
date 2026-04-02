import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

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

const J41_DIR = path.join(os.homedir(), '.j41');

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
  return platformOs === 'linux' ? '/etc/j41' : J41_DIR;
}

// ── Main exports ──────────────────────────────────────────────────────────────

/**
 * Check whether the security setup has been completed for the given product.
 *
 * @param {'dispatcher'|'jailbox'} product
 * @returns {boolean}
 */
export function isInitialized(product) {
  const markerPath = path.join(J41_DIR, `${product}-security-initialized`);
  return fs.existsSync(markerPath);
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
  fs.mkdirSync(J41_DIR, { recursive: true });

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

    if (platform.hasKVM) {
      out('[setup] Attempting to install gVisor (KVM available)...');
      try {
        const gvisorResult = await installGvisor({ distro: platform.distro, arch: platform.arch });
        if (gvisorResult.success) {
          out('[setup] gVisor installed and configured successfully.');
          gvisorOk = true;
          isolationMode = 'gvisor';
        } else {
          out('[setup] gVisor installation failed — falling back to bubblewrap.');
        }
      } catch (err) {
        out(`[setup] gVisor installation error: ${err.message} — falling back to bubblewrap.`);
      }
    } else {
      out('[setup] KVM not available — skipping gVisor, trying bubblewrap.');
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
      out(`[setup] Network setup failed: ${err.message}`);
      return { success: false, log, score: 0, mode: isolationMode };
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
    fs.writeFileSync(markerPath, JSON.stringify(markerData, null, 2), 'utf8');
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
