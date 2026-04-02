import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

/**
 * Returns true if the given command is on PATH (`which <cmd>` exits 0).
 * @param {string} cmd
 * @returns {boolean}
 */
export function commandExists(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check whether /etc/docker/daemon.json has "default-runtime": "runsc".
 * @returns {boolean}
 */
function isGvisorDefault() {
  try {
    const raw = fs.readFileSync('/etc/docker/daemon.json', 'utf8');
    const cfg = JSON.parse(raw);
    return cfg['default-runtime'] === 'runsc';
  } catch {
    return false;
  }
}

/**
 * Check whether the j41 seccomp profiles have been deployed.
 * Linux: /etc/j41/  |  macOS: ~/.j41/
 * @returns {boolean}
 */
function areSeccompProfilesDeployed() {
  const platform = os.platform();
  const dir = platform === 'linux'
    ? '/etc/j41'
    : path.join(os.homedir(), '.j41');

  try {
    const entries = fs.readdirSync(dir);
    // At least one .json profile must be present
    return entries.some((f) => f.endsWith('.json'));
  } catch {
    return false;
  }
}

/**
 * Check whether any j41 AppArmor profiles are loaded by reading
 * /sys/kernel/security/apparmor/profiles.
 * @returns {boolean}
 */
function isApparmorLoaded() {
  try {
    const content = fs.readFileSync('/sys/kernel/security/apparmor/profiles', 'utf8');
    return content.includes('j41');
  } catch {
    return false;
  }
}

/**
 * Check whether the j41-isolated Docker network exists.
 * @returns {boolean}
 */
function doesJ41NetworkExist() {
  try {
    execSync('docker network inspect j41-isolated', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Determine whether we are running inside macOS with Docker Desktop.
 * Mirrors the logic from detect-platform for self-contained use.
 * @returns {boolean}
 */
function isDockerDesktopVM() {
  if (os.platform() !== 'darwin') return false;
  try {
    const out = execSync('docker info --format "{{.OperatingSystem}}"', {
      stdio: 'pipe',
      timeout: 10000,
    }).toString().trim();
    return out.includes('Docker Desktop');
  } catch {
    return false;
  }
}

/**
 * Calculate an isolation score (0-10) and determine the isolation mode.
 *
 * Score rules:
 *   gVisor as default runtime → 10
 *   macOS Docker Desktop VM   → 8
 *   bubblewrap installed      → 8
 *   otherwise                 → 4
 *   If seccomp profiles not deployed → cap at 4
 *
 * Mode selection (first match wins):
 *   gvisorDefault              → 'gvisor'
 *   dockerDesktopVM            → 'macos-vm'
 *   bwrapInstalled             → 'bwrap'
 *   otherwise                  → 'docker-only'
 *
 * @param {{
 *   gvisorDefault: boolean,
 *   dockerDesktopVM: boolean,
 *   bwrapInstalled: boolean,
 *   seccompProfilesDeployed: boolean,
 * }} flags
 * @returns {{ score: number, mode: string }}
 */
function calcScoreAndMode({ gvisorDefault, dockerDesktopVM, bwrapInstalled, seccompProfilesDeployed }) {
  let score;
  let mode;

  if (gvisorDefault) {
    score = 10;
    mode = 'gvisor';
  } else if (dockerDesktopVM) {
    score = 8;
    mode = 'macos-vm';
  } else if (bwrapInstalled) {
    score = 8;
    mode = 'bwrap';
  } else {
    score = 4;
    mode = 'docker-only';
  }

  if (!seccompProfilesDeployed) {
    score = Math.min(score, 4);
  }

  return { score, mode };
}

/**
 * Detect the current isolation posture of the host.
 *
 * @returns {{
 *   gvisorInstalled: boolean,
 *   gvisorDefault: boolean,
 *   bwrapInstalled: boolean,
 *   seccompProfilesDeployed: boolean,
 *   apparmorLoaded: boolean,
 *   j41NetworkExists: boolean,
 *   dockerDesktopVM: boolean,
 *   score: number,
 *   mode: string,
 * }}
 */
export async function detectIsolation() {
  const gvisorInstalled = commandExists('runsc');
  const gvisorDefault = isGvisorDefault();
  const bwrapInstalled = commandExists('bwrap');
  const seccompProfilesDeployed = areSeccompProfilesDeployed();
  const apparmorLoaded = isApparmorLoaded();
  const j41NetworkExists = doesJ41NetworkExist();
  const dockerDesktopVM = isDockerDesktopVM();

  const { score, mode } = calcScoreAndMode({
    gvisorDefault,
    dockerDesktopVM,
    bwrapInstalled,
    seccompProfilesDeployed,
  });

  return {
    gvisorInstalled,
    gvisorDefault,
    bwrapInstalled,
    seccompProfilesDeployed,
    apparmorLoaded,
    j41NetworkExists,
    dockerDesktopVM,
    score,
    mode,
  };
}
