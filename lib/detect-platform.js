import os from 'node:os';
import fs from 'node:fs';
import { execSync } from 'node:child_process';

/**
 * Read and parse /etc/os-release to extract the distro ID.
 * Returns the ID value (e.g. 'ubuntu', 'debian') or 'unknown'.
 */
function readLinuxDistro() {
  try {
    const content = fs.readFileSync('/etc/os-release', 'utf8');
    for (const line of content.split('\n')) {
      const match = line.match(/^ID=(.+)$/);
      if (match) {
        // Strip surrounding quotes if present
        return match[1].replace(/^["']|["']$/g, '').trim();
      }
    }
  } catch {
    // File missing or unreadable
  }
  return 'unknown';
}

/**
 * Check whether `docker info` runs successfully.
 * Returns { hasDocker, dockerDesktopVM }.
 */
function probeDocker(platform) {
  let hasDocker = false;
  let dockerDesktopVM = false;

  try {
    execSync('docker info', { stdio: 'pipe', timeout: 10000 });
    hasDocker = true;

    if (platform === 'darwin') {
      try {
        const out = execSync('docker info --format "{{.OperatingSystem}}"', {
          stdio: 'pipe',
          timeout: 10000,
        }).toString().trim();
        dockerDesktopVM = out.includes('Docker Desktop');
      } catch {
        // docker info succeeded but format query failed — non-fatal
      }
    }
  } catch {
    // docker not available or daemon not running
  }

  return { hasDocker, dockerDesktopVM };
}

/**
 * Returns true if /dev/kvm exists (Linux only; always false on macOS).
 */
function checkKVM() {
  try {
    fs.accessSync('/dev/kvm', fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect the current platform and available runtime features.
 *
 * @returns {{
 *   os: 'linux'|'darwin',
 *   arch: 'x64'|'arm64',
 *   distro: string,
 *   hasDocker: boolean,
 *   dockerDesktopVM: boolean,
 *   hasKVM: boolean,
 * }}
 */
export async function detectPlatform() {
  const platform = os.platform(); // e.g. 'linux', 'darwin'
  const arch = os.arch();         // e.g. 'x64', 'arm64'

  const distro = platform === 'linux' ? readLinuxDistro() : 'macos';

  const { hasDocker, dockerDesktopVM } = probeDocker(platform);
  const hasKVM = platform === 'linux' ? checkKVM() : false;

  return {
    os: platform,
    arch,
    distro,
    hasDocker,
    dockerDesktopVM,
    hasKVM,
  };
}
