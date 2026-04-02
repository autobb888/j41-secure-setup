import { execSync } from 'node:child_process';

/**
 * Return true if bwrap is already installed.
 * @returns {boolean}
 */
function isBwrapInstalled() {
  try {
    execSync('bwrap --version', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect whether dnf is available (prefer over yum).
 * @returns {'dnf'|'yum'}
 */
function detectYumVariant() {
  try {
    execSync('which dnf', { stdio: 'pipe', timeout: 5000 });
    return 'dnf';
  } catch {
    return 'yum';
  }
}

/**
 * Install bubblewrap on the host.
 *
 * Distro mapping:
 *   ubuntu / debian (and variants) → apt-get
 *   fedora / centos / rhel / rocky / almalinux / amzn → yum or dnf
 *
 * @param {{ distro: string }} options
 * @returns {Promise<{ success: boolean, alreadyInstalled: boolean, error?: string }>}
 */
export async function installBwrap({ distro }) {
  // ── Step 1: check if already installed ─────────────────────────────────
  if (isBwrapInstalled()) {
    return { success: true, alreadyInstalled: true };
  }

  // ── Step 2: install ─────────────────────────────────────────────────────
  const debianLike = ['ubuntu', 'debian', 'linuxmint', 'pop', 'elementary'].includes(distro);
  const rhelLike = ['fedora', 'centos', 'rhel', 'rocky', 'almalinux', 'amzn', 'amazonlinux'].includes(distro);

  try {
    if (debianLike) {
      execSync('sudo apt-get update -y', { stdio: 'inherit', timeout: 120000 });
      execSync('sudo apt-get install -y bubblewrap', { stdio: 'inherit', timeout: 120000 });
    } else if (rhelLike) {
      const pkgMgr = detectYumVariant();
      execSync(`sudo ${pkgMgr} install -y bubblewrap`, { stdio: 'inherit', timeout: 120000 });
    } else {
      return {
        success: false,
        alreadyInstalled: false,
        error: `Unsupported distro: ${distro}. Install bubblewrap manually.`,
      };
    }
  } catch (err) {
    return { success: false, alreadyInstalled: false, error: err.message };
  }

  // ── Step 3: verify ──────────────────────────────────────────────────────
  if (!isBwrapInstalled()) {
    return {
      success: false,
      alreadyInstalled: false,
      error: 'bubblewrap not found after installation — verification failed',
    };
  }

  return { success: true, alreadyInstalled: false };
}
