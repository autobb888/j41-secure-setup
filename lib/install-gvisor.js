import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

/**
 * Map a Node.js arch string to the gVisor release arch name.
 * @param {string} arch - os.arch() value
 * @returns {string}
 */
function mapArch(arch) {
  if (arch === 'arm64' || arch === 'aarch64') return 'aarch64';
  return 'x86_64';
}

/**
 * Return true if runsc is already installed.
 * @returns {boolean}
 */
function isGvisorInstalled() {
  try {
    execSync('runsc --version', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Install gVisor via the apt repository (Ubuntu / Debian).
 */
function installViaApt() {
  execSync(
    'curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg',
    { stdio: 'inherit', timeout: 60000 },
  );
  execSync(
    'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null',
    { stdio: 'inherit', timeout: 15000 },
  );
  execSync('sudo apt-get update -y', { stdio: 'inherit', timeout: 120000 });
  execSync('sudo apt-get install -y runsc', { stdio: 'inherit', timeout: 120000 });
}

/**
 * Install gVisor via yum/dnf (Fedora / CentOS / RHEL / Rocky / AlmaLinux / Amazon Linux).
 */
function installViaYum() {
  const pkgMgr = (() => {
    try {
      execSync('which dnf', { stdio: 'pipe', timeout: 5000 });
      return 'dnf';
    } catch {
      return 'yum';
    }
  })();

  execSync(
    `sudo ${pkgMgr} install -y runsc`,
    { stdio: 'inherit', timeout: 120000 },
  );
}

/**
 * Install gVisor via direct binary download (fallback for unsupported distros).
 * @param {string} arch - gVisor arch string (x86_64 or aarch64)
 */
function installViaBinary(arch) {
  const url = `https://storage.googleapis.com/gvisor/releases/release/latest/${arch}/runsc`;
  execSync(`curl -fsSL -o /tmp/runsc "${url}"`, { stdio: 'inherit', timeout: 120000 });
  execSync('chmod +x /tmp/runsc', { stdio: 'pipe', timeout: 5000 });
  execSync('sudo mv /tmp/runsc /usr/local/bin/runsc', { stdio: 'inherit', timeout: 10000 });
}

/**
 * Update /etc/docker/daemon.json to make runsc the default runtime.
 */
function configureDaemonJson() {
  const daemonPath = '/etc/docker/daemon.json';
  let cfg = {};

  try {
    const raw = fs.readFileSync(daemonPath, 'utf8');
    cfg = JSON.parse(raw);
  } catch {
    // File may not exist yet; start fresh
  }

  cfg['default-runtime'] = 'runsc';
  cfg.runtimes = cfg.runtimes ?? {};
  cfg.runtimes.runsc = { path: 'runsc' };

  // Write to a temp file, then sudo-mv to handle permission-restricted path
  const tmpPath = '/tmp/daemon.json.j41';
  fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2), 'utf8');
  execSync(`sudo mkdir -p /etc/docker && sudo mv "${tmpPath}" "${daemonPath}"`, {
    stdio: 'pipe',
    timeout: 10000,
  });
}

/**
 * Install gVisor on the host and configure Docker to use it as the default runtime.
 *
 * @param {{ distro: string, arch: string }} options
 * @returns {Promise<{ success: boolean, steps: Array<{step: string, status: string, [key: string]: unknown}> }>}
 */
export async function installGvisor({ distro, arch }) {
  const steps = [];
  const gvisorArch = mapArch(arch);

  // ── Step 1: check if already installed ──────────────────────────────────
  const alreadyInstalled = isGvisorInstalled();
  steps.push({ step: 'check-installed', status: alreadyInstalled ? 'skipped' : 'needed', alreadyInstalled });

  if (!alreadyInstalled) {
    // ── Step 2: install based on distro ───────────────────────────────────
    const debianLike = ['ubuntu', 'debian', 'linuxmint', 'pop', 'elementary'].includes(distro);
    const rhelLike = ['fedora', 'centos', 'rhel', 'rocky', 'almalinux', 'amzn', 'amazonlinux'].includes(distro);

    try {
      if (debianLike) {
        installViaApt();
        steps.push({ step: 'install', status: 'ok', method: 'apt' });
      } else if (rhelLike) {
        installViaYum();
        steps.push({ step: 'install', status: 'ok', method: 'yum/dnf' });
      } else {
        installViaBinary(gvisorArch);
        steps.push({ step: 'install', status: 'ok', method: 'binary', arch: gvisorArch });
      }
    } catch (err) {
      steps.push({ step: 'install', status: 'error', error: err.message });
      return { success: false, steps };
    }
  }

  // ── Step 3: configure Docker daemon.json ────────────────────────────────
  try {
    configureDaemonJson();
    steps.push({ step: 'configure-docker', status: 'ok' });
  } catch (err) {
    steps.push({ step: 'configure-docker', status: 'error', error: err.message });
    return { success: false, steps };
  }

  // ── Step 4: restart Docker ───────────────────────────────────────────────
  try {
    execSync('sudo systemctl restart docker', { stdio: 'inherit', timeout: 30000 });
    steps.push({ step: 'restart-docker', status: 'ok' });
  } catch (err) {
    steps.push({ step: 'restart-docker', status: 'error', error: err.message });
    return { success: false, steps };
  }

  // ── Step 5: verify ───────────────────────────────────────────────────────
  try {
    execSync('docker run --rm --runtime=runsc alpine echo "gVisor OK"', {
      stdio: 'inherit',
      timeout: 60000,
    });
    steps.push({ step: 'verify', status: 'ok' });
  } catch (err) {
    steps.push({ step: 'verify', status: 'error', error: err.message });
    return { success: false, steps };
  }

  return { success: true, steps };
}
