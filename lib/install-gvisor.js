import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

// Audit 2026-06-02 C6 + H5 + H6: every artifact this module installs must be
// verified against a trust anchor SHIPPED INSIDE THIS PACKAGE — not fetched
// from the same origin as the artifact. The pinned-gvisor.json file (under
// assets/) lists J41-qualified gVisor releases with their expected sha512
// per architecture and the gVisor signing key fingerprint that signed them.
// Operators MUST NOT install runsc via the binary-fallback path unless a
// matching release entry exists; the rotating "latest" channel is refused.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PINNED_GVISOR_PATH = path.resolve(__dirname, '..', 'assets', 'pinned-gvisor.json');

function loadPinnedGvisor() {
  try {
    const raw = fs.readFileSync(PINNED_GVISOR_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed.releases)) {
      throw new Error('pinned-gvisor.json missing releases[]');
    }
    return parsed;
  } catch (err) {
    throw new Error(
      `Could not load J41-qualified gVisor pin file at ${PINNED_GVISOR_PATH}: ${err.message}. ` +
      'This file ships in the npm tarball; if it is missing, the package is corrupt.',
    );
  }
}

/**
 * Map a Node.js arch string to the gVisor release arch name.
 */
function mapArch(arch) {
  if (arch === 'arm64' || arch === 'aarch64') return 'aarch64';
  return 'x86_64';
}

/**
 * Return true if runsc is already installed.
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
 *
 * Audit H5: the gVisor signing key is shipped inside this npm tarball at
 * assets/gvisor-archive-keyring.gpg if available. If shipped, we copy it
 * directly into /usr/share/keyrings — NEVER curl-pipe a key into sudo gpg.
 * If the operator has not yet bundled the keyring, the apt path is REFUSED
 * with a clear error pointing at the binary-pin path instead.
 */
function installViaApt() {
  const bundledKeyring = path.resolve(__dirname, '..', 'assets', 'gvisor-archive-keyring.gpg');
  if (!fs.existsSync(bundledKeyring)) {
    throw new Error(
      'Refusing apt path: gVisor signing key was not bundled in this @junction41/secure-setup release. ' +
      'Audit H5 forbids "curl https://gvisor.dev/archive.key | sudo gpg --dearmor". ' +
      'Use --gvisor-binary-only to take the pinned-binary path, or add ' +
      'assets/gvisor-archive-keyring.gpg to the package and republish.',
    );
  }
  execSync(
    `sudo cp "${bundledKeyring}" /usr/share/keyrings/gvisor-archive-keyring.gpg`,
    { stdio: 'inherit', timeout: 15000 },
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
 * Same rationale as apt: refuses without bundled keyring.
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

  const bundledKeyring = path.resolve(__dirname, '..', 'assets', 'gvisor-archive-keyring.gpg');
  if (!fs.existsSync(bundledKeyring)) {
    throw new Error(
      'Refusing yum/dnf path: gVisor signing key was not bundled in this @junction41/secure-setup release. ' +
      'Audit H5 forbids unauthenticated keyring fetches.',
    );
  }
  execSync(`sudo ${pkgMgr} install -y runsc`, { stdio: 'inherit', timeout: 120000 });
}

/**
 * Install gVisor via direct binary download (fallback for unsupported distros).
 *
 * Audit C6 + H6: previously fetched runsc + runsc.sha512 from the SAME GCS
 * URL — same-origin checksum is a transport check, not authenticity. We now:
 *   1. Refuse the rotating `latest` channel — only J41-qualified releases.
 *   2. Compare the downloaded binary's sha512 against an in-package constant
 *      from assets/pinned-gvisor.json. Hash mismatch = abort install.
 *   3. Refuse outright if the requested release isn't in the pin file
 *      (i.e. has not been qualified by J41 maintainers yet).
 *
 * Set GVISOR_RELEASE env to the qualified release tag; defaults to the
 * first entry of pinned-gvisor.json's releases[].
 */
function installViaBinary(arch) {
  const pinned = loadPinnedGvisor();
  const requestedRelease = process.env.GVISOR_RELEASE || pinned.releases[0]?.release;
  if (!requestedRelease || requestedRelease === 'TBD') {
    throw new Error(
      'Refusing gVisor binary install: assets/pinned-gvisor.json contains no qualified releases. ' +
      'A maintainer must qualify a real gVisor release (verify gpg sig + compute sha512) ' +
      'and update the pin file before this path is usable. See the audit C6/H6 notes ' +
      'in the file header for the qualification checklist.',
    );
  }
  const entry = pinned.releases.find(r => r.release === requestedRelease);
  if (!entry) {
    throw new Error(
      `Refusing gVisor binary install: release "${requestedRelease}" is not in the J41 pin file. ` +
      `Add it to assets/pinned-gvisor.json after qualifying.`,
    );
  }
  const sha512Key = arch === 'aarch64' ? 'sha512_aarch64' : 'sha512_x86_64';
  const expectedSha512 = entry[sha512Key];
  if (!expectedSha512 || expectedSha512 === 'TBD') {
    throw new Error(
      `Refusing gVisor binary install: pin entry for ${requestedRelease}/${arch} has no sha512. ` +
      `Update assets/pinned-gvisor.json.`,
    );
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'j41-gvisor-'));
  const tmpBin = path.join(tmpDir, 'runsc');
  const url = `https://storage.googleapis.com/gvisor/releases/release/${encodeURIComponent(requestedRelease)}/${arch}/runsc`;
  try {
    execSync(`curl -fsSL --max-filesize 67108864 -o "${tmpBin}" "${url}"`, { stdio: 'inherit', timeout: 120000 });
    // Compute sha512 of what we downloaded and compare against the
    // in-package expected value. This is the audit fix: trust anchor is
    // local to the npm tarball, NOT a sibling URL on storage.googleapis.com.
    const got = execSync(`sha512sum "${tmpBin}"`, { stdio: ['pipe', 'pipe', 'ignore'], timeout: 30000 })
      .toString('utf8').split(/\s+/)[0].toLowerCase();
    const expected = expectedSha512.toLowerCase().replace(/\s+/g, '');
    if (got !== expected) {
      throw new Error(
        `gVisor binary sha512 mismatch for ${requestedRelease}/${arch}: ` +
        `expected ${expected}, got ${got}. ABORTING.`,
      );
    }
    execSync(`chmod +x "${tmpBin}"`, { stdio: 'pipe', timeout: 5000 });
    execSync(`sudo mv "${tmpBin}" /usr/local/bin/runsc`, { stdio: 'inherit', timeout: 10000 });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
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

  // Write to a random temp file, then sudo-mv to handle permission-restricted path
  const tmpDir = fs.mkdtempSync('/tmp/j41-daemon-');
  const tmpPath = path.join(tmpDir, 'daemon.json');
  fs.writeFileSync(tmpPath, JSON.stringify(cfg, null, 2), { mode: 0o600 });
  execSync(`sudo mkdir -p /etc/docker && sudo mv "${tmpPath}" "${daemonPath}"`, {
    stdio: 'pipe',
    timeout: 10000,
  });
  fs.rmSync(tmpDir, { recursive: true });
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

  // -- Step 1: check if already installed --
  const alreadyInstalled = isGvisorInstalled();
  steps.push({ step: 'check-installed', status: alreadyInstalled ? 'skipped' : 'needed', alreadyInstalled });

  if (!alreadyInstalled) {
    // -- Step 2: install based on distro --
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

  // -- Step 3: configure Docker daemon.json --
  try {
    configureDaemonJson();
    steps.push({ step: 'configure-docker', status: 'ok' });
  } catch (err) {
    steps.push({ step: 'configure-docker', status: 'error', error: err.message });
    return { success: false, steps };
  }

  // -- Step 4: restart Docker --
  try {
    execSync('sudo systemctl restart docker', { stdio: 'inherit', timeout: 30000 });
    steps.push({ step: 'restart-docker', status: 'ok' });
  } catch (err) {
    steps.push({ step: 'restart-docker', status: 'error', error: err.message });
    return { success: false, steps };
  }

  // -- Step 5: verify --
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
