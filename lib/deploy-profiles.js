import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to the bundled profiles directory */
const PROFILES_DIR = path.resolve(__dirname, '..', 'profiles');

/** Files deployed per product */
const PRODUCT_PROFILES = {
  dispatcher: ['seccomp-agent.json', 'seccomp-bwrap.json', 'apparmor-agent'],
  jailbox: ['seccomp-jailbox.json', 'seccomp-bwrap.json', 'apparmor-jailbox'],
};

/** AppArmor profile filenames (subset of the above that must be loaded) */
const APPARMOR_FILES = new Set(['apparmor-agent', 'apparmor-jailbox']);

/**
 * Audit 2026-06-02 H7: load profiles/known-good-hashes.json and assert each
 * source profile file in PROFILES_DIR matches its known-good entry BEFORE
 * copying. If a supply-chain compromise of @junction41/secure-setup ever
 * publishes tampered profiles (and updates profile-hashes.json post-deploy
 * to look consistent), this check rejects the package at install time.
 *
 * Treats a missing or unparseable known-good-hashes.json as fatal — it is
 * the package's authoritative source of truth and should never be empty.
 */
function loadKnownGoodHashes() {
  const p = path.join(PROFILES_DIR, 'known-good-hashes.json');
  let raw;
  try {
    raw = fs.readFileSync(p, 'utf8');
  } catch (err) {
    throw new Error(
      `Cannot deploy profiles: known-good-hashes.json missing at ${p}. ` +
      'This file is the package\'s authoritative integrity anchor; refusing to proceed.',
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Cannot deploy profiles: known-good-hashes.json unparseable: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Object.keys(parsed).length === 0) {
    throw new Error('Cannot deploy profiles: known-good-hashes.json is empty');
  }
  return parsed;
}

/**
 * Compute the SHA-256 hex digest of a file.
 * @param {string} filePath
 * @returns {string}
 */
function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Deploy security profiles for a given product to a target directory.
 *
 * @param {{
 *   product: 'dispatcher' | 'jailbox',
 *   targetDir: string,
 *   skipAppArmor?: boolean,
 * }} options
 * @returns {{
 *   profilesDeployed: string[],
 *   hashes: Record<string, string>,
 * }}
 */
export function deployProfiles({ product, targetDir, skipAppArmor = false }) {
  const files = PRODUCT_PROFILES[product];
  if (!files) {
    throw new Error(`Unknown product "${product}". Expected 'dispatcher' or 'jailbox'.`);
  }

  // Audit H7: verify each source profile against known-good-hashes BEFORE
  // copying anything. Mismatch = abort entire deploy.
  const knownGood = loadKnownGoodHashes();
  for (const filename of files) {
    const src = path.join(PROFILES_DIR, filename);
    const actual = sha256File(src);
    const expected = knownGood[filename];
    if (!expected) {
      throw new Error(
        `Refusing to deploy: profile ${filename} has no entry in known-good-hashes.json. ` +
        'Either this is a new profile that hasn\'t been qualified yet, or known-good-hashes.json ' +
        'is out of date. Refusing to deploy unqualified profiles.',
      );
    }
    if (actual !== expected) {
      throw new Error(
        `Refusing to deploy: profile ${filename} has hash ${actual} but known-good-hashes.json ` +
        `declares ${expected}. This indicates the npm tarball was tampered with.`,
      );
    }
  }

  // Ensure the target directory exists; mode 0700 so a different-UID local
  // user can't read profile content (audit M-SECURE-SETUP-funds-1).
  fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(targetDir, 0o700); } catch { /* may not be ours */ }

  const profilesDeployed = [];
  /** @type {Record<string, string>} */
  const hashes = {};

  for (const filename of files) {
    const src = path.join(PROFILES_DIR, filename);
    const dest = path.join(targetDir, filename);

    fs.copyFileSync(src, dest);
    // Audit H3: deployed profile mode 0600 (was 0644) — container runs as the
    // dispatcher UID so the relaxation to 0644 served no purpose.
    fs.chmodSync(dest, 0o600);
    profilesDeployed.push(filename);

    hashes[filename] = sha256File(dest);
  }

  // Write profile-hashes.json — note this is the post-deploy hash, which we
  // separately verified equals the in-package known-good above. Keeping both
  // files lets the dispatcher quick-check verify in either direction.
  const hashesPath = path.join(targetDir, 'profile-hashes.json');
  fs.writeFileSync(hashesPath, JSON.stringify(hashes, null, 2), { encoding: 'utf8', mode: 0o600 });

  // Audit H3 part 2: best-effort chattr +i so a brief operator-context code
  // execution can't tamper with profiles between deploys. Requires root
  // (which we already have via sudo per other steps in this package) and the
  // ext4/xfs filesystem to support the immutable bit. Non-fatal if it fails.
  for (const filename of profilesDeployed) {
    const dest = path.join(targetDir, filename);
    try {
      execSync(`sudo chattr +i "${dest}"`, { stdio: 'pipe', timeout: 5000 });
    } catch {
      // chattr may be unavailable (non-ext4 fs, container, macOS, BSD) — soft skip.
    }
  }

  // Load AppArmor profiles unless skipped
  if (!skipAppArmor) {
    for (const filename of profilesDeployed) {
      if (APPARMOR_FILES.has(filename)) {
        const dest = path.join(targetDir, filename);
        try {
          execSync(`sudo apparmor_parser -r "${dest}"`, { stdio: 'pipe', timeout: 15000 });
        } catch (err) {
          // Non-fatal: AppArmor may not be available (e.g. macOS, non-AppArmor kernel)
          // Note: bypasses caller's log array — stderr only
          process.stderr.write(
            `[deploy-profiles] Warning: apparmor_parser failed for ${filename}: ${err.message}\n`,
          );
        }
      }
    }
  }

  return { profilesDeployed, hashes };
}
