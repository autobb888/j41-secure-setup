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

  // Ensure the target directory exists
  fs.mkdirSync(targetDir, { recursive: true });

  const profilesDeployed = [];
  /** @type {Record<string, string>} */
  const hashes = {};

  for (const filename of files) {
    const src = path.join(PROFILES_DIR, filename);
    const dest = path.join(targetDir, filename);

    fs.copyFileSync(src, dest);
    profilesDeployed.push(filename);

    hashes[filename] = sha256File(dest);
  }

  // Write profile-hashes.json
  const hashesPath = path.join(targetDir, 'profile-hashes.json');
  fs.writeFileSync(hashesPath, JSON.stringify(hashes, null, 2), 'utf8');

  // Load AppArmor profiles unless skipped
  if (!skipAppArmor) {
    for (const filename of profilesDeployed) {
      if (APPARMOR_FILES.has(filename)) {
        const dest = path.join(targetDir, filename);
        try {
          execSync(`sudo apparmor_parser -r "${dest}"`, { stdio: 'pipe', timeout: 15000 });
        } catch (err) {
          // Non-fatal: AppArmor may not be available (e.g. macOS, non-AppArmor kernel)
          // Surface warning but don't abort
          process.stderr.write(
            `[deploy-profiles] Warning: apparmor_parser failed for ${filename}: ${err.message}\n`,
          );
        }
      }
    }
  }

  return { profilesDeployed, hashes };
}
