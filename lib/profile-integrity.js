import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to the bundled known-good hashes file */
const KNOWN_GOOD_HASHES_PATH = path.resolve(__dirname, '..', 'profiles', 'known-good-hashes.json');

/**
 * Compute the SHA-256 hex digest of a file.
 * Returns null if the file cannot be read (e.g. missing).
 *
 * @param {string} filePath
 * @returns {string | null}
 */
function sha256File(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Load the package's known-good hashes from profiles/known-good-hashes.json.
 * Returns an empty object if the file cannot be read (non-fatal).
 *
 * @returns {Record<string, string>}
 */
function loadKnownGoodHashes() {
  try {
    const raw = fs.readFileSync(KNOWN_GOOD_HASHES_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Verify the integrity of deployed security profiles in `profileDir`.
 *
 * Reads `profile-hashes.json` from `profileDir`, then for each listed file:
 *   1. Checks the file exists on disk.
 *   2. Recomputes its SHA-256 and compares against the stored hash.
 *   3. Cross-checks against the package's `profiles/known-good-hashes.json`.
 *
 * A file is considered tampered if:
 *   - It is listed in profile-hashes.json but does not exist on disk.
 *   - Its computed hash does not match the stored hash in profile-hashes.json.
 *   - It appears in known-good-hashes.json and its computed hash differs.
 *
 * @param {string} profileDir  Absolute path to the directory holding deployed profiles.
 * @returns {Promise<{
 *   passed: boolean,
 *   tampered: string[],
 *   error?: string,
 * }>}
 */
export async function verifyProfileIntegrity(profileDir) {
  const hashesPath = path.join(profileDir, 'profile-hashes.json');

  // Guard: profile-hashes.json must exist
  if (!fs.existsSync(hashesPath)) {
    return { passed: false, error: 'No profile-hashes.json found', tampered: [] };
  }

  /** @type {Record<string, string>} */
  let storedHashes;
  try {
    const raw = fs.readFileSync(hashesPath, 'utf8');
    storedHashes = JSON.parse(raw);
  } catch (err) {
    return { passed: false, error: `Failed to parse profile-hashes.json: ${err.message}`, tampered: [] };
  }

  const knownGoodHashes = loadKnownGoodHashes();
  /** @type {string[]} */
  const tampered = [];

  for (const [filename, storedHash] of Object.entries(storedHashes)) {
    const filePath = path.join(profileDir, filename);
    const actualHash = sha256File(filePath);

    // File is missing on disk
    if (actualHash === null) {
      tampered.push(filename);
      continue;
    }

    // Hash mismatch against profile-hashes.json
    if (actualHash !== storedHash) {
      tampered.push(filename);
      continue;
    }

    // Cross-check against known-good-hashes.json (if the file is listed there)
    if (knownGoodHashes[filename] !== undefined && actualHash !== knownGoodHashes[filename]) {
      if (!tampered.includes(filename)) {
        tampered.push(filename);
      }
    }
  }

  return { passed: tampered.length === 0, tampered };
}
