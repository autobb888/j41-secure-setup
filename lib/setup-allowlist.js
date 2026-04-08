import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/** Directory for J41 config files */
const J41_DIR = path.join(os.homedir(), '.j41');

/** Path to the financial allowlist file */
const ALLOWLIST_PATH = path.join(J41_DIR, 'financial-allowlist.json');

/** Default allowlist structure */
const DEFAULT_ALLOWLIST = {
  permanent: [],
  operator: [],
  active_jobs: [],
};

/**
 * Create `~/.j41/financial-allowlist.json` with default structure if it does
 * not already exist.  The file is written with mode 0o600 (owner read/write
 * only) and the parent directory is created as needed.
 *
 * @returns {{ status: 'created' | 'already-exists', path: string }}
 */
export function setupAllowlist() {
  // Ensure ~/.j41/ directory exists
  fs.mkdirSync(J41_DIR, { recursive: true, mode: 0o700 });

  // If the file already exists, return without overwriting
  if (fs.existsSync(ALLOWLIST_PATH)) {
    return { status: 'already-exists', path: ALLOWLIST_PATH };
  }

  // Write file with restrictive permissions (owner r/w only)
  fs.writeFileSync(
    ALLOWLIST_PATH,
    JSON.stringify(DEFAULT_ALLOWLIST, null, 2),
    { encoding: 'utf8', mode: 0o600 },
  );

  return { status: 'created', path: ALLOWLIST_PATH };
}
