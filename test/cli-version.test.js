import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const BIN = new URL('../bin/j41-secure-setup.js', import.meta.url).pathname;
const PKG = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
);

function run(...args) {
  return execFileSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    timeout: 10_000,
  });
}

test('--version prints the installed package version', () => {
  assert.strictEqual(run('--version').trim(), PKG.version);
});

test('-v is an alias for --version', () => {
  assert.strictEqual(run('-v').trim(), PKG.version);
});

// --version must never fall through into setup: a newcomer running it on a
// fresh box should get a version string, not a privileged install.
test('--version does not run setup, even with a product flag', () => {
  const out = run('--version', '--jailbox');
  assert.strictEqual(out.trim(), PKG.version);
});

test('--help still lists the version flag', () => {
  assert.match(run('--help'), /--version, -v/);
});
