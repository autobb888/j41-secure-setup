import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { deployProfiles } from '../lib/deploy-profiles.js';
import { verifyProfileIntegrity } from '../lib/profile-integrity.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'j41-integrity-test-'));
}

function rmTempDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe('verifyProfileIntegrity — passes on clean deploy', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
    deployProfiles({ product: 'dispatcher', targetDir: tmpDir, skipAppArmor: true });
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('returns passed: true and empty tampered array for a fresh deploy', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.passed, true, 'passed should be true');
    assert.deepEqual(result.tampered, [], 'tampered should be empty');
  });

  it('does not have an error field on success', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.error, undefined, 'error should be undefined on success');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('verifyProfileIntegrity — jailbox clean deploy', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
    deployProfiles({ product: 'jailbox', targetDir: tmpDir, skipAppArmor: true });
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('returns passed: true for a clean jailbox deploy', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.passed, true);
    assert.deepEqual(result.tampered, []);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('verifyProfileIntegrity — tampered file', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
    deployProfiles({ product: 'dispatcher', targetDir: tmpDir, skipAppArmor: true });
    // Tamper seccomp-agent.json by appending a byte
    const filePath = path.join(tmpDir, 'seccomp-agent.json');
    fs.appendFileSync(filePath, ' ');
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('returns passed: false when a file is tampered', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.passed, false, 'passed should be false when a file is tampered');
  });

  it('reports the tampered file name', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.ok(
      result.tampered.includes('seccomp-agent.json'),
      `Expected 'seccomp-agent.json' in tampered: ${JSON.stringify(result.tampered)}`,
    );
  });

  it('does not report non-tampered files', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.ok(
      !result.tampered.includes('seccomp-bwrap.json'),
      'seccomp-bwrap.json should not be in tampered list',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('verifyProfileIntegrity — deleted file', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
    deployProfiles({ product: 'dispatcher', targetDir: tmpDir, skipAppArmor: true });
    // Delete one of the deployed files
    fs.unlinkSync(path.join(tmpDir, 'apparmor-agent'));
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('returns passed: false when a file is missing', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.passed, false);
  });

  it('reports the deleted file as tampered', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.ok(
      result.tampered.includes('apparmor-agent'),
      `Expected 'apparmor-agent' in tampered: ${JSON.stringify(result.tampered)}`,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('verifyProfileIntegrity — missing profile-hashes.json', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
    // No profiles deployed — directory is empty
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('returns passed: false with a descriptive error', async () => {
    const result = await verifyProfileIntegrity(tmpDir);
    assert.equal(result.passed, false);
    assert.ok(
      typeof result.error === 'string' && result.error.length > 0,
      'error should be a non-empty string',
    );
    assert.ok(
      result.error.includes('profile-hashes.json'),
      `error should mention 'profile-hashes.json': ${result.error}`,
    );
    assert.deepEqual(result.tampered, []);
  });
});
