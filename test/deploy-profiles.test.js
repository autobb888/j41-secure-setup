import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import { deployProfiles } from '../lib/deploy-profiles.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Create a unique temp directory for a test.
 * @returns {string} Absolute path to the created dir
 */
function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'j41-profiles-test-'));
}

/**
 * Remove a directory and all its contents.
 * @param {string} dir
 */
function rmTempDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Compute SHA-256 hex digest of a file.
 * @param {string} filePath
 * @returns {string}
 */
function sha256File(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// ── Test suites ───────────────────────────────────────────────────────────────

describe('deployProfiles — dispatcher', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('deploys the expected dispatcher profile files', () => {
    const { profilesDeployed } = deployProfiles({
      product: 'dispatcher',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    assert.deepEqual(
      [...profilesDeployed].sort(),
      ['apparmor-agent', 'seccomp-agent.json', 'seccomp-bwrap.json'].sort(),
    );
  });

  it('all deployed files exist in targetDir', () => {
    const expected = ['seccomp-agent.json', 'seccomp-bwrap.json', 'apparmor-agent'];
    for (const file of expected) {
      assert.ok(
        fs.existsSync(path.join(tmpDir, file)),
        `Expected ${file} to exist in targetDir`,
      );
    }
  });

  it('creates profile-hashes.json in targetDir', () => {
    assert.ok(
      fs.existsSync(path.join(tmpDir, 'profile-hashes.json')),
      'profile-hashes.json should exist',
    );
  });

  it('profile-hashes.json contains correct SHA-256 for each deployed file', () => {
    const { hashes } = deployProfiles({
      product: 'dispatcher',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    for (const [filename, storedHash] of Object.entries(hashes)) {
      const actualHash = sha256File(path.join(tmpDir, filename));
      assert.equal(
        storedHash,
        actualHash,
        `Hash mismatch for ${filename}: stored ${storedHash} vs actual ${actualHash}`,
      );
    }
  });

  it('profile-hashes.json on disk matches returned hashes', () => {
    const { hashes } = deployProfiles({
      product: 'dispatcher',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    const onDisk = JSON.parse(fs.readFileSync(path.join(tmpDir, 'profile-hashes.json'), 'utf8'));
    assert.deepEqual(onDisk, hashes);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('deployProfiles — jailbox', () => {
  let tmpDir;

  before(() => {
    tmpDir = makeTempDir();
  });

  after(() => {
    rmTempDir(tmpDir);
  });

  it('deploys the expected jailbox profile files', () => {
    const { profilesDeployed } = deployProfiles({
      product: 'jailbox',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    assert.deepEqual(
      [...profilesDeployed].sort(),
      ['apparmor-jailbox', 'seccomp-bwrap.json', 'seccomp-jailbox.json'].sort(),
    );
  });

  it('all deployed files exist in targetDir', () => {
    const expected = ['seccomp-jailbox.json', 'seccomp-bwrap.json', 'apparmor-jailbox'];
    for (const file of expected) {
      assert.ok(
        fs.existsSync(path.join(tmpDir, file)),
        `Expected ${file} to exist in targetDir`,
      );
    }
  });

  it('creates profile-hashes.json in targetDir', () => {
    assert.ok(
      fs.existsSync(path.join(tmpDir, 'profile-hashes.json')),
      'profile-hashes.json should exist',
    );
  });

  it('profile-hashes.json contains correct SHA-256 for each deployed file', () => {
    const { hashes } = deployProfiles({
      product: 'jailbox',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    for (const [filename, storedHash] of Object.entries(hashes)) {
      const actualHash = sha256File(path.join(tmpDir, filename));
      assert.equal(
        storedHash,
        actualHash,
        `Hash mismatch for ${filename}: stored ${storedHash} vs actual ${actualHash}`,
      );
    }
  });

  it('profile-hashes.json on disk matches returned hashes', () => {
    const { hashes } = deployProfiles({
      product: 'jailbox',
      targetDir: tmpDir,
      skipAppArmor: true,
    });

    const onDisk = JSON.parse(fs.readFileSync(path.join(tmpDir, 'profile-hashes.json'), 'utf8'));
    assert.deepEqual(onDisk, hashes);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('deployProfiles — edge cases', () => {
  it('throws for an unknown product', () => {
    assert.throws(
      () => deployProfiles({ product: 'unknown', targetDir: os.tmpdir(), skipAppArmor: true }),
      /Unknown product/,
    );
  });

  it('creates targetDir if it does not exist', () => {
    const base = makeTempDir();
    const nested = path.join(base, 'deep', 'nested', 'dir');

    try {
      deployProfiles({ product: 'dispatcher', targetDir: nested, skipAppArmor: true });
      assert.ok(fs.existsSync(nested), 'nested targetDir should have been created');
    } finally {
      rmTempDir(base);
    }
  });

  it('shared seccomp-bwrap.json hash is consistent across products', () => {
    const dirA = makeTempDir();
    const dirB = makeTempDir();

    try {
      const { hashes: hashesA } = deployProfiles({
        product: 'dispatcher',
        targetDir: dirA,
        skipAppArmor: true,
      });
      const { hashes: hashesB } = deployProfiles({
        product: 'jailbox',
        targetDir: dirB,
        skipAppArmor: true,
      });

      assert.equal(
        hashesA['seccomp-bwrap.json'],
        hashesB['seccomp-bwrap.json'],
        'seccomp-bwrap.json hash should be the same regardless of product',
      );
    } finally {
      rmTempDir(dirA);
      rmTempDir(dirB);
    }
  });
});
