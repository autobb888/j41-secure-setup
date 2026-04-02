import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// ── Imports under test ────────────────────────────────────────────────────────

import { detectPlatform } from '../lib/detect-platform.js';
import { detectIsolation } from '../lib/detect-isolation.js';
import { quickCheck } from '../lib/quick-check.js';
import { isInitialized, setup, selfTest } from '../lib/index.js';

// ── Test 1: detectPlatform returns valid data ─────────────────────────────────

describe('detectPlatform — valid return shape', () => {
  it('returns an object with all expected fields', async () => {
    const result = await detectPlatform();

    assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
    assert.ok(typeof result.os === 'string' && result.os.length > 0, 'os should be a non-empty string');
    assert.ok(typeof result.arch === 'string' && result.arch.length > 0, 'arch should be a non-empty string');
    assert.ok(typeof result.distro === 'string' && result.distro.length > 0, 'distro should be a non-empty string');
    assert.equal(typeof result.hasDocker, 'boolean', 'hasDocker should be a boolean');
    assert.equal(typeof result.dockerDesktopVM, 'boolean', 'dockerDesktopVM should be a boolean');
    assert.equal(typeof result.hasKVM, 'boolean', 'hasKVM should be a boolean');
  });

  it('os is one of the recognised platform strings', async () => {
    const result = await detectPlatform();
    // Node.js os.platform() returns 'linux', 'darwin', 'win32', etc.
    assert.ok(['linux', 'darwin', 'win32', 'freebsd'].includes(result.os),
      `Unexpected os value: ${result.os}`);
  });
});

// ── Test 2: detectIsolation returns score and mode ────────────────────────────

describe('detectIsolation — score and mode', () => {
  it('returns an object with a numeric score and string mode', async () => {
    const result = await detectIsolation();

    assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
    assert.equal(typeof result.score, 'number', 'score should be a number');
    assert.ok(result.score >= 0 && result.score <= 10, `score ${result.score} should be in range 0-10`);
    assert.equal(typeof result.mode, 'string', 'mode should be a string');
    assert.ok(result.mode.length > 0, 'mode should be non-empty');
  });

  it('returns all expected boolean fields', async () => {
    const result = await detectIsolation();
    const boolFields = [
      'gvisorInstalled',
      'gvisorDefault',
      'bwrapInstalled',
      'seccompProfilesDeployed',
      'apparmorLoaded',
      'j41NetworkExists',
      'dockerDesktopVM',
    ];
    for (const field of boolFields) {
      assert.equal(typeof result[field], 'boolean', `${field} should be a boolean`);
    }
  });
});

// ── Test 3: quickCheck('dispatcher') structure ────────────────────────────────

describe('quickCheck dispatcher — return structure', () => {
  it('returns checks array with expected structure', async () => {
    const result = await quickCheck('dispatcher');

    assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
    assert.equal(result.product, 'dispatcher', 'product should be "dispatcher"');
    assert.ok(Array.isArray(result.checks), 'checks should be an array');
    assert.ok(result.checks.length > 0, 'checks should be non-empty');
    assert.equal(typeof result.passed, 'boolean', 'passed should be a boolean');
    assert.equal(typeof result.score, 'number', 'score should be a number');
    assert.equal(typeof result.mode, 'string', 'mode should be a string');

    const VALID_STATUSES = new Set(['pass', 'fail', 'warn', 'skip']);
    for (const check of result.checks) {
      assert.equal(typeof check.name, 'string', 'check.name should be a string');
      assert.ok(check.name.length > 0, 'check.name should be non-empty');
      assert.ok(VALID_STATUSES.has(check.status), `check.status "${check.status}" should be valid`);
      assert.equal(typeof check.detail, 'string', 'check.detail should be a string');
    }
  });
});

// ── Test 4: quickCheck('jailbox') does not include financial-allowlist ─────────

describe('quickCheck jailbox — exclusions', () => {
  it('returns checks array that does not include financial-allowlist', async () => {
    const result = await quickCheck('jailbox');

    assert.ok(Array.isArray(result.checks), 'checks should be an array');
    assert.ok(result.checks.length > 0, 'checks should be non-empty');

    const names = result.checks.map((c) => c.name);
    assert.ok(!names.includes('financial-allowlist'),
      `'financial-allowlist' should not appear in jailbox checks: ${JSON.stringify(names)}`);
  });

  it('jailbox checks do not include network-allowlist or iptables-rules', async () => {
    const result = await quickCheck('jailbox');
    const names = result.checks.map((c) => c.name);
    assert.ok(!names.includes('network-allowlist'),
      `'network-allowlist' should not be in jailbox checks`);
    assert.ok(!names.includes('iptables-rules'),
      `'iptables-rules' should not be in jailbox checks`);
  });
});

// ── Test 5: isInitialized returns false for non-existent product ──────────────

describe('isInitialized — non-existent product', () => {
  it('returns false for a product that has never been initialized', () => {
    // Use a name that definitely has no marker file
    const result = isInitialized('__nonexistent_product_xyz__');
    assert.equal(result, false, 'isInitialized should return false for an unknown product');
  });

  it('returns a boolean', () => {
    const result = isInitialized('__test_product__');
    assert.equal(typeof result, 'boolean', 'isInitialized should return a boolean');
  });
});

// ── Test 6: All modules import without error ───────────────────────────────────

describe('module imports — no errors', () => {
  it('detect-platform exports detectPlatform as a function', async () => {
    const mod = await import('../lib/detect-platform.js');
    assert.equal(typeof mod.detectPlatform, 'function', 'detectPlatform should be a function');
  });

  it('detect-isolation exports detectIsolation as a function', async () => {
    const mod = await import('../lib/detect-isolation.js');
    assert.equal(typeof mod.detectIsolation, 'function', 'detectIsolation should be a function');
  });

  it('install-gvisor exports installGvisor as a function', async () => {
    const mod = await import('../lib/install-gvisor.js');
    assert.equal(typeof mod.installGvisor, 'function', 'installGvisor should be a function');
  });

  it('install-bwrap exports installBwrap as a function', async () => {
    const mod = await import('../lib/install-bwrap.js');
    assert.equal(typeof mod.installBwrap, 'function', 'installBwrap should be a function');
  });

  it('deploy-profiles exports deployProfiles as a function', async () => {
    const mod = await import('../lib/deploy-profiles.js');
    assert.equal(typeof mod.deployProfiles, 'function', 'deployProfiles should be a function');
  });

  it('setup-network exports setupNetwork and resolveAndPinDNS as functions', async () => {
    const mod = await import('../lib/setup-network.js');
    assert.equal(typeof mod.setupNetwork, 'function', 'setupNetwork should be a function');
    assert.equal(typeof mod.resolveAndPinDNS, 'function', 'resolveAndPinDNS should be a function');
  });

  it('setup-allowlist exports setupAllowlist as a function', async () => {
    const mod = await import('../lib/setup-allowlist.js');
    assert.equal(typeof mod.setupAllowlist, 'function', 'setupAllowlist should be a function');
  });

  it('profile-integrity exports verifyProfileIntegrity as a function', async () => {
    const mod = await import('../lib/profile-integrity.js');
    assert.equal(typeof mod.verifyProfileIntegrity, 'function', 'verifyProfileIntegrity should be a function');
  });

  it('quick-check exports quickCheck as a function', async () => {
    const mod = await import('../lib/quick-check.js');
    assert.equal(typeof mod.quickCheck, 'function', 'quickCheck should be a function');
  });

  it('self-test exports selfTest as a function', async () => {
    const mod = await import('../lib/self-test.js');
    assert.equal(typeof mod.selfTest, 'function', 'selfTest should be a function');
  });

  it('index.js exports setup, isInitialized, quickCheck, selfTest, detectIsolation, detectPlatform', async () => {
    const mod = await import('../lib/index.js');
    assert.equal(typeof mod.setup, 'function', 'setup should be a function');
    assert.equal(typeof mod.isInitialized, 'function', 'isInitialized should be a function');
    assert.equal(typeof mod.quickCheck, 'function', 'quickCheck should be a function');
    assert.equal(typeof mod.selfTest, 'function', 'selfTest should be a function');
    assert.equal(typeof mod.detectIsolation, 'function', 'detectIsolation should be a function');
    assert.equal(typeof mod.detectPlatform, 'function', 'detectPlatform should be a function');
  });
});
