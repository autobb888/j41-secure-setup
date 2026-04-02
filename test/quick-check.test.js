import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { quickCheck } from '../lib/quick-check.js';

// ── Shared helpers ────────────────────────────────────────────────────────────

const VALID_STATUSES = new Set(['pass', 'fail', 'warn', 'skip']);

// ── Test suites ───────────────────────────────────────────────────────────────

describe('quickCheck — return shape', () => {
  it('returns an object with checks array, passed boolean, score number, mode string (dispatcher)', async () => {
    const result = await quickCheck('dispatcher');

    assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
    assert.ok(Array.isArray(result.checks), 'checks should be an array');
    assert.equal(typeof result.passed, 'boolean', 'passed should be a boolean');
    assert.equal(typeof result.score, 'number', 'score should be a number');
    assert.equal(typeof result.mode, 'string', 'mode should be a string');
    assert.equal(result.product, 'dispatcher', 'product should be "dispatcher"');
  });

  it('returns an object with checks array, passed boolean, score number, mode string (jailbox)', async () => {
    const result = await quickCheck('jailbox');

    assert.ok(Array.isArray(result.checks), 'checks should be an array');
    assert.equal(typeof result.passed, 'boolean');
    assert.equal(typeof result.score, 'number');
    assert.equal(typeof result.mode, 'string');
    assert.equal(result.product, 'jailbox');
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('quickCheck — check item shape', () => {
  it('all dispatcher checks have name, status, and detail fields', async () => {
    const { checks } = await quickCheck('dispatcher');

    assert.ok(checks.length > 0, 'checks array should not be empty');

    for (const check of checks) {
      assert.equal(typeof check.name, 'string', `check.name should be a string: ${JSON.stringify(check)}`);
      assert.ok(check.name.length > 0, `check.name should be non-empty: ${JSON.stringify(check)}`);

      assert.ok(
        VALID_STATUSES.has(check.status),
        `check.status '${check.status}' must be one of: pass, fail, warn, skip`,
      );

      assert.equal(typeof check.detail, 'string', `check.detail should be a string: ${JSON.stringify(check)}`);
    }
  });

  it('all jailbox checks have name, status, and detail fields', async () => {
    const { checks } = await quickCheck('jailbox');

    assert.ok(checks.length > 0, 'checks array should not be empty');

    for (const check of checks) {
      assert.equal(typeof check.name, 'string');
      assert.ok(check.name.length > 0);
      assert.ok(VALID_STATUSES.has(check.status), `Invalid status '${check.status}'`);
      assert.equal(typeof check.detail, 'string');
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('quickCheck — passed logic', () => {
  it('passed is false if any check has status "fail" (dispatcher)', async () => {
    const { checks, passed } = await quickCheck('dispatcher');
    const hasFail = checks.some((c) => c.status === 'fail');
    if (hasFail) {
      assert.equal(passed, false, 'passed should be false when there is a fail check');
    } else {
      assert.equal(passed, true, 'passed should be true when there are no fail checks');
    }
  });

  it('passed is false if any check has status "fail" (jailbox)', async () => {
    const { checks, passed } = await quickCheck('jailbox');
    const hasFail = checks.some((c) => c.status === 'fail');
    if (hasFail) {
      assert.equal(passed, false);
    } else {
      assert.equal(passed, true);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('quickCheck — dispatcher-specific checks', () => {
  it('dispatcher checks include "financial-allowlist"', async () => {
    const { checks } = await quickCheck('dispatcher');
    const names = checks.map((c) => c.name);
    assert.ok(
      names.includes('financial-allowlist'),
      `Expected 'financial-allowlist' in dispatcher checks: ${JSON.stringify(names)}`,
    );
  });

  it('dispatcher checks include "network-allowlist"', async () => {
    const { checks } = await quickCheck('dispatcher');
    const names = checks.map((c) => c.name);
    assert.ok(
      names.includes('network-allowlist'),
      `Expected 'network-allowlist' in dispatcher checks: ${JSON.stringify(names)}`,
    );
  });

  it('dispatcher checks include "j41-isolated-network"', async () => {
    const { checks } = await quickCheck('dispatcher');
    const names = checks.map((c) => c.name);
    assert.ok(
      names.includes('j41-isolated-network'),
      `Expected 'j41-isolated-network' in dispatcher checks: ${JSON.stringify(names)}`,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('quickCheck — jailbox exclusions', () => {
  it('jailbox checks do not include "financial-allowlist"', async () => {
    const { checks } = await quickCheck('jailbox');
    const names = checks.map((c) => c.name);
    assert.ok(
      !names.includes('financial-allowlist'),
      `'financial-allowlist' should not appear in jailbox checks: ${JSON.stringify(names)}`,
    );
  });

  it('jailbox checks do not include "network-allowlist"', async () => {
    const { checks } = await quickCheck('jailbox');
    const names = checks.map((c) => c.name);
    assert.ok(
      !names.includes('network-allowlist'),
      `'network-allowlist' should not appear in jailbox checks: ${JSON.stringify(names)}`,
    );
  });

  it('jailbox checks do not include "iptables-rules"', async () => {
    const { checks } = await quickCheck('jailbox');
    const names = checks.map((c) => c.name);
    assert.ok(
      !names.includes('iptables-rules'),
      `'iptables-rules' should not appear in jailbox checks: ${JSON.stringify(names)}`,
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe('quickCheck — shared checks present in both products', () => {
  it('dispatcher includes shared check "gvisor-or-bwrap"', async () => {
    const { checks } = await quickCheck('dispatcher');
    const names = checks.map((c) => c.name);
    assert.ok(names.includes('gvisor-or-bwrap'), `Missing 'gvisor-or-bwrap': ${JSON.stringify(names)}`);
  });

  it('jailbox includes shared check "gvisor-or-bwrap"', async () => {
    const { checks } = await quickCheck('jailbox');
    const names = checks.map((c) => c.name);
    assert.ok(names.includes('gvisor-or-bwrap'), `Missing 'gvisor-or-bwrap': ${JSON.stringify(names)}`);
  });

  it('dispatcher includes shared check "profile-integrity"', async () => {
    const { checks } = await quickCheck('dispatcher');
    const names = checks.map((c) => c.name);
    assert.ok(names.includes('profile-integrity'), `Missing 'profile-integrity': ${JSON.stringify(names)}`);
  });

  it('jailbox includes shared check "profile-integrity"', async () => {
    const { checks } = await quickCheck('jailbox');
    const names = checks.map((c) => c.name);
    assert.ok(names.includes('profile-integrity'), `Missing 'profile-integrity': ${JSON.stringify(names)}`);
  });
});
