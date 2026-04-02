import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectIsolation } from '../lib/detect-isolation.js';

const VALID_MODES = ['gvisor', 'bwrap', 'macos-vm', 'docker-only'];

test('detectIsolation returns an object with all expected fields', async () => {
  const result = await detectIsolation();
  assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
  assert.ok('gvisorInstalled' in result, 'result should have gvisorInstalled field');
  assert.ok('gvisorDefault' in result, 'result should have gvisorDefault field');
  assert.ok('bwrapInstalled' in result, 'result should have bwrapInstalled field');
  assert.ok('seccompProfilesDeployed' in result, 'result should have seccompProfilesDeployed field');
  assert.ok('apparmorLoaded' in result, 'result should have apparmorLoaded field');
  assert.ok('j41NetworkExists' in result, 'result should have j41NetworkExists field');
  assert.ok('dockerDesktopVM' in result, 'result should have dockerDesktopVM field');
  assert.ok('score' in result, 'result should have score field');
  assert.ok('mode' in result, 'result should have mode field');
});

test('all boolean fields are booleans', async () => {
  const result = await detectIsolation();
  const booleanFields = [
    'gvisorInstalled',
    'gvisorDefault',
    'bwrapInstalled',
    'seccompProfilesDeployed',
    'apparmorLoaded',
    'j41NetworkExists',
    'dockerDesktopVM',
  ];
  for (const field of booleanFields) {
    assert.strictEqual(
      typeof result[field],
      'boolean',
      `${field} should be a boolean, got ${typeof result[field]}`
    );
  }
});

test('score is a number between 0 and 10 inclusive', async () => {
  const result = await detectIsolation();
  assert.strictEqual(typeof result.score, 'number', 'score should be a number');
  assert.ok(result.score >= 0, `score should be >= 0, got ${result.score}`);
  assert.ok(result.score <= 10, `score should be <= 10, got ${result.score}`);
});

test('mode is one of the valid mode strings', async () => {
  const result = await detectIsolation();
  assert.ok(
    VALID_MODES.includes(result.mode),
    `mode should be one of ${VALID_MODES.join(', ')}, got '${result.mode}'`
  );
});
