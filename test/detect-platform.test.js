import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectPlatform } from '../lib/detect-platform.js';

test('detectPlatform returns an object with all expected fields', async () => {
  const result = await detectPlatform();
  assert.ok(typeof result === 'object' && result !== null, 'result should be an object');
  assert.ok('os' in result, 'result should have os field');
  assert.ok('arch' in result, 'result should have arch field');
  assert.ok('distro' in result, 'result should have distro field');
  assert.ok('hasDocker' in result, 'result should have hasDocker field');
  assert.ok('dockerDesktopVM' in result, 'result should have dockerDesktopVM field');
  assert.ok('hasKVM' in result, 'result should have hasKVM field');
});

test('os is one of linux or darwin', async () => {
  const result = await detectPlatform();
  assert.ok(
    result.os === 'linux' || result.os === 'darwin',
    `os should be 'linux' or 'darwin', got '${result.os}'`
  );
});

test('arch is one of x64 or arm64', async () => {
  const result = await detectPlatform();
  assert.ok(
    result.arch === 'x64' || result.arch === 'arm64',
    `arch should be 'x64' or 'arm64', got '${result.arch}'`
  );
});

test('hasDocker is a boolean', async () => {
  const result = await detectPlatform();
  assert.strictEqual(typeof result.hasDocker, 'boolean', 'hasDocker should be a boolean');
});

test('dockerDesktopVM is a boolean', async () => {
  const result = await detectPlatform();
  assert.strictEqual(typeof result.dockerDesktopVM, 'boolean', 'dockerDesktopVM should be a boolean');
});

test('distro is a non-empty string', async () => {
  const result = await detectPlatform();
  assert.strictEqual(typeof result.distro, 'string', 'distro should be a string');
  assert.ok(result.distro.length > 0, 'distro should be non-empty');
});

test('hasKVM is a boolean', async () => {
  const result = await detectPlatform();
  assert.strictEqual(typeof result.hasKVM, 'boolean', 'hasKVM should be a boolean');
});
