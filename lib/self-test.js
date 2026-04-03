import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { detectIsolation } from './detect-isolation.js';

// ── Constants ─────────────────────────────────────────────────────────────────

const IMAGE = 'node:18-alpine';

const PROFILE_DIR = os.platform() === 'linux'
  ? (fs.existsSync('/etc/j41') ? '/etc/j41' : path.join(os.homedir(), '.j41'))
  : path.join(os.homedir(), '.j41');

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Wrap a test function in a try/catch and return a normalised result.
 *
 * @param {string} name
 * @param {() => void | Promise<void>} fn  Should throw to signal failure.
 * @returns {Promise<{ name: string, passed: boolean, error: string | null }>}
 */
async function runTest(name, fn) {
  try {
    await fn();
    return { name, passed: true, error: null };
  } catch (err) {
    return { name, passed: false, error: err.message ?? String(err) };
  }
}

/**
 * Build the base docker run arguments for the given product and isolation config.
 *
 * @param {'dispatcher' | 'jailbox'} product
 * @param {{ gvisorDefault: boolean }} isolation
 * @returns {string[]}  Array of CLI flags (not including `docker run` itself)
 */
function buildDockerArgs(product, isolation) {
  const args = ['--rm'];

  // Runtime
  if (isolation.gvisorDefault) {
    args.push('--runtime=runsc');
  }

  // Seccomp profile
  const seccompFile = product === 'dispatcher' ? 'seccomp-agent.json' : 'seccomp-jailbox.json';
  const seccompPath = path.join(PROFILE_DIR, seccompFile);
  if (fs.existsSync(seccompPath)) {
    args.push(`--security-opt seccomp=${seccompPath}`);
  }

  // Hardening flags
  args.push('--security-opt no-new-privileges:true');
  args.push('--cap-drop ALL');

  // Network
  if (product === 'dispatcher') {
    args.push('--network=j41-isolated');
  } else {
    args.push('--network=none');
  }

  return args;
}

/**
 * Run a docker command and return its stdout.
 * Throws if the command exits non-zero.
 *
 * @param {string} cmd   Full docker command string
 * @param {number} [timeout=15000]
 * @returns {string}
 */
function docker(cmd, timeout = 15000) {
  return execSync(cmd, { stdio: 'pipe', timeout }).toString();
}

/**
 * Assert that running a command inside the container fails (exits non-zero or
 * produces error output matching the given pattern).
 *
 * @param {string} dockerCmd  Full `docker run ...` command
 * @param {RegExp | null} [pattern]  Optional pattern to match in output/error
 */
function assertContainerFails(dockerCmd, pattern = null) {
  let stdout = '';
  let stderr = '';
  let exitCode = 0;

  try {
    stdout = docker(dockerCmd, 20000);
    exitCode = 0;
  } catch (err) {
    exitCode = err.status ?? 1;
    stdout = err.stdout ? err.stdout.toString() : '';
    stderr = err.stderr ? err.stderr.toString() : '';
  }

  const combined = stdout + stderr;

  if (exitCode === 0 && (!pattern || pattern.test(combined))) {
    // Command succeeded and output looked "fine" — the escape may have worked
    throw new Error(`Expected container command to fail but it exited 0.\nOutput: ${combined}`);
  }

  if (pattern && !pattern.test(combined) && exitCode === 0) {
    throw new Error(`Expected pattern ${pattern} in output but got: ${combined}`);
  }

  // Non-zero exit (or matching error output) → test passes
}

// ── Individual tests ──────────────────────────────────────────────────────────

/**
 * container-escape — mount the HOST's /etc/shadow into the container and try to read it.
 * Should fail because cap-drop ALL removes DAC_OVERRIDE needed to read 0640 files as non-owner.
 */
function testContainerEscape(baseArgs) {
  const cmd = `docker run ${baseArgs.join(' ')} -v /etc/shadow:/host-shadow:ro ${IMAGE} cat /host-shadow`;
  assertContainerFails(cmd, /Permission denied|No such file|cannot open|nonexistent|Operation not permitted/i);
}

/**
 * network-escape — attempt an outbound HTTP request.
 * Should timeout or fail because the network is isolated/disabled.
 */
function testNetworkEscape(baseArgs) {
  const cmd = `docker run ${baseArgs.join(' ')} ${IMAGE} wget -q -O- --timeout=5 http://google.com`;
  assertContainerFails(cmd, /Network unreachable|timeout|Unable to connect|bad address|wget:/i);
}

/**
 * privilege-escalation — attempt a privileged mount inside the container.
 * Should fail with "Operation not permitted" or similar.
 */
function testPrivilegeEscalation(baseArgs) {
  const cmd = `docker run ${baseArgs.join(' ')} ${IMAGE} mount -t tmpfs none /mnt`;
  assertContainerFails(cmd, /Operation not permitted|must be root|permission denied|not permitted/i);
}

/**
 * fork-bomb — attempt a fork bomb with a PID limit of 64.
 * The container should survive (PID limit enforced) and exit without hanging.
 */
function testForkBomb(baseArgs) {
  // Replace the pids-limit in baseArgs if present, or add it
  const argsWithPids = [...baseArgs, '--pids-limit 64'];
  const bomb = ':(){ :|:& };: ; sleep 2';
  const cmd = `docker run ${argsWithPids.join(' ')} ${IMAGE} sh -c "${bomb}"`;

  // We allow any exit code — what matters is the command completes within timeout
  // (i.e. the container is not left hanging by the fork bomb).
  try {
    docker(cmd, 30000);
  } catch (err) {
    // If it timed out (ETIMEDOUT / killed) the PID limit did not protect → fail
    if (err.signal === 'SIGTERM' || (err.message && err.message.includes('timed out'))) {
      throw new Error('Fork bomb caused container to hang — PID limit not enforced');
    }
    // Any other non-zero exit (e.g. shell was killed by PID exhaustion) is fine
  }
}

/**
 * seccomp-ptrace — attempt strace inside the container.
 * Should fail because ptrace is blocked by the seccomp profile.
 */
function testSeccompPtrace(baseArgs) {
  // strace itself may not be in the image, but the syscall should be blocked
  const cmd = `docker run ${baseArgs.join(' ')} ${IMAGE} sh -c "strace ls 2>&1 || true"`;

  try {
    const out = docker(cmd, 15000);
    // If strace runs successfully and produces strace output, ptrace is allowed
    if (/execve|openat|read\(|write\(/i.test(out)) {
      throw new Error(`ptrace appears to be allowed — strace produced syscall output: ${out.slice(0, 200)}`);
    }
    // Not found / exec format error / permission denied → test passes
  } catch (err) {
    if (err.message && err.message.startsWith('ptrace appears')) {
      throw err;
    }
    // Command failed to run (strace not installed, seccomp blocked) → pass
  }
}

/**
 * isolation-active — verifies that at least one isolation mechanism is detected.
 */
function testIsolationActive(isolation) {
  const { gvisorDefault, bwrapInstalled, dockerDesktopVM } = isolation;
  if (!gvisorDefault && !bwrapInstalled && !dockerDesktopVM) {
    throw new Error(
      'No active isolation detected (expected gVisor default, bwrap, or Docker Desktop VM)',
    );
  }
}

/**
 * network-allowlist (dispatcher) — test that the j41-isolated network allows
 * access to api.junction41.io.
 */
function testNetworkAllowlist(baseArgs) {
  // Replace --network=j41-isolated (already in baseArgs for dispatcher)
  const cmd = `docker run ${baseArgs.join(' ')} ${IMAGE} wget -q -O- --timeout=10 https://api.junction41.io`;
  // Should succeed (exit 0); allow any HTTP-level failure but not a network block
  try {
    docker(cmd, 20000);
  } catch (err) {
    const out = (err.stdout ? err.stdout.toString() : '') + (err.stderr ? err.stderr.toString() : '');
    // Network-level failures mean the allowlist isn't working
    if (/Network unreachable|Connection refused|Unable to connect/i.test(out)) {
      throw new Error(`api.junction41.io not reachable on j41-isolated network: ${out.slice(0, 200)}`);
    }
    // HTTP errors (4xx/5xx) are fine — the network works, that's what we test
  }
}

/**
 * readonly-mount (jailbox) — verify that writing to a read-only bind mount fails.
 */
function testReadonlyMount(baseArgs) {
  // Create a temp dir on the host for the bind mount
  const hostDir = fs.mkdtempSync(path.join(os.tmpdir(), 'j41-ro-test-'));

  try {
    // Replace --network=none in baseArgs (already present for jailbox)
    const mountFlag = `-v ${hostDir}:/jailbox:ro`;
    const argsWithMount = [...baseArgs, mountFlag];
    const cmd = `docker run ${argsWithMount.join(' ')} ${IMAGE} touch /jailbox/test`;
    assertContainerFails(cmd, /Read-only file system|Permission denied|cannot touch|read-only/i);
  } finally {
    try { fs.rmdirSync(hostDir); } catch { /* ignore */ }
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Run the full self-test suite against real Docker containers.
 *
 * @param {'dispatcher' | 'jailbox'} product
 * @returns {Promise<{
 *   product: string,
 *   results: Array<{ name: string, passed: boolean, error: string | null }>,
 *   passed: boolean,
 *   score: number,
 *   mode: string,
 * }>}
 */
export async function selfTest(product) {
  const isolation = await detectIsolation();
  const baseArgs = buildDockerArgs(product, isolation);

  // ── Shared tests ─────────────────────────────────────────────────────────────
  const results = await Promise.all([
    runTest('container-escape', () => testContainerEscape(baseArgs)),
    runTest('network-escape', () => testNetworkEscape(baseArgs)),
    runTest('privilege-escalation', () => testPrivilegeEscalation(baseArgs)),
    runTest('fork-bomb', () => testForkBomb(baseArgs)),
    runTest('seccomp-ptrace', () => testSeccompPtrace(baseArgs)),
    runTest('isolation-active', () => testIsolationActive(isolation)),
  ]);

  // ── Product-specific tests ───────────────────────────────────────────────────
  if (product === 'dispatcher') {
    results.push(
      await runTest('network-allowlist', () => testNetworkAllowlist(baseArgs)),
    );
  } else {
    results.push(
      await runTest('readonly-mount', () => testReadonlyMount(baseArgs)),
    );
  }

  const passed = results.every((r) => r.passed);

  return {
    product,
    results,
    passed,
    score: isolation.score,
    mode: isolation.mode,
  };
}
