#!/usr/bin/env node

import { setup, isInitialized } from '../lib/index.js';
import { quickCheck } from '../lib/quick-check.js';
import { selfTest } from '../lib/self-test.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function printUsage() {
  console.log(`
Usage: j41-secure-setup [product] [action]

Product flags:
  --dispatcher          Target the dispatcher product
  --jailbox             Target the jailbox product

Action flags:
  (no action)           Run first-run setup for the specified product
  --check               Run quickCheck (all initialized products, or specified product)
  --test                Run selfTest (requires a product flag)
  --fix                 Re-run setup (all products, or specified product)

Other:
  --help, -h            Show this help message

Examples:
  j41-secure-setup --dispatcher
  j41-secure-setup --jailbox
  j41-secure-setup --check
  j41-secure-setup --check --dispatcher
  j41-secure-setup --test --dispatcher
  j41-secure-setup --fix
  j41-secure-setup --fix --jailbox
`.trim());
}

/**
 * Print quickCheck results for a product.
 * @param {'dispatcher'|'jailbox'} product
 */
async function runCheck(product) {
  console.log(`\nQuick Check: ${product}`);
  console.log('-'.repeat(36));

  const result = await quickCheck(product);

  for (const check of result.checks) {
    const icon = check.status === 'pass' ? '\u2713'
      : check.status === 'skip' ? '-'
      : check.status === 'warn' ? '!'
      : '\u2717';
    console.log(`  ${icon} [${check.status.padEnd(4)}] ${check.name}: ${check.detail}`);
  }

  console.log('');
  console.log(`Score : ${result.score}/10`);
  console.log(`Mode  : ${result.mode}`);
  console.log(`Passed: ${result.passed}`);

  return result.passed;
}

/**
 * Print selfTest results for a product.
 * @param {'dispatcher'|'jailbox'} product
 */
async function runSelfTest(product) {
  console.log(`\nSelf-Test: ${product}`);
  console.log('-'.repeat(36));

  const result = await selfTest(product);

  for (const r of result.results) {
    const icon = r.passed ? '\u2713' : '\u2717';
    const errSuffix = r.error ? ` — ${r.error}` : '';
    console.log(`  ${icon} ${r.name}${errSuffix}`);
  }

  console.log('');
  console.log(`Score : ${result.score}/10`);
  console.log(`Mode  : ${result.mode}`);
  console.log(`Passed: ${result.passed}`);

  return result.passed;
}

// ── Argument parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);

const hasDispatcher = args.includes('--dispatcher');
const hasJailbox = args.includes('--jailbox');
const hasCheck = args.includes('--check');
const hasTest = args.includes('--test');
const hasFix = args.includes('--fix');
const hasHelp = args.includes('--help') || args.includes('-h');

const ALL_PRODUCTS = ['dispatcher', 'jailbox'];

// No arguments → print help
if (args.length === 0 || hasHelp) {
  printUsage();
  process.exit(0);
}

// ── Action dispatch ───────────────────────────────────────────────────────────

let exitCode = 0;

try {
  if (hasCheck) {
    // --check: run quickCheck for specified product(s), or all initialized products
    let products = [];

    if (hasDispatcher) {
      products = ['dispatcher'];
    } else if (hasJailbox) {
      products = ['jailbox'];
    } else {
      // All initialized products
      products = ALL_PRODUCTS.filter((p) => isInitialized(p));
      if (products.length === 0) {
        console.log('No initialized products found. Run setup first.');
        process.exit(1);
      }
    }

    for (const product of products) {
      const passed = await runCheck(product);
      if (!passed) exitCode = 1;
    }

  } else if (hasTest) {
    // --test: requires a product flag
    const products = [];
    if (hasDispatcher) products.push('dispatcher');
    if (hasJailbox) products.push('jailbox');

    if (products.length === 0) {
      console.error('--test requires a product flag (--dispatcher or --jailbox)');
      process.exit(1);
    }

    for (const product of products) {
      const passed = await runSelfTest(product);
      if (!passed) exitCode = 1;
    }

  } else if (hasFix) {
    // --fix: re-run setup for specified product(s), or all
    let products = [];

    if (hasDispatcher) {
      products = ['dispatcher'];
    } else if (hasJailbox) {
      products = ['jailbox'];
    } else {
      products = ALL_PRODUCTS;
    }

    for (const product of products) {
      const result = await setup(product);
      if (!result.success) exitCode = 1;
    }

  } else {
    // Default: run setup for specified product(s)
    const products = [];
    if (hasDispatcher) products.push('dispatcher');
    if (hasJailbox) products.push('jailbox');

    if (products.length === 0) {
      console.error('Please specify a product: --dispatcher or --jailbox');
      printUsage();
      process.exit(1);
    }

    for (const product of products) {
      const result = await setup(product);
      if (!result.success) exitCode = 1;
    }
  }
} catch (err) {
  console.error(`Fatal error: ${err.message}`);
  exitCode = 1;
}

process.exit(exitCode);
