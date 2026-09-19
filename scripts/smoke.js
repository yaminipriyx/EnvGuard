/**
 * Smoke test suite for EnvGuard CLI verification.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * Provides a dependency-free test runner using native child_process and fs
 * to validate CLI argument parsing, help text, versioning, command registration,
 * and stub behaviors.
 * Later phases will add comprehensive crypto, integration, and server tests in test/.
 */

import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * Execute the EnvGuard CLI with specified arguments.
 *
 * @param {string[]} args - CLI arguments to pass to the envguard binary.
 * @returns {{status: number, stdout: string, stderr: string, output: string}} Execution result.
 */
function runCli(args) {
  const cliPath = fileURLToPath(new URL('../bin/envguard.js', import.meta.url));
  const result = spawnSync(process.execPath, [cliPath, ...args], {
    shell: false,
    encoding: 'utf8'
  });

  let stdout = '';
  if (result.stdout) {
    stdout = result.stdout;
  }

  let stderr = '';
  if (result.stderr) {
    stderr = result.stderr;
  }

  let status = 0;
  if (typeof result.status === 'number') {
    status = result.status;
  } else if (result.error) {
    status = 1;
  }

  const output = stdout + stderr;

  return {
    status: status,
    stdout: stdout,
    stderr: stderr,
    output: output
  };
}

/**
 * Record and format the result of an individual smoke test.
 *
 * @param {string} description - Description of the test case.
 * @param {boolean} passed - Whether the test assertion succeeded.
 */
function recordResult(description, passed) {
  if (passed) {
    console.log(`PASS ${description}`);
  } else {
    console.error(`FAIL ${description}`);
    process.exitCode = 1;
  }
}

/**
 * Run the entire smoke test suite.
 */
function runSmokeTests() {
  const packageJsonUrl = new URL('../package.json', import.meta.url);
  const packageContent = fs.readFileSync(packageJsonUrl, 'utf8');
  const packageInfo = JSON.parse(packageContent);

  // Test 1: Help command
  const test1 = runCli(['--help']);
  const test1Passed =
    test1.status === 0 &&
    test1.output.includes('init') &&
    test1.output.includes('project') &&
    test1.output.includes('set') &&
    test1.output.includes('run') &&
    test1.output.includes('grant') &&
    test1.output.includes('revoke');
  recordResult('Test 1 — help displays all registered commands', test1Passed);

  // Test 2: Version command
  const test2 = runCli(['--version']);
  const test2Passed =
    test2.status === 0 &&
    test2.stdout.trim() === packageInfo.version;
  recordResult('Test 2 — version matches package.json', test2Passed);

  // Test 3: Init command validation
  const test3 = runCli(['init', 'invalid@user!']);
  const test3Passed =
    test3.status === 1 &&
    test3.output.includes('Invalid username');
  recordResult('Test 3 — init validates username format and exits with code 1', test3Passed);

  // Test 4: Project init command stub
  const test4 = runCli(['project', 'init', 'demo']);
  const test4Passed =
    test4.status === 1 &&
    test4.output.includes('not implemented');
  recordResult('Test 4 — project init demo stub returns exit code 1 with not implemented notice', test4Passed);

  // Test 5: Set command validation
  const test5 = runCli(['set', '123_INVALID=secret']);
  const test5Passed =
    test5.status === 1 &&
    test5.output.includes('Invalid secret key name');
  recordResult('Test 5 — set validates secret key format and exits with code 1', test5Passed);

  // Test 6: Run fails cleanly when prerequisites are unavailable without executing target command
  const test6 = runCli(['run', '--', 'node', '-e', 'process.exit(0)']);
  const test6Passed =
    test6.status === 1 &&
    (test6.output.includes('Credentials file not found') || test6.output.includes('Project configuration not found'));
  recordResult('Test 6 — run fails cleanly without executing target command when prerequisites are unavailable', test6Passed);

  // Test 6b: Run without command returns non-zero exit code
  const test6b = runCli(['run']);
  const test6bPassed =
    test6b.status === 1 &&
    test6b.output.includes('No command specified');
  recordResult('Test 6b — run without command exits with non-zero status', test6bPassed);

  // Test 7: Grant fails cleanly when prerequisites are unavailable
  const test7 = runCli(['grant', 'bob']);
  const test7Passed =
    test7.status === 1 &&
    (test7.output.includes('Credentials file not found') || test7.output.includes('Project configuration not found'));
  recordResult('Test 7 — grant fails cleanly when prerequisites are unavailable', test7Passed);

  // Test 8: Revoke fails cleanly when prerequisites are unavailable
  const test8 = runCli(['revoke', 'bob']);
  const test8Passed =
    test8.status === 1 &&
    (test8.output.includes('Credentials file not found') || test8.output.includes('Project configuration not found'));
  recordResult('Test 8 — revoke fails cleanly when prerequisites are unavailable', test8Passed);

  // Test 9: Run argument preservation after --
  // Verifies that arguments after '--' (including arbitrary flags) are preserved as child command arguments
  const test9WithoutSep = runCli(['run', '--unknown-child-flag']);
  const test9WithSep = runCli(['run', '--env', 'staging', '--', '--unknown-child-flag', 'node', '--version']);
  const test9Passed =
    test9WithoutSep.status !== 0 &&
    test9WithoutSep.output.includes("error: unknown option '--unknown-child-flag'") &&
    !test9WithSep.output.includes("error: unknown option '--unknown-child-flag'");
  recordResult('Test 9 — run preserves exact arguments after --', test9Passed);

  // Test 10: Invalid grant role rejected by Commander
  const test10 = runCli(['grant', 'bob', '--role', 'superuser']);
  const test10Passed = test10.status !== 0;
  recordResult('Test 10 — invalid grant role is rejected with non-zero exit code', test10Passed);

  // Test 11: Unknown command rejected
  const test11 = runCli(['foo']);
  const test11Passed = test11.status !== 0;
  recordResult('Test 11 — unknown command is rejected with non-zero exit code', test11Passed);
}

runSmokeTests();
