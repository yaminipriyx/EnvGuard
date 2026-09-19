/**
 * Logger module for EnvGuard CLI terminal output formatting.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * Provides standardized terminal output methods with Chalk formatting.
 * Later phases will use this logger for user-facing CLI messages and error reporting.
 */

import chalk from 'chalk';

/**
 * Output an informational message to stdout.
 *
 * @param {string} message - The message text to print.
 */
export function info(message) {
  console.log(`[info] ${message}`);
}

/**
 * Output a success message to stdout with green ok prefix.
 *
 * @param {string} message - The message text to print.
 */
export function success(message) {
  console.log(`${chalk.green('[ok]')} ${message}`);
}

/**
 * Output a warning message to stderr with yellow warn prefix.
 *
 * @param {string} message - The warning text to print.
 */
export function warn(message) {
  console.error(`${chalk.yellow('[warn]')} ${message}`);
}

/**
 * Output an error message to stderr with red error prefix.
 *
 * @param {string} message - The error text to print.
 */
export function error(message) {
  console.error(`${chalk.red('[error]')} ${message}`);
}

/**
 * Output a not-implemented notice to stderr and set exit code to 1.
 *
 * @param {string} commandName - Name of the stubbed command.
 * @param {number|string} phaseNumber - The future phase scheduled to implement this command.
 */
export function notImplemented(commandName, phaseNumber) {
  console.error(`${chalk.yellow('[warn]')} "${commandName}" is not implemented yet (planned for Phase ${phaseNumber})`);
  process.exitCode = 1;
}
