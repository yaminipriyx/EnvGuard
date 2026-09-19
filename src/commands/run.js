/**
 * Command registration and handler for 'envguard run'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * The command handler is currently a stub that verifies argument parsing.
 * Phase 6 (Runtime Execution & Secret Injection) will replace this stub with
 * DEK unwrapping, in-memory decryption, and child process execution via spawn.
 */

import * as logger from '../client/logger.js';

/**
 * Register the 'run' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerRunCommand(program) {
  program
    .command('run <command...>')
    .description('Run a command with secrets injected into runtime memory')
    .option('--env <name>', 'Target environment name')
    .action((command, options) => {
      // Phase 6 replaces this handler
      logger.info(`Parsed command array: ${JSON.stringify(command)}`);
      for (const item of command) {
        logger.info(item);
      }
      logger.notImplemented('run', 6);
    });
}
