/**
 * Command registration and handler for 'envguard set'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * The command handler is currently a stub that records Phase 1 non-implementation.
 * Phase 4 (Secret Provisioning & DEK Encryption) will replace this stub with
 * interactive prompt, stdin parsing, AES-256-GCM encryption, and server upload.
 */

import * as logger from '../client/logger.js';

/**
 * Register the 'set' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerSetCommand(program) {
  program
    .command('set [keyValue]')
    .description('Set or update an environment secret in the target vault')
    .option('--stdin', 'Read secrets from standard input')
    .option('--env <name>', 'Target environment name')
    .action((keyValue, options) => {
      logger.notImplemented('set', 4);
    });
}
