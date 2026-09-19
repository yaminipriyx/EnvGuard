/**
 * Command registration and handler for 'envguard revoke'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * The command handler is currently a stub that records Phase 1 non-implementation.
 * Phase 5 (Access Management: Grant & Revoke) will replace this stub with
 * DEK rotation, re-encryption, member deletion, and server submission.
 */

import * as logger from '../client/logger.js';

/**
 * Register the 'revoke' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerRevokeCommand(program) {
  program
    .command('revoke <username>')
    .description('Revoke vault access from a user and trigger DEK rotation')
    .option('--env <name>', 'Target environment name')
    .action((username, options) => {
      logger.notImplemented('revoke', 5);
    });
}
