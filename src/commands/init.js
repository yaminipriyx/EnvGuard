/**
 * Command registration and handler for 'envguard init'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * The command handler is currently a stub that records Phase 1 non-implementation.
 * Phase 3 (Client Identity & Enrollment) will replace this stub with keypair generation,
 * master passphrase derivation, and Vault Server registration.
 */

import * as logger from '../client/logger.js';

/**
 * Register the 'init' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerInitCommand(program) {
  program
    .command('init')
    .description('Initialize developer cryptographic identity and register with Vault Server')
    .action(() => {
      logger.notImplemented('init', 3);
    });
}
