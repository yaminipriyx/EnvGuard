/**
 * Command registration and handler for 'envguard grant'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * The command handler is currently a stub that records Phase 1 non-implementation.
 * Phase 5 (Access Management: Grant & Revoke) will replace this stub with
 * public key fetching, fingerprint verification, and DEK re-wrapping.
 */

import { Option } from 'commander';
import * as logger from '../client/logger.js';

/**
 * Register the 'grant' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerGrantCommand(program) {
  const roleOption = new Option('--role <role>', 'Role assigned to the user');
  roleOption.choices(['admin', 'member', 'readonly']);
  roleOption.default('member');

  program
    .command('grant <username>')
    .description('Grant vault access to a user')
    .addOption(roleOption)
    .option('--fingerprint <fp>', 'Expected recipient public key fingerprint')
    .option('--env <name>', 'Target environment name')
    .action((username, options) => {
      logger.notImplemented('grant', 5);
    });
}
