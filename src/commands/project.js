/**
 * Command registration and handler for 'envguard project'.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * Provides the 'project' parent command and 'project init' subcommand stub.
 * Phase 4 (Project Vault Configuration) will replace this stub with .envguard.json
 * generation and environment vault initialization.
 */

import * as logger from '../client/logger.js';

/**
 * Register the 'project' command and subcommands with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerProjectCommand(program) {
  const project = program
    .command('project')
    .description('Manage project vault configurations');

  project
    .command('init <name>')
    .description('Initialize a new project configuration')
    .option('--envs <list>', 'Comma-separated deployment environments', 'development,staging,production')
    .action((name, options) => {
      logger.notImplemented('project init', 4);
    });
}
