#!/usr/bin/env node

/**
 * Main CLI entry point and wiring for the EnvGuard CLI application.
 *
 * This file is part of Phase 1 (Project Scaffolding).
 * Responsible exclusively for Node version validation, reading package metadata,
 * setting up the Commander program, adding global options, and registering command modules.
 * Later phases will integrate real command handlers, crypto modules, and server communication.
 */

import fs from 'node:fs';
import { Command } from 'commander';
import * as logger from '../src/client/logger.js';
import { registerInitCommand } from '../src/commands/init.js';
import { registerProjectCommand } from '../src/commands/project.js';
import { registerSetCommand } from '../src/commands/set.js';
import { registerRunCommand } from '../src/commands/run.js';
import { registerGrantCommand } from '../src/commands/grant.js';
import { registerRevokeCommand } from '../src/commands/revoke.js';

/**
 * Execute the EnvGuard CLI program initialization and argument parsing.
 */
function main() {
  const nodeVersionParts = process.versions.node.split('.');
  const nodeMajorVersion = parseInt(nodeVersionParts[0], 10);

  if (nodeMajorVersion < 22) {
    logger.error(`Node.js version 22 or higher is required (current version is v${process.versions.node})`);
    process.exitCode = 1;
    return;
  }

  const packageJsonUrl = new URL('../package.json', import.meta.url);
  const packageJsonContent = fs.readFileSync(packageJsonUrl, 'utf8');
  const packageInfo = JSON.parse(packageJsonContent);

  const program = new Command();
  program
    .name('envguard')
    .description(packageInfo.description)
    .version(packageInfo.version)
    .showHelpAfterError();

  program.option('--server <url>', 'Vault Server URL');
  program.option('--ca-cert <path>', 'Path to a CA certificate for a self-signed demo server');

  registerInitCommand(program);
  registerProjectCommand(program);
  registerSetCommand(program);
  registerRunCommand(program);
  registerGrantCommand(program);
  registerRevokeCommand(program);

  program.parse(process.argv);
}

main();
