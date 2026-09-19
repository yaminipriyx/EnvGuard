/**
 * Command registration and handler for 'envguard grant'.
 *
 * This file is part of Phase 7 (Access Management: Grant & Revoke).
 * Grants vault access to a new or existing user:
 * 1. Validates username and target role (admin, member, readonly). Reject owner.
 * 2. Fetches target user's registered public key and fingerprint from server.
 * 3. Optionally confirms against --fingerprint <fp> if provided.
 * 4. Unwraps current DEK locally using caller's private key (master passphrase prompt).
 * 5. Re-wraps existing DEK for target user with AAD ${vaultId}:${currentDekVersion}:${targetUsername}.
 *    (Grant does NOT rotate DEK; dekVersion remains unchanged).
 * 6. Submits POST /api/v1/vault/:vaultId/members with expectedVersion.
 * 7. Server independently authorizes caller (owner/admin) and atomically commits update.
 *
 * Security Invariants:
 * - The server is authoritative for ACL permissions.
 * - Raw DEKs, private keys, and passphrases are NEVER sent to the server.
 * - Sensitive DEK buffer is zeroized via buffer.fill(0) after wrapping.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import { Option } from 'commander';
import * as logger from '../client/logger.js';
import * as keystore from '../client/keystore.js';
import * as api from '../client/api.js';
import * as envelope from '../crypto/envelope.js';
import { isValidUsername } from '../server/storage.js';
import { promptInput } from './init.js';

/**
 * Validate the grant role argument.
 *
 * @param {string} role - Candidate role name.
 */
export function validateGrantRole(role) {
  if (typeof role !== 'string' || role.trim().length === 0) {
    throw new Error('Role must be a non-empty string');
  }

  const normalized = role.trim();
  if (normalized === 'owner') {
    throw new Error('Cannot grant owner role: vault owner is immutable');
  }

  if (normalized !== 'admin' && normalized !== 'member' && normalized !== 'readonly') {
    throw new Error(`Invalid role "${role}": must be admin, member, or readonly`);
  }
}

/**
 * Programmatic execution of the 'grant' operation.
 *
 * @param {object} params - Execution parameters.
 * @param {string} params.username - Target username to grant access.
 * @param {string} [params.role] - Role to assign ('admin', 'member', 'readonly', default 'member').
 * @param {string} [params.fingerprint] - Optional expected recipient public key fingerprint.
 * @param {string} [params.env] - Target environment name (default 'development').
 * @param {string} [params.serverUrl] - Explicit server URL override.
 * @param {string} [params.caCertPath] - Custom CA certificate path for TLS.
 * @param {string} [params.keystoreDir] - Keystore directory override.
 * @param {object} [params.projectConfig] - Project config override for testing.
 * @param {string} [params.passphrase] - Master passphrase override for testing.
 * @param {import('node:stream').Readable} [params.inStream] - Input stream for prompt.
 * @param {import('node:stream').Writable} [params.outStream] - Output stream for prompt.
 * @returns {Promise<{ vaultId: string, username: string, role: string, vaultVersion: number, dekVersion: number }>}
 */
export async function executeGrant(params) {
  if (typeof params !== 'object' || params === null) {
    throw new TypeError('Invalid params: must be a non-null object');
  }

  const targetUsername = params.username;
  if (typeof targetUsername !== 'string' || !isValidUsername(targetUsername)) {
    throw new Error(`Invalid target username "${targetUsername}": must match ^[A-Za-z0-9_.-]{3,32}$`);
  }

  let targetRole = 'member';
  if (typeof params.role === 'string' && params.role.trim().length > 0) {
    targetRole = params.role.trim();
  }
  validateGrantRole(targetRole);

  // 1. Authenticate using Phase 4 local credentials
  const credentials = await keystore.loadCredentials(params.keystoreDir);

  // 2. Resolve project configuration (.envguard.json)
  let resolvedConfig = params.projectConfig;
  if (!resolvedConfig) {
    const found = api.findProjectConfig();
    if (!found) {
      throw new Error('Project configuration not found (.envguard.json). Run in a configured project root.');
    }
    resolvedConfig = found.config;
  }

  if (typeof resolvedConfig.project !== 'string' || resolvedConfig.project.trim().length === 0) {
    throw new Error('Invalid project configuration: missing "project" name in .envguard.json');
  }

  // 3. Resolve target environment: CLI --env -> ENVGUARD_ENV -> 'development'
  let activeEnv = 'development';
  if (typeof params.env === 'string' && params.env.trim().length > 0) {
    activeEnv = params.env.trim();
  } else if (typeof process.env.ENVGUARD_ENV === 'string' && process.env.ENVGUARD_ENV.trim().length > 0) {
    activeEnv = process.env.ENVGUARD_ENV.trim();
  }

  // 4. Resolve configured vault ID
  let configuredVaultId = null;
  if (resolvedConfig.environments && typeof resolvedConfig.environments[activeEnv] === 'string') {
    configuredVaultId = resolvedConfig.environments[activeEnv].trim();
  }

  if (!configuredVaultId || configuredVaultId.length === 0) {
    throw new Error(`No vault configured for environment "${activeEnv}" in .envguard.json`);
  }

  // 5. Resolve Vault Server URL & Transport
  const targetServerUrl = api.resolveServerUrl(params.serverUrl, resolvedConfig);

  const transportOptions = {};
  if (params.caCertPath) {
    transportOptions.caCertPath = params.caCertPath;
  }

  // 6. Fetch current encrypted vault state
  const vaultState = await api.getVaultSecrets(targetServerUrl, configuredVaultId, credentials, transportOptions);

  if (typeof vaultState.wrappedDeks !== 'object' || vaultState.wrappedDeks === null) {
    throw new Error(`Corrupted vault response: missing wrappedDeks for vault "${configuredVaultId}"`);
  }

  const callerWrappedDek = vaultState.wrappedDeks[credentials.username];
  if (!callerWrappedDek) {
    throw new Error(`Access denied: caller "${credentials.username}" is not an authorized vault member`);
  }

  // 7. Fetch target user's registered public identity from server
  let targetUserRecord;
  try {
    targetUserRecord = await api.getUser(targetServerUrl, targetUsername, credentials, transportOptions);
  } catch (err) {
    if (err.statusCode === 404) {
      throw new Error(`Target user "${targetUsername}" does not exist on Vault Server`);
    }
    throw err;
  }

  if (!targetUserRecord || targetUserRecord.status !== 'active') {
    throw new Error(`Target user "${targetUsername}" is inactive or invalid`);
  }

  // Optional fingerprint verification
  if (typeof params.fingerprint === 'string' && params.fingerprint.trim().length > 0) {
    const expectedFp = params.fingerprint.trim();
    if (targetUserRecord.publicKeyFingerprint !== expectedFp) {
      throw new Error(`Public key fingerprint mismatch for user "${targetUsername}": expected ${expectedFp}, server has ${targetUserRecord.publicKeyFingerprint}`);
    }
  }

  // 8. Prompt caller for master passphrase to decrypt local private key
  let masterPassphrase = params.passphrase;
  if (typeof masterPassphrase !== 'string' || masterPassphrase.length === 0) {
    masterPassphrase = await promptInput('Master Passphrase: ', true, params.inStream, params.outStream);
  }

  if (typeof masterPassphrase !== 'string' || masterPassphrase.length < 12) {
    throw new Error('Master passphrase must be at least 12 characters');
  }

  // 9. Unlock local private key
  const keyEnvelope = await keystore.loadKeyEnvelope(params.keystoreDir);
  let privateKeyJwk;
  try {
    privateKeyJwk = envelope.openPrivateKeyEnvelope(keyEnvelope, masterPassphrase);
  } catch (err) {
    throw new Error('Master passphrase authentication failed');
  }

  // 10. Unwrap current DEK locally and wrap for target user
  // Grant property: DEK is NOT rotated (dekVersion remains unchanged)
  const currentDekVersion = vaultState.dekVersion;
  let currentDek = null;
  let targetWrappedDek = null;

  try {
    currentDek = envelope.openWrappedDekEnvelope(
      callerWrappedDek,
      privateKeyJwk,
      configuredVaultId,
      currentDekVersion,
      credentials.username
    );

    targetWrappedDek = envelope.createWrappedDekEnvelope(
      currentDek,
      targetUserRecord.publicKey,
      configuredVaultId,
      currentDekVersion,
      targetUsername
    );
  } catch (err) {
    throw new Error(`Failed to unwrap and re-wrap DEK for user "${targetUsername}": ${err.message}`);
  } finally {
    if (currentDek) {
      currentDek.fill(0);
    }
  }

  // 11. Submit grant request to server
  const grantPayload = {
    expectedVersion: vaultState.vaultVersion,
    username: targetUsername,
    role: targetRole,
    wrappedDek: targetWrappedDek,
    publicKeyFingerprint: targetUserRecord.publicKeyFingerprint
  };

  try {
    const updateResult = await api.grantVaultMember(
      targetServerUrl,
      configuredVaultId,
      grantPayload,
      credentials,
      transportOptions
    );

    return {
      vaultId: configuredVaultId,
      username: targetUsername,
      role: targetRole,
      vaultVersion: updateResult.vaultVersion,
      dekVersion: updateResult.dekVersion
    };
  } catch (err) {
    if (err.statusCode === 409) {
      throw new Error(`Optimistic concurrency conflict: vault "${configuredVaultId}" was modified concurrently. Grant aborted.`);
    }
    throw err;
  }
}

/**
 * Handle execution of the 'envguard grant' CLI command.
 *
 * @param {string} username - Target username.
 * @param {object} cmdOptions - Command options (--role, --fingerprint, --env).
 * @param {import('commander').Command} command - The Commander command instance.
 */
export async function grantCommandAction(username, cmdOptions, command) {
  try {
    let globalOpts = {};
    if (command && typeof command.optsWithGlobals === 'function') {
      globalOpts = command.optsWithGlobals();
    }

    let role = 'member';
    if (cmdOptions && typeof cmdOptions.role === 'string') {
      role = cmdOptions.role;
    }

    let fingerprint = null;
    if (cmdOptions && typeof cmdOptions.fingerprint === 'string') {
      fingerprint = cmdOptions.fingerprint;
    }

    let env = null;
    if (cmdOptions && typeof cmdOptions.env === 'string') {
      env = cmdOptions.env;
    }

    let serverUrl = null;
    if (globalOpts.server) {
      serverUrl = globalOpts.server;
    }

    let caCertPath = null;
    if (globalOpts.caCert) {
      caCertPath = globalOpts.caCert;
    }

    const result = await executeGrant({
      username: username,
      role: role,
      fingerprint: fingerprint,
      env: env,
      serverUrl: serverUrl,
      caCertPath: caCertPath
    });

    logger.success(`Granted ${result.role} access to "${result.username}" in vault "${result.vaultId}" (version ${result.vaultVersion})`);
  } catch (err) {
    logger.error(err.message);
    process.exitCode = 1;
  }
}

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
    .action(async (username, options, command) => {
      await grantCommandAction(username, options, command);
    });
}
