/**
 * Command registration and handler for 'envguard revoke'.
 *
 * This file is part of Phase 7 (Access Management: Grant & Revoke).
 * Revokes vault access from an existing member and performs mandatory DEK rotation:
 * 1. Validates target username (must not be caller, must not be owner).
 * 2. Loads local credentials and resolves project/environment vault ID.
 * 3. Fetches vault state (including authoritative members and wrappedDeks).
 * 4. Authorizes caller: caller must be member with 'owner' or 'admin' role.
 *    - Owner can revoke any non-owner member.
 *    - Admin can revoke member or readonly (cannot revoke owner or another admin).
 * 5. Identifies authoritative remaining members:
 *    remainingUsernames = Object.keys(vaultState.members).filter(u => u !== targetUsername).
 * 6. Decrypts current secrets using caller's unlocked private key and old DEK.
 * 7. Zeroizes old DEK.
 * 8. Generates fresh random 32-byte DEK (DEK_new), dekVersion = oldDekVersion + 1.
 * 9. Re-encrypts secret map using DEK_new with AAD ${vaultId}:${newDekVersion}.
 * 10. Re-wraps DEK_new for ALL remaining members:
 *     - If member is caller, uses caller's local public key.
 *     - If member is another user, fetches registered public key via GET /api/v1/users/:username.
 *     - AAD for each member: ${vaultId}:${newDekVersion}:${memberName}.
 * 11. Zeroizes DEK_new in finally block.
 * 12. Validates client-side before submission:
 *     - targetUsername is NOT in newWrappedDeks.
 *     - keys(newWrappedDeks) exactly equals remaining authorized members.
 *     - newBlob.aad === ${vaultId}:${newDekVersion}.
 * 13. Submits DELETE /api/v1/vault/:vaultId/members/:username with expectedVersion, newBlob, newWrappedDeks.
 * 14. Server atomically updates storage (mutateVault) and returns new vaultVersion and dekVersion.
 *
 * Security Invariants:
 * - Server is authoritative for ACL permissions.
 * - Raw DEKs, private keys, and plaintexts are NEVER sent to the server.
 * - Sensitive buffers are zeroized immediately after use.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import crypto from 'node:crypto';
import * as logger from '../client/logger.js';
import * as keystore from '../client/keystore.js';
import * as api from '../client/api.js';
import * as envelope from '../crypto/envelope.js';
import { isValidUsername } from '../server/storage.js';
import { promptInput } from './init.js';

/**
 * Programmatic execution of the 'revoke' operation.
 *
 * @param {object} params - Execution parameters.
 * @param {string} params.username - Target username to revoke access from.
 * @param {string} [params.env] - Target environment name (default 'development').
 * @param {string} [params.serverUrl] - Explicit server URL override.
 * @param {string} [params.caCertPath] - Custom CA certificate path for TLS.
 * @param {string} [params.keystoreDir] - Keystore directory override.
 * @param {object} [params.projectConfig] - Project config override for testing.
 * @param {string} [params.passphrase] - Master passphrase override for testing.
 * @param {import('node:stream').Readable} [params.inStream] - Input stream for prompt.
 * @param {import('node:stream').Writable} [params.outStream] - Output stream for prompt.
 * @returns {Promise<{ vaultId: string, username: string, vaultVersion: number, dekVersion: number, remainingMembers: string[] }>}
 */
export async function executeRevoke(params) {
  if (typeof params !== 'object' || params === null) {
    throw new TypeError('Invalid params: must be a non-null object');
  }

  const targetUsername = params.username;
  if (typeof targetUsername !== 'string' || !isValidUsername(targetUsername)) {
    throw new Error(`Invalid target username "${targetUsername}": must match ^[A-Za-z0-9_.-]{3,32}$`);
  }

  // 1. Authenticate using Phase 4 local credentials
  const credentials = await keystore.loadCredentials(params.keystoreDir);

  if (targetUsername === credentials.username) {
    throw new Error('Cannot revoke yourself: vault members cannot revoke their own access');
  }

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

  if (typeof vaultState.members !== 'object' || vaultState.members === null) {
    throw new Error(`Corrupted vault response: missing members map for vault "${configuredVaultId}"`);
  }

  if (typeof vaultState.wrappedDeks !== 'object' || vaultState.wrappedDeks === null) {
    throw new Error(`Corrupted vault response: missing wrappedDeks for vault "${configuredVaultId}"`);
  }

  // 7. Authorize caller client-side
  if (!Object.prototype.hasOwnProperty.call(vaultState.members, credentials.username)) {
    throw new Error(`Access denied: caller "${credentials.username}" is not an authorized vault member`);
  }

  const callerRole = vaultState.members[credentials.username];
  if (callerRole !== 'owner' && callerRole !== 'admin') {
    throw new Error('Access denied: only owner or admin can revoke members');
  }

  // 8. Validate target membership client-side
  if (!Object.prototype.hasOwnProperty.call(vaultState.members, targetUsername)) {
    throw new Error(`Target user "${targetUsername}" is not a member of vault "${configuredVaultId}"`);
  }

  const targetRole = vaultState.members[targetUsername];
  if (targetRole === 'owner') {
    throw new Error('Cannot revoke owner: vault owner is immutable');
  }

  if (callerRole === 'admin') {
    if (targetRole === 'admin' || targetRole === 'owner') {
      throw new Error('Admin role violation: admins cannot revoke another admin or owner');
    }
  }

  // 9. Determine authoritative remaining members
  const remainingUsernames = Object.keys(vaultState.members).filter(function(uname) {
    return uname !== targetUsername;
  });

  const callerWrappedDek = vaultState.wrappedDeks[credentials.username];
  if (!callerWrappedDek) {
    throw new Error(`Access denied: missing wrapped DEK for caller "${credentials.username}"`);
  }

  // 10. Prompt caller for master passphrase to decrypt local private key
  let masterPassphrase = params.passphrase;
  if (typeof masterPassphrase !== 'string' || masterPassphrase.length === 0) {
    masterPassphrase = await promptInput('Master Passphrase: ', true, params.inStream, params.outStream);
  }

  if (typeof masterPassphrase !== 'string' || masterPassphrase.length < 12) {
    throw new Error('Master passphrase must be at least 12 characters');
  }

  // 11. Unlock local private key
  const keyEnvelope = await keystore.loadKeyEnvelope(params.keystoreDir);
  let privateKeyJwk;
  try {
    privateKeyJwk = envelope.openPrivateKeyEnvelope(keyEnvelope, masterPassphrase);
  } catch (err) {
    throw new Error('Master passphrase authentication failed');
  }

  // 12. Unwrap current DEK locally and decrypt existing secrets
  const oldDekVersion = vaultState.dekVersion;
  let oldDek = null;
  let decryptedSecretsPlaintext = null;
  let secretsMap = {};

  try {
    oldDek = envelope.openWrappedDekEnvelope(
      callerWrappedDek,
      privateKeyJwk,
      configuredVaultId,
      oldDekVersion,
      credentials.username
    );

    decryptedSecretsPlaintext = envelope.openSecretEnvelope(
      vaultState.blob,
      oldDek,
      configuredVaultId,
      oldDekVersion
    );

    secretsMap = JSON.parse(decryptedSecretsPlaintext.toString('utf8'));
  } catch (err) {
    throw new Error(`Failed to decrypt current secrets: ${err.message}`);
  } finally {
    if (oldDek) {
      oldDek.fill(0);
    }
    if (decryptedSecretsPlaintext) {
      decryptedSecretsPlaintext.fill(0);
    }
  }

  // 13. Mandatory DEK Rotation: generate fresh 32-byte DEK
  const newDek = crypto.randomBytes(32);
  const newDekVersion = oldDekVersion + 1;

  let newBlob = null;
  const newWrappedDeks = {};

  try {
    // Re-encrypt secret map with new DEK and AAD = `${vaultId}:${newDekVersion}`
    const canonicalJson = JSON.stringify(secretsMap, Object.keys(secretsMap).sort());
    const plaintextBuffer = Buffer.from(canonicalJson, 'utf8');

    try {
      newBlob = envelope.createSecretEnvelope(
        plaintextBuffer,
        newDek,
        configuredVaultId,
        newDekVersion
      );
    } finally {
      plaintextBuffer.fill(0);
    }

    // Re-wrap new DEK for ALL remaining authorized members
    for (let i = 0; i < remainingUsernames.length; i = i + 1) {
      const memberName = remainingUsernames[i];
      let memberPublicKey = null;

      if (memberName === credentials.username) {
        memberPublicKey = keyEnvelope.publicKey;
      } else {
        let memberRecord = null;
        try {
          memberRecord = await api.getUser(targetServerUrl, memberName, credentials, transportOptions);
        } catch (fetchErr) {
          throw new Error(`Failed to retrieve public identity for remaining member "${memberName}": ${fetchErr.message}`);
        }

        if (!memberRecord || memberRecord.status !== 'active') {
          throw new Error(`Remaining member "${memberName}" is inactive or invalid`);
        }
        memberPublicKey = memberRecord.publicKey;
      }

      const memberWrappedDek = envelope.createWrappedDekEnvelope(
        newDek,
        memberPublicKey,
        configuredVaultId,
        newDekVersion,
        memberName
      );

      newWrappedDeks[memberName] = memberWrappedDek;
    }
  } finally {
    if (newDek) {
      newDek.fill(0);
    }
  }

  // 14. Client-side pre-submission validation
  if (Object.prototype.hasOwnProperty.call(newWrappedDeks, targetUsername)) {
    throw new Error('Revoked user cannot receive a wrapped DEK');
  }

  const remainingSorted = remainingUsernames.slice().sort();
  const wrappedSorted = Object.keys(newWrappedDeks).sort();
  if (remainingSorted.length !== wrappedSorted.length) {
    throw new Error('New wrapped DEKs count does not match remaining members count');
  }

  for (let i = 0; i < remainingSorted.length; i = i + 1) {
    if (remainingSorted[i] !== wrappedSorted[i]) {
      throw new Error(`Wrapped DEK mismatch for remaining member "${remainingSorted[i]}"`);
    }
  }

  const expectedBlobAad = `${configuredVaultId}:${newDekVersion}`;
  if (newBlob.aad !== expectedBlobAad) {
    throw new Error('New secret blob AAD mismatch');
  }

  for (let i = 0; i < remainingSorted.length; i = i + 1) {
    const memberName = remainingSorted[i];
    const expectedMemberAad = `${configuredVaultId}:${newDekVersion}:${memberName}`;
    if (newWrappedDeks[memberName].aad !== expectedMemberAad) {
      throw new Error(`Wrapped DEK AAD mismatch for member "${memberName}"`);
    }
  }

  // 15. Submit revocation request to Vault Server
  const revokePayload = {
    expectedVersion: vaultState.vaultVersion,
    newBlob: newBlob,
    newWrappedDeks: newWrappedDeks
  };

  try {
    const updateResult = await api.revokeVaultMember(
      targetServerUrl,
      configuredVaultId,
      targetUsername,
      revokePayload,
      credentials,
      transportOptions
    );

    return {
      vaultId: configuredVaultId,
      username: targetUsername,
      vaultVersion: updateResult.vaultVersion,
      dekVersion: updateResult.dekVersion,
      remainingMembers: remainingUsernames
    };
  } catch (err) {
    if (err.statusCode === 409) {
      throw new Error(`Optimistic concurrency conflict: vault "${configuredVaultId}" was modified concurrently. Revoke aborted.`);
    }
    throw err;
  }
}

/**
 * Handle execution of the 'envguard revoke' CLI command.
 *
 * @param {string} username - Target username to revoke.
 * @param {object} cmdOptions - Command options (--env).
 * @param {import('commander').Command} command - The Commander command instance.
 */
export async function revokeCommandAction(username, cmdOptions, command) {
  try {
    let globalOpts = {};
    if (command && typeof command.optsWithGlobals === 'function') {
      globalOpts = command.optsWithGlobals();
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

    const result = await executeRevoke({
      username: username,
      env: env,
      serverUrl: serverUrl,
      caCertPath: caCertPath
    });

    logger.success(`Revoked access for "${result.username}" from vault "${result.vaultId}" (vault version ${result.vaultVersion}, DEK version ${result.dekVersion})`);
  } catch (err) {
    logger.error(err.message);
    process.exitCode = 1;
  }
}

/**
 * Register the 'revoke' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerRevokeCommand(program) {
  program
    .command('revoke <username>')
    .description('Revoke vault access from a user and rotate the Data Encryption Key')
    .option('--env <name>', 'Target environment name')
    .action(async (username, options, command) => {
      await revokeCommandAction(username, options, command);
    });
}
