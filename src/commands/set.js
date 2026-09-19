/**
 * Command registration and handler for 'envguard set'.
 *
 * This file is part of Phase 5 (Secret Provisioning & DEK Encryption).
 * Implements local zero-knowledge secret encryption and vault storage:
 * 1. Supports KEY=VALUE, interactive KEY prompt (hidden input), and --stdin input modes.
 * 2. Enforces variable name format: ^[A-Za-z_][A-Za-z0-9_]*$.
 * 3. Resolves project and environment from .envguard.json and CLI flags.
 * 4. For initial vault creation:
 *    - Generates fresh 32-byte DEK in memory.
 *    - Sets vaultVersion = 1, dekVersion = 1.
 *    - Encrypts secret map locally via AES-256-GCM with AAD ${vaultId}:1.
 *    - Wraps DEK for caller with AAD ${vaultId}:1:${username}.
 *    - Calls POST /api/v1/vault and atomically updates .envguard.json with new vaultId.
 * 5. For existing vaults:
 *    - Fetches encrypted vault state via GET /api/v1/vault/:vaultId/secrets.
 *    - Unwraps existing DEK using caller's private key (master passphrase prompt).
 *    - Reuses existing DEK without rotation (dekVersion unchanged).
 *    - Decrypts existing secrets, merges updates, re-encrypts with active dekVersion.
 *    - Calls PUT /api/v1/vault/:vaultId/secrets with expectedVersion.
 *    - Aborts safely on 409 Conflict without overwriting newer data.
 *
 * Security Contract:
 * - Plaintext secret values and raw DEKs are NEVER sent to or stored on the server.
 * - Sensitive buffers are zeroized after encryption/decryption.
 * - Secret values are NEVER logged, printed, or included in error messages.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import crypto from 'node:crypto';
import * as logger from '../client/logger.js';
import * as keystore from '../client/keystore.js';
import * as api from '../client/api.js';
import * as envelope from '../crypto/envelope.js';
import { promptInput } from './init.js';

const VALID_KEY_REGEX = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Validate that a variable name adheres to the required POSIX/EnvGuard identifier format.
 *
 * @param {string} key - Variable name string to validate.
 */
export function validateKeyName(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new Error('Invalid secret key name: must be a non-empty string');
  }
  if (!VALID_KEY_REGEX.test(key)) {
    throw new Error(`Invalid secret key name "${key}": must match ^[A-Za-z_][A-Za-z0-9_]*$`);
  }
}

/**
 * Parse lines from standard input text in standard KEY=VALUE format.
 *
 * @param {string} text - Raw input text.
 * @returns {Record<string, string>} Map of validated key-value pairs.
 */
export function parseStdinSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('No secrets provided on stdin');
  }

  const lines = text.split(/\r?\n/);
  const result = {};
  let count = 0;

  for (let i = 0; i < lines.length; i = i + 1) {
    const rawLine = lines[i].trim();
    if (rawLine.length === 0 || rawLine.startsWith('#')) {
      continue;
    }

    const eqIndex = rawLine.indexOf('=');
    if (eqIndex === -1) {
      throw new Error(`Invalid stdin format on line ${i + 1}: expected KEY=VALUE`);
    }

    const key = rawLine.substring(0, eqIndex).trim();
    const value = rawLine.substring(eqIndex + 1);

    validateKeyName(key);
    if (value.length === 0) {
      throw new Error(`Secret value for key "${key}" cannot be empty`);
    }

    result[key] = value;
    count = count + 1;
  }

  if (count === 0) {
    throw new Error('No valid secrets found on stdin');
  }

  return result;
}

/**
 * Read all text from a readable stream until completion.
 *
 * @param {import('node:stream').Readable} stream - Input stream to read from.
 * @returns {Promise<string>} Accumulated UTF-8 text.
 */
function readStreamText(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => {
      chunks.push(chunk);
    });
    stream.on('end', () => {
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    stream.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Execute programmatic secret setting (new vault creation or existing vault update).
 *
 * @param {object} params - Execution parameters.
 * @param {Record<string, string>} params.secretsToSet - Map of variable name -> secret value.
 * @param {string} [params.env] - Target environment name (default 'development').
 * @param {string} [params.serverUrl] - Explicit server URL override.
 * @param {string} [params.caCertPath] - Custom CA certificate path for TLS.
 * @param {string} [params.keystoreDir] - Keystore directory override.
 * @param {object} [params.projectConfig] - Project config override for testing.
 * @param {string} [params.projectConfigPath] - Project config path override for testing.
 * @param {string} [params.passphrase] - Master passphrase override for testing.
 * @param {import('node:stream').Readable} [params.inStream] - Input stream for prompt.
 * @param {import('node:stream').Writable} [params.outStream] - Output stream for prompt.
 * @returns {Promise<{ vaultId: string, vaultVersion: number, dekVersion: number, keysSet: string[], isNewVault: boolean }>}
 */
export async function executeSet(params) {
  if (typeof params !== 'object' || params === null) {
    throw new TypeError('Invalid params: must be a non-null object');
  }

  const secretsToSet = params.secretsToSet;
  if (typeof secretsToSet !== 'object' || secretsToSet === null) {
    throw new TypeError('Invalid secretsToSet: must be a non-null object');
  }

  const keys = Object.keys(secretsToSet);
  if (keys.length === 0) {
    throw new Error('No secret variables provided to set');
  }

  for (let i = 0; i < keys.length; i = i + 1) {
    const k = keys[i];
    validateKeyName(k);
    const v = secretsToSet[k];
    if (typeof v !== 'string' || v.length === 0) {
      throw new Error(`Secret value for "${k}" cannot be empty`);
    }
  }

  // 1. Authenticate using Phase 4 local credentials
  const credentials = await keystore.loadCredentials(params.keystoreDir);

  // 2. Resolve project configuration (.envguard.json)
  let resolvedConfig = params.projectConfig;
  let resolvedConfigPath = params.projectConfigPath;

  if (!resolvedConfig || !resolvedConfigPath) {
    const found = api.findProjectConfig();
    if (!found) {
      throw new Error('Project configuration not found (.envguard.json). Run in a configured project root.');
    }
    resolvedConfig = found.config;
    resolvedConfigPath = found.filePath;
  }

  if (typeof resolvedConfig.project !== 'string' || resolvedConfig.project.trim().length === 0) {
    throw new Error('Invalid project configuration: missing "project" name in .envguard.json');
  }
  const projectName = resolvedConfig.project.trim();

  // 3. Resolve target environment: CLI --env -> ENVGUARD_ENV -> 'development'
  let activeEnv = 'development';
  if (typeof params.env === 'string' && params.env.trim().length > 0) {
    activeEnv = params.env.trim();
  } else if (typeof process.env.ENVGUARD_ENV === 'string' && process.env.ENVGUARD_ENV.trim().length > 0) {
    activeEnv = process.env.ENVGUARD_ENV.trim();
  }

  // 4. Resolve Vault Server URL
  const targetServerUrl = api.resolveServerUrl(params.serverUrl, resolvedConfig);

  const transportOptions = {};
  if (params.caCertPath) {
    transportOptions.caCertPath = params.caCertPath;
  }

  // 5. Determine whether vault exists for this environment
  let configuredVaultId = null;
  if (resolvedConfig.environments && typeof resolvedConfig.environments[activeEnv] === 'string') {
    configuredVaultId = resolvedConfig.environments[activeEnv].trim();
  }

  let vaultState = null;
  if (configuredVaultId && configuredVaultId.length > 0) {
    try {
      vaultState = await api.getVaultSecrets(targetServerUrl, configuredVaultId, credentials, transportOptions);
    } catch (err) {
      if (err.statusCode === 404) {
        // Vault ID is recorded locally, but not found on server
        vaultState = null;
      } else {
        throw err;
      }
    }
  }

  // =========================================================================
  // Case A: Initial Vault Creation
  // =========================================================================
  if (vaultState === null) {
    let vaultId = configuredVaultId;
    if (!vaultId || vaultId.length === 0) {
      const randomSuffix = crypto.randomBytes(8).toString('hex');
      vaultId = `${projectName}-${activeEnv}-${randomSuffix}`;
    }

    const keyEnvelope = await keystore.loadKeyEnvelope(params.keystoreDir);
    const callerPublicKey = keyEnvelope.publicKey;

    // Generate fresh 32-byte DEK
    const dek = crypto.randomBytes(32);

    // Encrypt initial secret map with AAD = `${vaultId}:1`
    const secretsMap = Object.assign({}, secretsToSet);
    const serialized = Buffer.from(JSON.stringify(secretsMap), 'utf8');

    let blob;
    try {
      blob = envelope.createSecretEnvelope(serialized, dek, vaultId, 1);
    } finally {
      serialized.fill(0);
    }

    // Wrap DEK for owner with AAD = `${vaultId}:1:${callerUsername}`
    let wrappedDek;
    try {
      wrappedDek = envelope.createWrappedDekEnvelope(dek, callerPublicKey, vaultId, 1, credentials.username);
    } finally {
      dek.fill(0);
    }

    // Submit initial vault creation to server
    const vaultPayload = {
      vaultId: vaultId,
      blob: blob,
      wrappedDek: wrappedDek
    };

    await api.createVault(targetServerUrl, vaultPayload, credentials, transportOptions);

    // Atomically persist newly created vault ID into .envguard.json
    if (!resolvedConfig.environments) {
      resolvedConfig.environments = {};
    }
    resolvedConfig.environments[activeEnv] = vaultId;
    await api.saveProjectConfig(resolvedConfigPath, resolvedConfig);

    return {
      vaultId: vaultId,
      vaultVersion: 1,
      dekVersion: 1,
      keysSet: keys,
      isNewVault: true
    };
  }

  // =========================================================================
  // Case B: Existing Vault Update
  // =========================================================================
  const activeVaultId = configuredVaultId;
  const currentVaultVersion = vaultState.vaultVersion;
  const currentDekVersion = vaultState.dekVersion;

  if (typeof vaultState.wrappedDeks !== 'object' || vaultState.wrappedDeks === null) {
    throw new Error(`Corrupted vault response: missing wrappedDeks for vault "${activeVaultId}"`);
  }

  const callerWrappedDek = vaultState.wrappedDeks[credentials.username];
  if (!callerWrappedDek) {
    throw new Error(`Access denied: caller "${credentials.username}" is not an authorized vault member with a wrapped DEK in "${activeVaultId}"`);
  }

  // Obtain master passphrase to decrypt local private key
  let masterPassphrase = params.passphrase;
  if (typeof masterPassphrase !== 'string' || masterPassphrase.length === 0) {
    masterPassphrase = await promptInput('Master Passphrase: ', true, params.inStream, params.outStream);
  }
  if (typeof masterPassphrase !== 'string' || masterPassphrase.length === 0) {
    throw new Error('Master passphrase is required to unwrap vault secrets');
  }

  const keyEnvelope = await keystore.loadKeyEnvelope(params.keystoreDir);
  let privateKeyJwk;
  try {
    privateKeyJwk = envelope.openPrivateKeyEnvelope(keyEnvelope, masterPassphrase);
  } catch (err) {
    throw new Error('Master passphrase authentication failed');
  }

  // Unwrap existing DEK using caller's private key
  let existingDek;
  try {
    existingDek = envelope.openWrappedDekEnvelope(
      callerWrappedDek,
      privateKeyJwk,
      activeVaultId,
      currentDekVersion,
      credentials.username
    );
  } catch (err) {
    throw new Error('Failed to unwrap DEK: wrapped key authentication failed or corrupted envelope');
  }

  // Decrypt existing secrets blob
  let existingSecrets = {};
  let decryptedPlaintext;
  try {
    decryptedPlaintext = envelope.openSecretEnvelope(vaultState.blob, existingDek, activeVaultId, currentDekVersion);
    if (decryptedPlaintext.length > 0) {
      existingSecrets = JSON.parse(decryptedPlaintext.toString('utf8'));
    }
  } catch (err) {
    if (existingDek) {
      existingDek.fill(0);
    }
    throw new Error('Failed to decrypt existing vault secrets: ciphertext authentication failed or corrupted');
  } finally {
    if (decryptedPlaintext) {
      decryptedPlaintext.fill(0);
    }
  }

  // Merge updates into secret map
  for (let i = 0; i < keys.length; i = i + 1) {
    const k = keys[i];
    existingSecrets[k] = secretsToSet[k];
  }

  // Re-encrypt updated secrets with existing DEK and current dekVersion (dekVersion unchanged)
  const updatedSerialized = Buffer.from(JSON.stringify(existingSecrets), 'utf8');
  let newBlob;
  try {
    newBlob = envelope.createSecretEnvelope(updatedSerialized, existingDek, activeVaultId, currentDekVersion);
  } finally {
    updatedSerialized.fill(0);
    existingDek.fill(0);
  }

  // Submit update with optimistic concurrency expectedVersion
  const updatePayload = {
    expectedVersion: currentVaultVersion,
    blob: newBlob
  };

  try {
    const updateResult = await api.updateVaultSecrets(
      targetServerUrl,
      activeVaultId,
      updatePayload,
      credentials,
      transportOptions
    );

    return {
      vaultId: activeVaultId,
      vaultVersion: updateResult.vaultVersion,
      dekVersion: updateResult.dekVersion,
      keysSet: keys,
      isNewVault: false
    };
  } catch (err) {
    if (err.statusCode === 409) {
      throw new Error(`Optimistic concurrency conflict: vault "${activeVaultId}" was modified concurrently by another user. Update aborted.`);
    }
    throw err;
  }
}

/**
 * Handle execution of the 'envguard set' CLI command.
 *
 * @param {string} [keyValueArg] - Inline argument ('KEY=VALUE' or 'KEY').
 * @param {object} cmdOptions - Command options (--stdin, --env).
 * @param {import('commander').Command} command - The Commander command instance.
 */
export async function setCommandAction(keyValueArg, cmdOptions, command) {
  try {
    let secretsToSet = null;

    if (cmdOptions && cmdOptions.stdin) {
      const stdinText = await readStreamText(process.stdin);
      secretsToSet = parseStdinSecrets(stdinText);
    } else if (typeof keyValueArg === 'string' && keyValueArg.trim().length > 0) {
      const trimmed = keyValueArg.trim();
      const eqIndex = trimmed.indexOf('=');

      if (eqIndex !== -1) {
        const key = trimmed.substring(0, eqIndex).trim();
        const value = trimmed.substring(eqIndex + 1);

        validateKeyName(key);
        if (value.length === 0) {
          logger.error(`Secret value for "${key}" cannot be empty.`);
          process.exitCode = 1;
          return;
        }

        logger.warn('Setting secrets via command-line arguments may expose values in shell history and process lists.');
        secretsToSet = { [key]: value };
      } else {
        const key = trimmed;
        validateKeyName(key);

        const value = await promptInput('Secret Value: ', true);
        if (value.length === 0) {
          logger.error(`Secret value for "${key}" cannot be empty.`);
          process.exitCode = 1;
          return;
        }

        secretsToSet = { [key]: value };
      }
    } else {
      logger.error('Missing secret input: provide KEY=VALUE, KEY (for interactive prompt), or --stdin');
      process.exitCode = 1;
      return;
    }

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

    const result = await executeSet({
      secretsToSet: secretsToSet,
      env: env,
      serverUrl: serverUrl,
      caCertPath: caCertPath
    });

    for (let i = 0; i < result.keysSet.length; i = i + 1) {
      const k = result.keysSet[i];
      logger.success(`Set secret "${k}" in vault "${result.vaultId}" (version ${result.vaultVersion})`);
    }
  } catch (err) {
    logger.error(err.message);
    process.exitCode = 1;
  }
}

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
    .action(async (keyValue, options, command) => {
      await setCommandAction(keyValue, options, command);
    });
}
