/**
 * Command registration and handler for 'envguard run'.
 *
 * This file is part of Phase 6 (Runtime Execution & Secret Injection).
 * Executes a target child command with decrypted secrets injected directly
 * into child process volatile memory without disk persistence.
 *
 * Security Invariants:
 * 1. Secrets are NEVER written to disk (.env, temp files, caches).
 * 2. Child command is spawned with shell: false to prevent shell injection.
 * 3. Exact argument list after '--' is preserved without modification.
 * 4. Master passphrase prompted with hidden input (no echo).
 * 5. Server response treated as untrusted: validates AAD, versions, envelopes.
 * 6. DEK unwrapping and secret decryption performed entirely locally in memory.
 * 7. Sensitive Buffers (DEK, plaintext JSON) zeroized via buffer.fill(0) after use.
 * 8. Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import { spawn } from 'node:child_process';
import * as logger from '../client/logger.js';
import * as keystore from '../client/keystore.js';
import * as api from '../client/api.js';
import * as envelope from '../crypto/envelope.js';
import { promptInput } from './init.js';

const VALID_KEY_REGEX = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Validate and separate the command and arguments array.
 *
 * @param {string[]} commandArgs - Array of command and argument strings.
 * @returns {{ command: string, args: string[] }} Separated command and arguments.
 */
export function validateCommandArgs(commandArgs) {
  if (!Array.isArray(commandArgs) || commandArgs.length === 0) {
    throw new Error('No command specified. Usage: envguard run [--env <name>] -- <command> [args...]');
  }

  const targetCommand = commandArgs[0];
  if (typeof targetCommand !== 'string' || targetCommand.trim().length === 0) {
    throw new Error('Invalid command: must be a non-empty string');
  }

  const targetArgs = commandArgs.slice(1);
  return {
    command: targetCommand,
    args: targetArgs
  };
}

/**
 * Validate the schema and types of the decrypted secret map.
 *
 * @param {unknown} secretMap - Decrypted and parsed secret map.
 * @returns {Record<string, string>} Validated string secret map.
 */
export function validateSecretMap(secretMap) {
  if (typeof secretMap !== 'object' || secretMap === null || Array.isArray(secretMap)) {
    throw new Error('Invalid secret payload: root must be a JSON object');
  }

  const keys = Object.keys(secretMap);
  const validated = {};

  for (let i = 0; i < keys.length; i = i + 1) {
    const k = keys[i];
    if (!VALID_KEY_REGEX.test(k)) {
      throw new Error(`Invalid secret key name "${k}": must match ^[A-Za-z_][A-Za-z0-9_]*$`);
    }

    const val = secretMap[k];
    if (typeof val !== 'string') {
      throw new Error(`Invalid secret value for key "${k}": values must be strings`);
    }

    validated[k] = val;
  }

  return validated;
}

/**
 * Validate the structure and cryptographic fields of the untrusted vault response.
 *
 * @param {object} vaultState - Server response object.
 * @param {string} vaultId - Expected vault identifier.
 * @param {string} username - Current caller username.
 */
export function validateVaultResponse(vaultState, vaultId, username) {
  if (typeof vaultState !== 'object' || vaultState === null) {
    throw new Error(`Corrupted vault response: invalid response structure for vault "${vaultId}"`);
  }

  if (typeof vaultState.vaultVersion !== 'number' || vaultState.vaultVersion <= 0) {
    throw new Error(`Corrupted vault response: missing or invalid vaultVersion for vault "${vaultId}"`);
  }

  if (typeof vaultState.dekVersion !== 'number' || vaultState.dekVersion <= 0) {
    throw new Error(`Corrupted vault response: missing or invalid dekVersion for vault "${vaultId}"`);
  }

  const blob = vaultState.blob;
  if (typeof blob !== 'object' || blob === null) {
    throw new Error(`Corrupted vault response: missing secret blob for vault "${vaultId}"`);
  }

  if (blob.algorithm !== 'aes-256-gcm') {
    throw new Error(`Unsupported blob algorithm "${blob.algorithm}": expected aes-256-gcm`);
  }

  if (typeof blob.dekVersion !== 'number' || blob.dekVersion !== vaultState.dekVersion) {
    throw new Error(`Cryptographic verification failed: blob dekVersion mismatch in vault "${vaultId}"`);
  }

  if (typeof blob.iv !== 'string' || typeof blob.tag !== 'string' || typeof blob.ciphertext !== 'string') {
    throw new Error(`Corrupted vault response: incomplete blob envelope fields in vault "${vaultId}"`);
  }

  const expectedBlobAad = `${vaultId}:${vaultState.dekVersion}`;
  if (blob.aad !== expectedBlobAad) {
    throw new Error(`Cryptographic verification failed: blob AAD mismatch in vault "${vaultId}"`);
  }

  const wrappedDeks = vaultState.wrappedDeks;
  if (typeof wrappedDeks !== 'object' || wrappedDeks === null) {
    throw new Error(`Corrupted vault response: missing wrappedDeks for vault "${vaultId}"`);
  }

  const callerWrappedDek = wrappedDeks[username];
  if (!callerWrappedDek) {
    throw new Error(`No wrapped DEK available for current user "${username}" in vault "${vaultId}"`);
  }

  if (callerWrappedDek.algorithm !== 'aes-256-gcm') {
    throw new Error(`Unsupported wrapped DEK algorithm "${callerWrappedDek.algorithm}": expected aes-256-gcm`);
  }

  if (typeof callerWrappedDek.kdf !== 'object' || callerWrappedDek.kdf === null) {
    throw new Error(`Corrupted wrapped DEK: missing KDF configuration for user "${username}"`);
  }

  if (callerWrappedDek.kdf.algorithm !== 'hkdf-sha512' || callerWrappedDek.kdf.info !== 'envguard-dek-wrap-v1') {
    throw new Error(`Unsupported wrapped DEK KDF parameters for user "${username}"`);
  }

  const ephKey = callerWrappedDek.ephemeralPublicKey;
  if (typeof ephKey !== 'object' || ephKey === null) {
    throw new Error(`Corrupted wrapped DEK: missing ephemeral public key for user "${username}"`);
  }

  if (ephKey.kty !== 'OKP' || ephKey.crv !== 'X25519' || typeof ephKey.x !== 'string') {
    throw new Error(`Corrupted wrapped DEK: invalid ephemeral public key JWK for user "${username}"`);
  }

  if (typeof callerWrappedDek.iv !== 'string' ||
      typeof callerWrappedDek.tag !== 'string' ||
      typeof callerWrappedDek.encryptedDek !== 'string') {
    throw new Error(`Corrupted wrapped DEK: incomplete envelope fields for user "${username}"`);
  }

  if (typeof callerWrappedDek.dekVersion === 'number') {
    if (callerWrappedDek.dekVersion !== vaultState.dekVersion) {
      throw new Error(`Cryptographic verification failed: wrapped DEK dekVersion mismatch for user "${username}"`);
    }
  }

  const expectedWrappedDekAad = `${vaultId}:${vaultState.dekVersion}:${username}`;
  if (callerWrappedDek.aad !== expectedWrappedDekAad) {
    throw new Error(`Cryptographic verification failed: wrapped DEK AAD mismatch for user "${username}"`);
  }
}

/**
 * Execute programmatic run: fetch vault, unwrap DEK, decrypt secrets, and spawn child process.
 *
 * @param {object} params - Execution parameters.
 * @param {string[]} params.commandArgs - Child command and arguments.
 * @param {string} [params.env] - Target environment name (default 'development').
 * @param {string} [params.serverUrl] - Explicit server URL override.
 * @param {string} [params.caCertPath] - Custom CA certificate path for TLS.
 * @param {string} [params.keystoreDir] - Keystore directory override.
 * @param {object} [params.projectConfig] - Project config override for testing.
 * @param {string} [params.passphrase] - Master passphrase override for testing.
 * @param {import('node:stream').Readable} [params.inStream] - Input stream for prompt.
 * @param {import('node:stream').Writable} [params.outStream] - Output stream for prompt.
 * @param {string|Array} [params.stdio] - Stdio configuration for child process.
 * @returns {Promise<{ exitCode: number, signal: string|null }>}
 */
export async function executeRun(params) {
  if (typeof params !== 'object' || params === null) {
    throw new TypeError('Invalid params: must be a non-null object');
  }

  const parsedCommand = validateCommandArgs(params.commandArgs);
  const targetCommand = parsedCommand.command;
  const targetArgs = parsedCommand.args;

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

  // 6. Fetch encrypted vault state (GET /api/v1/vault/:vaultId/secrets)
  const vaultState = await api.getVaultSecrets(targetServerUrl, configuredVaultId, credentials, transportOptions);

  // 7. Validate untrusted vault response structure, versions, and AAD
  validateVaultResponse(vaultState, configuredVaultId, credentials.username);

  const callerWrappedDek = vaultState.wrappedDeks[credentials.username];
  const activeDekVersion = vaultState.dekVersion;

  // 8. Obtain master passphrase to decrypt local private key
  let masterPassphrase = params.passphrase;
  if (typeof masterPassphrase !== 'string' || masterPassphrase.length === 0) {
    masterPassphrase = await promptInput('Master Passphrase: ', true, params.inStream, params.outStream);
  }

  if (typeof masterPassphrase !== 'string' || masterPassphrase.length < 12) {
    throw new Error('Master passphrase must be at least 12 characters');
  }

  // 9. Load and decrypt local private key JWK
  const keyEnvelope = await keystore.loadKeyEnvelope(params.keystoreDir);
  let privateKeyJwk;
  try {
    privateKeyJwk = envelope.openPrivateKeyEnvelope(keyEnvelope, masterPassphrase);
  } catch (err) {
    throw new Error('Master passphrase authentication failed');
  }

  // 10. Unwrap active DEK locally
  let dek;
  try {
    dek = envelope.openWrappedDekEnvelope(
      callerWrappedDek,
      privateKeyJwk,
      configuredVaultId,
      activeDekVersion,
      credentials.username
    );
  } catch (err) {
    throw new Error('Failed to unwrap DEK: wrapped key authentication failed or corrupted envelope');
  }

  // 11. Decrypt secret blob locally
  let decryptedPlaintext;
  try {
    decryptedPlaintext = envelope.openSecretEnvelope(
      vaultState.blob,
      dek,
      configuredVaultId,
      activeDekVersion
    );
  } catch (err) {
    throw new Error('Failed to decrypt vault secrets: ciphertext authentication failed or corrupted');
  } finally {
    if (dek) {
      dek.fill(0);
    }
  }

  // 12. Parse and validate plaintext secret map schema
  let secretMap;
  try {
    const jsonString = decryptedPlaintext.toString('utf8');
    secretMap = JSON.parse(jsonString);
  } catch (err) {
    throw new Error('Invalid secret payload: decrypted data is not valid JSON');
  } finally {
    if (decryptedPlaintext) {
      decryptedPlaintext.fill(0);
    }
  }

  const validatedSecrets = validateSecretMap(secretMap);

  // 13. Construct child environment explicitly in volatile memory
  // Vault secrets override inherited variables of the same name; unrelated parent variables remain intact.
  const childEnv = Object.assign({}, process.env, validatedSecrets);

  let stdioConfig = 'inherit';
  if (params.stdio) {
    stdioConfig = params.stdio;
  }

  const spawnOptions = {
    env: childEnv,
    stdio: stdioConfig,
    shell: false
  };

  // 14. Spawn child process with shell: false and forward relevant signals
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(targetCommand, targetArgs, spawnOptions);
    } catch (err) {
      reject(err);
      return;
    }

    const onSigint = () => {
      try {
        child.kill('SIGINT');
      } catch (err) {
        // Child already terminated
      }
    };

    const onSigterm = () => {
      try {
        child.kill('SIGTERM');
      } catch (err) {
        // Child already terminated
      }
    };

    process.on('SIGINT', onSigint);
    process.on('SIGTERM', onSigterm);

    child.on('error', (err) => {
      process.removeListener('SIGINT', onSigint);
      process.removeListener('SIGTERM', onSigterm);
      reject(err);
    });

    child.on('close', (code, signal) => {
      process.removeListener('SIGINT', onSigint);
      process.removeListener('SIGTERM', onSigterm);

      let finalExitCode = 0;
      if (typeof code === 'number') {
        finalExitCode = code;
      } else if (signal) {
        finalExitCode = 128 + 15;
      }

      let finalSignal = null;
      if (signal) {
        finalSignal = signal;
      }

      resolve({
        exitCode: finalExitCode,
        signal: finalSignal
      });
    });
  });
}

/**
 * Handle execution of the 'envguard run' CLI command.
 *
 * @param {string[]} commandArgs - Child command and arguments.
 * @param {object} cmdOptions - Command options (--env).
 * @param {import('commander').Command} command - The Commander command instance.
 */
export async function runCommandAction(commandArgs, cmdOptions, command) {
  try {
    if (!Array.isArray(commandArgs) || commandArgs.length === 0) {
      logger.error('No command specified. Usage: envguard run [--env <name>] -- <command> [args...]');
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

    const result = await executeRun({
      commandArgs: commandArgs,
      env: env,
      serverUrl: serverUrl,
      caCertPath: caCertPath
    });

    process.exitCode = result.exitCode;
  } catch (err) {
    logger.error(err.message);
    process.exitCode = 1;
  }
}

/**
 * Register the 'run' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerRunCommand(program) {
  program
    .command('run [command...]')
    .description('Run a command with secrets injected into runtime memory')
    .option('--env <name>', 'Target environment name')
    .action(async (commandArgs, options, command) => {
      await runCommandAction(commandArgs, options, command);
    });
}
