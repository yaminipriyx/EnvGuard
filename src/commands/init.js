/**
 * Command registration and handler for 'envguard init'.
 *
 * This file is part of Phase 4 (Client Identity & Registration).
 * Implements the initialization workflow:
 * 1. Checks that local identity does not already exist (prevents accidental overwrite).
 * 2. Securely prompts for username (if not supplied as argument) and master passphrase (min 12 chars).
 * 3. Enforces passphrase confirmation match.
 * 4. Resolves server URL and enrollment key.
 * 5. Generates X25519 asymmetric identity (canonical JWK) and calculates fingerprint.
 * 6. Generates raw 32-byte API token T and user salt; derives signing key K_sign via HKDF-SHA512.
 * 7. Encrypts private key locally using PBKDF2-HMAC-SHA256 (600,000 iterations) and AES-256-GCM.
 * 8. Submits public identity and authVerifier (K_sign) to Vault Server (POST /api/v1/auth/register).
 * 9. Atomically persists key.enc and credentials.json to ~/.envguard/ with mode 0600.
 * 10. Reports initialization status and public key fingerprint without leaking sensitive data.
 *
 * Security Contract:
 * - Master passphrase is never accepted via CLI argument, never logged, and never persisted.
 * - Raw API token T and private key are never sent to or stored by the Vault Server.
 * - Sensitive in-memory buffers are zeroized after use.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import readline from 'node:readline';
import crypto from 'node:crypto';
import * as logger from '../client/logger.js';
import * as keystore from '../client/keystore.js';
import * as api from '../client/api.js';
import * as ecdh from '../crypto/ecdh.js';
import * as kdf from '../crypto/kdf.js';
import * as envelope from '../crypto/envelope.js';
import { isValidUsername } from '../server/storage.js';

/**
 * Interactively prompt for user input via readline with optional hidden input (no echo).
 *
 * @param {string} promptText - Text to display before input.
 * @param {boolean} isSecret - Whether to hide typed characters (no terminal echo).
 * @param {import('node:stream').Readable} [inStream] - Optional input stream.
 * @param {import('node:stream').Writable} [outStream] - Optional output stream.
 * @returns {Promise<string>} The user's entered text.
 */
export function promptInput(promptText, isSecret, inStream, outStream) {
  let input = process.stdin;
  if (inStream) {
    input = inStream;
  }
  let output = process.stdout;
  if (outStream) {
    output = outStream;
  }

  return new Promise((resolve, reject) => {
    output.write(promptText);

    let isMuted = false;
    if (isSecret && input.isTTY) {
      isMuted = true;
    }

    const rl = readline.createInterface({
      input: input,
      output: output,
      terminal: Boolean(input.isTTY)
    });

    const originalWrite = output.write;
    if (isMuted) {
      output.write = function (chunk, encoding, callback) {
        if (!isMuted) {
          return originalWrite.call(output, chunk, encoding, callback);
        }
        return true;
      };
    }

    let closed = false;

    const cleanup = () => {
      if (isMuted) {
        isMuted = false;
        output.write = originalWrite;
      }
      input.removeListener('SIGINT', handleSigint);
    };

    const handleSigint = () => {
      if (closed) {
        return;
      }
      closed = true;
      cleanup();
      if (output && typeof output.write === 'function') {
        output.write('\n');
      }
      rl.close();
      reject(new Error('Operation cancelled by user'));
    };

    rl.on('SIGINT', handleSigint);
    input.on('SIGINT', handleSigint);

    rl.question('', (line) => {
      if (closed) {
        return;
      }
      closed = true;
      cleanup();
      if (isMuted) {
        output.write('\n');
      }
      rl.close();
      resolve(line.trim());
    });

    rl.on('close', () => {
      if (closed) {
        return;
      }
      closed = true;
      cleanup();
      reject(new Error('Input stream closed before input was provided'));
    });

    rl.on('error', (err) => {
      if (closed) {
        return;
      }
      closed = true;
      cleanup();
      rl.close();
      reject(err);
    });
  });
}

/**
 * Execute programmatic EnvGuard identity initialization and server registration.
 *
 * @param {object} params - Initialization configuration parameters.
 * @param {string} params.username - Registered developer username.
 * @param {string|Buffer} params.passphrase - Master developer passphrase (min 12 characters).
 * @param {string} params.enrollmentKey - Vault Server bootstrap enrollment key.
 * @param {string} [params.serverUrl] - Vault Server URL.
 * @param {string} [params.keystoreDir] - Keystore directory override.
 * @param {string} [params.caCertPath] - Custom CA certificate path for TLS.
 * @param {string} [params.caCertContent] - Custom CA certificate string content.
 * @returns {Promise<object>} Initialization metadata including public key fingerprint.
 */
export async function executeInit(params) {
  if (typeof params !== 'object' || params === null) {
    throw new TypeError('Invalid params: must be a non-null object');
  }

  const username = params.username;
  if (!isValidUsername(username)) {
    throw new Error('Invalid username: must be 1-64 characters matching [a-zA-Z0-9_.-]');
  }

  const passphrase = params.passphrase;
  if (typeof passphrase !== 'string' && !Buffer.isBuffer(passphrase)) {
    throw new TypeError('Invalid passphrase: must be a string or Buffer');
  }

  const passphraseBuf = Buffer.from(passphrase, 'utf8');
  if (passphraseBuf.length < 12) {
    passphraseBuf.fill(0);
    throw new Error('Invalid passphrase: master passphrase must be at least 12 characters');
  }

  const enrollmentKey = params.enrollmentKey;
  if (typeof enrollmentKey !== 'string' || enrollmentKey.length === 0) {
    passphraseBuf.fill(0);
    throw new Error('Invalid enrollment key: must be a non-empty string');
  }

  const resolvedKeystoreDir = keystore.getKeystoreDir(params.keystoreDir);
  if (keystore.isInitialized(resolvedKeystoreDir)) {
    passphraseBuf.fill(0);
    throw new Error(`Identity already exists in ${resolvedKeystoreDir}: refusing to overwrite existing keystore`);
  }

  const serverUrl = api.resolveServerUrl(params.serverUrl);

  // 1. Generate X25519 keypair in canonical JWK format
  const keyPair = ecdh.generateKeyPair();
  const publicKeyJwk = keyPair.publicKey;
  const privateKeyJwk = keyPair.privateKey;

  // 2. Calculate public key fingerprint
  const fingerprint = ecdh.calculateFingerprint(publicKeyJwk);

  // 3. Encrypt private key using PBKDF2-HMAC-SHA256 and AES-256-GCM
  let keyEnvelope;
  try {
    keyEnvelope = envelope.createPrivateKeyEnvelope(privateKeyJwk, passphraseBuf);
  } finally {
    passphraseBuf.fill(0);
  }

  // 4. Generate local 32-byte raw API token and 16-byte user salt
  const rawTokenBuffer = crypto.randomBytes(32);
  const userSaltBuffer = crypto.randomBytes(16);

  // 5. Derive 64-byte K_sign (authVerifier) using HKDF-SHA512
  let kSignBuffer;
  try {
    kSignBuffer = kdf.hkdfSha512(
      rawTokenBuffer,
      userSaltBuffer,
      'envguard-client-signing-v1',
      64
    );
  } catch (kdfErr) {
    rawTokenBuffer.fill(0);
    userSaltBuffer.fill(0);
    throw kdfErr;
  }

  const authVerifierHex = kSignBuffer.toString('hex');
  const userSaltHex = userSaltBuffer.toString('hex');
  const rawTokenHex = rawTokenBuffer.toString('hex');

  // Zeroize sensitive intermediate buffers
  rawTokenBuffer.fill(0);
  userSaltBuffer.fill(0);
  kSignBuffer.fill(0);

  // 6. Submit registration to Vault Server
  // Note: Only public key, salt, authVerifier, and enrollmentKey are transmitted
  const registrationPayload = {
    username: username,
    publicKey: {
      kty: 'OKP',
      crv: 'X25519',
      x: publicKeyJwk.x
    },
    salt: userSaltHex,
    authVerifier: authVerifierHex,
    enrollmentKey: enrollmentKey
  };

  const transportOptions = {};
  if (params.caCertPath) {
    transportOptions.caCertPath = params.caCertPath;
  }
  if (params.caCertContent) {
    transportOptions.caCertContent = params.caCertContent;
  }

  await api.registerUser(serverUrl, registrationPayload, transportOptions);

  // 7. Assemble credentials for atomic disk persistence
  const credentials = {
    version: 1,
    username: username,
    apiToken: rawTokenHex,
    userSalt: userSaltHex
  };

  // 8. Atomically persist key envelope and credentials to ~/.envguard/
  await keystore.atomicWriteKeystore(resolvedKeystoreDir, keyEnvelope, credentials);

  return {
    username: username,
    publicKeyFingerprint: fingerprint,
    keystoreDir: resolvedKeystoreDir
  };
}

/**
 * Handle execution of the 'envguard init' CLI command.
 *
 * @param {string} [usernameArg] - Optional username passed as argument.
 * @param {object} cmdOptions - Command-specific options (--enrollment-key).
 * @param {import('commander').Command} command - The Commander command instance.
 */
export async function initCommandAction(usernameArg, cmdOptions, command) {
  try {
    const resolvedKeystoreDir = keystore.getKeystoreDir();
    if (keystore.isInitialized(resolvedKeystoreDir)) {
      logger.error(`Identity already initialized in ${resolvedKeystoreDir}. Refusing to overwrite existing identity.`);
      process.exitCode = 1;
      return;
    }

    let username = usernameArg;
    if (typeof username !== 'string' || username.trim().length === 0) {
      username = await promptInput('Username: ', false);
    }
    username = username.trim();

    if (!isValidUsername(username)) {
      logger.error('Invalid username: must be 1-64 characters matching [a-zA-Z0-9_.-]');
      process.exitCode = 1;
      return;
    }

    const passphrase = await promptInput('Master Passphrase (min 12 chars): ', true);
    if (passphrase.length === 0) {
      logger.error('Master passphrase cannot be empty.');
      process.exitCode = 1;
      return;
    }
    if (passphrase.length < 12) {
      logger.error('Master passphrase must be at least 12 characters long.');
      process.exitCode = 1;
      return;
    }

    const confirmPassphrase = await promptInput('Confirm Master Passphrase: ', true);
    if (passphrase !== confirmPassphrase) {
      logger.error('Master passphrase confirmation does not match.');
      process.exitCode = 1;
      return;
    }

    let enrollmentKey = null;
    if (cmdOptions && typeof cmdOptions.enrollmentKey === 'string' && cmdOptions.enrollmentKey.length > 0) {
      enrollmentKey = cmdOptions.enrollmentKey;
    } else if (typeof process.env.ENVGUARD_ENROLLMENT_KEY === 'string' && process.env.ENVGUARD_ENROLLMENT_KEY.length > 0) {
      enrollmentKey = process.env.ENVGUARD_ENROLLMENT_KEY;
    }

    if (!enrollmentKey) {
      enrollmentKey = await promptInput('Enrollment Key: ', true);
    }

    if (!enrollmentKey || enrollmentKey.length === 0) {
      logger.error('Enrollment key is required.');
      process.exitCode = 1;
      return;
    }

    let globalOpts = {};
    if (command && typeof command.optsWithGlobals === 'function') {
      globalOpts = command.optsWithGlobals();
    }

    const serverUrl = api.resolveServerUrl(globalOpts.server);
    let caCertPath = null;
    if (globalOpts.caCert) {
      caCertPath = globalOpts.caCert;
    }

    logger.info('Initializing EnvGuard identity...');
    logger.info('Generating X25519 identity...');
    logger.info('Protecting local private key...');
    logger.info('Registering identity with Vault Server...');

    const result = await executeInit({
      username: username,
      passphrase: passphrase,
      enrollmentKey: enrollmentKey,
      serverUrl: serverUrl,
      caCertPath: caCertPath
    });

    logger.success('Initialization successful.');
    console.log('');
    console.log('Public key fingerprint:');
    console.log(result.publicKeyFingerprint);
    console.log('');
    console.log(`Identity stored locally in ${result.keystoreDir}.`);
  } catch (err) {
    logger.error(err.message);
    process.exitCode = 1;
  }
}

/**
 * Register the 'init' command with the Commander program.
 *
 * @param {import('commander').Command} program - The root Commander program instance.
 */
export function registerInitCommand(program) {
  program
    .command('init [username]')
    .description('Initialize developer cryptographic identity and register with Vault Server')
    .option('--enrollment-key <key>', 'Vault Server enrollment bootstrap key')
    .action(async (username, options, command) => {
      await initCommandAction(username, options, command);
    });
}
