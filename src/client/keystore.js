/**
 * Local client keystore management module.
 *
 * This file is part of Phase 4 (Client Identity & Registration).
 * Manages atomic disk persistence and loading of developer cryptographic identity files
 * in the user's keystore directory (~/.envguard/):
 * - key.enc: Encrypted private key envelope (mode 0600)
 * - credentials.json: Client credentials containing raw API token and salt (mode 0600)
 *
 * Security Contract:
 * - Atomic write pattern (unique temporary file -> sync -> rename) prevents corruption.
 * - Restrictive file permissions (0700 for directory, 0600 for files) enforced.
 * - Never blindly overwrites existing identities.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

/**
 * Resolve the local keystore directory.
 *
 * @param {string} [customDir] - Optional explicit directory override.
 * @returns {string} Absolute path to the keystore directory.
 */
export function getKeystoreDir(customDir) {
  if (typeof customDir === 'string' && customDir.length > 0) {
    return path.resolve(customDir);
  }
  if (typeof process.env.ENVGUARD_HOME === 'string' && process.env.ENVGUARD_HOME.length > 0) {
    return path.resolve(process.env.ENVGUARD_HOME);
  }
  return path.join(os.homedir(), '.envguard');
}

/**
 * Resolve path to the encrypted private key file.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @returns {string} Absolute path to key.enc.
 */
export function getKeyFilePath(keystoreDir) {
  return path.join(keystoreDir, 'key.enc');
}

/**
 * Resolve path to the local credentials file.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @returns {string} Absolute path to credentials.json.
 */
export function getCredentialsFilePath(keystoreDir) {
  return path.join(keystoreDir, 'credentials.json');
}

/**
 * Check whether a local identity is already initialized.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @returns {boolean} True if key.enc or credentials.json already exists.
 */
export function isInitialized(keystoreDir) {
  const keyPath = getKeyFilePath(keystoreDir);
  const credPath = getCredentialsFilePath(keystoreDir);

  if (fs.existsSync(keyPath)) {
    return true;
  }
  if (fs.existsSync(credPath)) {
    return true;
  }
  return false;
}

/**
 * Validate that an object has the required X25519 key envelope structure.
 *
 * @param {object} envelope - Candidate key envelope object.
 */
function validateKeyEnvelope(envelope) {
  if (typeof envelope !== 'object' || envelope === null) {
    throw new TypeError('Invalid key envelope: must be a non-null object');
  }
  if (envelope.version !== 1) {
    throw new Error('Unsupported key envelope version');
  }
  if (typeof envelope.publicKey !== 'object' || envelope.publicKey === null) {
    throw new TypeError('Invalid key envelope: missing publicKey JWK');
  }
  if (envelope.publicKey.kty !== 'OKP' || envelope.publicKey.crv !== 'X25519') {
    throw new TypeError('Invalid key envelope: publicKey must be an X25519 OKP key');
  }
  if (typeof envelope.publicKey.x !== 'string' || envelope.publicKey.x.length !== 43) {
    throw new TypeError('Invalid key envelope: publicKey x coordinate must be 43 base64url characters');
  }
  if (typeof envelope.kdf !== 'object' || envelope.kdf === null) {
    throw new TypeError('Invalid key envelope: missing kdf metadata');
  }
  if (envelope.kdf.algorithm !== 'pbkdf2' || envelope.kdf.digest !== 'sha256') {
    throw new Error('Invalid key envelope: unsupported KDF configuration');
  }
  if (typeof envelope.kdf.salt !== 'string' || !/^[0-9a-fA-F]{32}$/.test(envelope.kdf.salt)) {
    throw new TypeError('Invalid key envelope: salt must be 32 hexadecimal characters');
  }
  if (typeof envelope.cipher !== 'object' || envelope.cipher === null) {
    throw new TypeError('Invalid key envelope: missing cipher metadata');
  }
  if (envelope.cipher.algorithm !== 'aes-256-gcm') {
    throw new Error('Invalid key envelope: unsupported cipher algorithm');
  }
  if (typeof envelope.cipher.iv !== 'string' || !/^[0-9a-fA-F]{24}$/.test(envelope.cipher.iv)) {
    throw new TypeError('Invalid key envelope: iv must be 24 hexadecimal characters');
  }
  if (typeof envelope.cipher.tag !== 'string' || !/^[0-9a-fA-F]{32}$/.test(envelope.cipher.tag)) {
    throw new TypeError('Invalid key envelope: tag must be 32 hexadecimal characters');
  }
  if (typeof envelope.cipher.ciphertext !== 'string' || !/^[0-9a-fA-F]+$/.test(envelope.cipher.ciphertext)) {
    throw new TypeError('Invalid key envelope: ciphertext must be a valid hex string');
  }
  // Disallow plaintext or raw private keys
  if (Object.prototype.hasOwnProperty.call(envelope, 'privateKey') ||
      Object.prototype.hasOwnProperty.call(envelope, 'rawPrivateKey') ||
      Object.prototype.hasOwnProperty.call(envelope, 'd')) {
    throw new Error('Security violation: unencrypted private key material detected in key envelope');
  }
}

/**
 * Validate that an object has the required credentials structure.
 *
 * @param {object} credentials - Candidate credentials object.
 */
function validateCredentials(credentials) {
  if (typeof credentials !== 'object' || credentials === null) {
    throw new TypeError('Invalid credentials: must be a non-null object');
  }
  if (credentials.version !== 1) {
    throw new Error('Unsupported credentials version');
  }
  if (typeof credentials.username !== 'string' || credentials.username.length === 0) {
    throw new TypeError('Invalid credentials: username must be a non-empty string');
  }
  if (typeof credentials.apiToken !== 'string' || !/^[0-9a-fA-F]{64}$/.test(credentials.apiToken)) {
    throw new TypeError('Invalid credentials: apiToken must be 64 hexadecimal characters (32 bytes)');
  }
  if (typeof credentials.userSalt !== 'string' || !/^[0-9a-fA-F]{32}$/.test(credentials.userSalt)) {
    throw new TypeError('Invalid credentials: userSalt must be 32 hexadecimal characters (16 bytes)');
  }
  // Disallow private key, passphrase, or authVerifier
  if (Object.prototype.hasOwnProperty.call(credentials, 'passphrase') ||
      Object.prototype.hasOwnProperty.call(credentials, 'privateKey') ||
      Object.prototype.hasOwnProperty.call(credentials, 'd') ||
      Object.prototype.hasOwnProperty.call(credentials, 'authVerifier')) {
    throw new Error('Security violation: forbidden sensitive fields detected in credentials object');
  }
}

/**
 * Atomically write a single sensitive file to disk with mode 0600 and fsync.
 *
 * @param {string} targetPath - Final destination file path.
 * @param {string} content - File string content.
 */
async function atomicWriteSensitiveFile(targetPath, content) {
  const dir = path.dirname(targetPath);
  const randomSuffix = crypto.randomBytes(8).toString('hex');
  const tempPath = `${targetPath}.${randomSuffix}.tmp`;

  let fileHandle = null;
  try {
    fileHandle = await fsp.open(tempPath, 'wx', 0o600);
    await fileHandle.writeFile(content, { encoding: 'utf8', mode: 0o600 });
    await fileHandle.sync();
    await fileHandle.close();
    fileHandle = null;

    try {
      await fsp.chmod(tempPath, 0o600);
    } catch (chmodErr) {
      // Ignored on platforms (e.g. Windows) where POSIX chmod is unsupported
    }

    await fsp.rename(tempPath, targetPath);
  } catch (err) {
    if (fileHandle !== null) {
      try {
        await fileHandle.close();
      } catch (closeErr) {
        // Suppress secondary error
      }
    }
    if (fs.existsSync(tempPath)) {
      try {
        await fsp.unlink(tempPath);
      } catch (unlinkErr) {
        // Suppress secondary cleanup error
      }
    }
    throw err;
  }
}

/**
 * Atomically write key envelope and credentials to the keystore directory.
 * Refuses to overwrite existing identity files.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @param {object} keyEnvelope - Validated encrypted private key envelope.
 * @param {object} credentials - Validated client credentials object.
 */
export async function atomicWriteKeystore(keystoreDir, keyEnvelope, credentials) {
  validateKeyEnvelope(keyEnvelope);
  validateCredentials(credentials);

  const resolvedDir = getKeystoreDir(keystoreDir);
  const keyPath = getKeyFilePath(resolvedDir);
  const credPath = getCredentialsFilePath(resolvedDir);

  if (fs.existsSync(keyPath) || fs.existsSync(credPath)) {
    throw new Error('Identity already exists: refusing to overwrite existing keystore');
  }

  await fsp.mkdir(resolvedDir, { recursive: true, mode: 0o700 });
  try {
    await fsp.chmod(resolvedDir, 0o700);
  } catch (chmodErr) {
    // Ignored on platforms without POSIX mode support
  }

  const keyContent = JSON.stringify(keyEnvelope, null, 2) + '\n';
  const credContent = JSON.stringify(credentials, null, 2) + '\n';

  try {
    await atomicWriteSensitiveFile(keyPath, keyContent);
    await atomicWriteSensitiveFile(credPath, credContent);
  } catch (err) {
    // Clean up if partial write occurred
    if (fs.existsSync(keyPath)) {
      try {
        await fsp.unlink(keyPath);
      } catch (cleanErr) {
        // Suppress secondary error
      }
    }
    if (fs.existsSync(credPath)) {
      try {
        await fsp.unlink(credPath);
      } catch (cleanErr) {
        // Suppress secondary error
      }
    }
    throw err;
  }
}

/**
 * Load and validate client credentials from keystore directory.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @returns {Promise<object>} Parsed credentials object.
 */
export async function loadCredentials(keystoreDir) {
  const resolvedDir = getKeystoreDir(keystoreDir);
  const credPath = getCredentialsFilePath(resolvedDir);

  if (!fs.existsSync(credPath)) {
    throw new Error('Credentials file not found: run "envguard init" first');
  }

  const rawContent = await fsp.readFile(credPath, 'utf8');
  let credentials;
  try {
    credentials = JSON.parse(rawContent);
  } catch (parseErr) {
    throw new Error('Credentials file is corrupted: invalid JSON');
  }

  validateCredentials(credentials);
  return credentials;
}

/**
 * Load and validate encrypted key envelope from keystore directory.
 *
 * @param {string} keystoreDir - Keystore directory path.
 * @returns {Promise<object>} Parsed key envelope object.
 */
export async function loadKeyEnvelope(keystoreDir) {
  const resolvedDir = getKeystoreDir(keystoreDir);
  const keyPath = getKeyFilePath(resolvedDir);

  if (!fs.existsSync(keyPath)) {
    throw new Error('Key file not found: run "envguard init" first');
  }

  const rawContent = await fsp.readFile(keyPath, 'utf8');
  let envelope;
  try {
    envelope = JSON.parse(rawContent);
  } catch (parseErr) {
    throw new Error('Key file is corrupted: invalid JSON');
  }

  validateKeyEnvelope(envelope);
  return envelope;
}
