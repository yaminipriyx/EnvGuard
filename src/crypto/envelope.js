/**
 * Cryptographic envelope composition module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Implements canonical envelope construction and authenticated unwrapping
 * for secret blobs, wrapped Data Encryption Keys (DEKs), and encrypted private keys.
 * Enforces strict AAD derivation contracts, ephemeral X25519 ECDH key agreement,
 * and fail-closed authentication.
 * Later phases (Phases 3, 4, 5, 6) will compose this module for vault storage,
 * client credentials, secret distribution, and runtime decryption.
 */

import crypto from 'node:crypto';
import * as aes from './aes.js';
import * as ecdh from './ecdh.js';
import * as kdf from './kdf.js';

/**
 * Construct the canonical AAD for an encrypted secret blob.
 *
 * @param {string} vaultId - The unique vault identifier.
 * @param {number} dekVersion - The DEK generation version.
 * @returns {string} The canonical AAD string.
 */
export function constructSecretAad(vaultId, dekVersion) {
  if (typeof vaultId !== 'string' || vaultId.length === 0) {
    throw new TypeError('Invalid vaultId: must be a non-empty string');
  }
  if (typeof dekVersion !== 'number' || dekVersion < 1 || !Number.isInteger(dekVersion)) {
    throw new TypeError('Invalid dekVersion: must be a positive integer');
  }
  return `${vaultId}:${dekVersion}`;
}

/**
 * Construct the canonical AAD for a wrapped Data Encryption Key (DEK).
 *
 * @param {string} vaultId - The unique vault identifier.
 * @param {number} dekVersion - The DEK generation version.
 * @param {string} recipientUsername - The recipient username.
 * @returns {string} The canonical AAD string.
 */
export function constructWrappedDekAad(vaultId, dekVersion, recipientUsername) {
  if (typeof vaultId !== 'string' || vaultId.length === 0) {
    throw new TypeError('Invalid vaultId: must be a non-empty string');
  }
  if (typeof dekVersion !== 'number' || dekVersion < 1 || !Number.isInteger(dekVersion)) {
    throw new TypeError('Invalid dekVersion: must be a positive integer');
  }
  if (typeof recipientUsername !== 'string' || recipientUsername.length === 0) {
    throw new TypeError('Invalid recipientUsername: must be a non-empty string');
  }
  return `${vaultId}:${dekVersion}:${recipientUsername}`;
}

/**
 * Create an encrypted secret blob envelope.
 *
 * @param {Buffer|string} plaintext - Plaintext secret payload (typically serialized JSON).
 * @param {Buffer} dek - 32-byte Data Encryption Key.
 * @param {string} vaultId - Target vault ID.
 * @param {number} dekVersion - Active DEK version.
 * @returns {object} The encrypted secret blob envelope.
 */
export function createSecretEnvelope(plaintext, dek, vaultId, dekVersion) {
  const expectedAad = constructSecretAad(vaultId, dekVersion);
  const encrypted = aes.encrypt(plaintext, dek, expectedAad);

  return {
    algorithm: 'aes-256-gcm',
    dekVersion: dekVersion,
    iv: encrypted.iv.toString('hex'),
    tag: encrypted.tag.toString('hex'),
    ciphertext: encrypted.ciphertext.toString('hex'),
    aad: expectedAad
  };
}

/**
 * Authenticate and decrypt an encrypted secret blob envelope.
 *
 * @param {object} envelope - The encrypted secret blob envelope.
 * @param {Buffer} dek - 32-byte Data Encryption Key.
 * @param {string} expectedVaultId - Expected vault ID to bind.
 * @param {number} expectedDekVersion - Expected DEK version to bind.
 * @returns {Buffer} The authenticated decrypted plaintext buffer.
 */
export function openSecretEnvelope(envelope, dek, expectedVaultId, expectedDekVersion) {
  if (typeof envelope !== 'object' || envelope === null) {
    throw new TypeError('Invalid envelope: must be a non-null object');
  }

  if (envelope.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported envelope algorithm: must be aes-256-gcm');
  }

  if (envelope.dekVersion !== expectedDekVersion) {
    throw new Error('DEK version mismatch between envelope and expected state');
  }

  const expectedAad = constructSecretAad(expectedVaultId, expectedDekVersion);
  if (envelope.aad !== expectedAad) {
    throw new Error('AAD mismatch: stored AAD does not match expected canonical AAD');
  }

  const hex24Regex = /^[0-9a-fA-F]{24}$/;
  if (typeof envelope.iv !== 'string' || !hex24Regex.test(envelope.iv)) {
    throw new TypeError('Invalid envelope IV: must be a 24-character hex string');
  }

  const hex32Regex = /^[0-9a-fA-F]{32}$/;
  if (typeof envelope.tag !== 'string' || !hex32Regex.test(envelope.tag)) {
    throw new TypeError('Invalid envelope tag: must be a 32-character hex string');
  }

  if (typeof envelope.ciphertext !== 'string') {
    throw new TypeError('Invalid envelope ciphertext: must be a string');
  }

  if (envelope.ciphertext.length % 2 !== 0) {
    throw new TypeError('Invalid envelope ciphertext: hex length must be even');
  }

  if (envelope.ciphertext.length > 0) {
    const hexRegex = /^[0-9a-fA-F]+$/;
    if (!hexRegex.test(envelope.ciphertext)) {
      throw new TypeError('Invalid envelope ciphertext: must be a valid hex string');
    }
  }

  const ivBuffer = Buffer.from(envelope.iv, 'hex');
  const tagBuffer = Buffer.from(envelope.tag, 'hex');
  const ciphertextBuffer = Buffer.from(envelope.ciphertext, 'hex');

  return aes.decrypt(ciphertextBuffer, dek, ivBuffer, tagBuffer, expectedAad);
}

/**
 * Wrap a Data Encryption Key (DEK) for a recipient using X25519 ECDH, HKDF-SHA512, and AES-256-GCM.
 *
 * @param {Buffer} dek - 32-byte Data Encryption Key to wrap.
 * @param {object} recipientPublicKeyJwk - Recipient X25519 public key JWK.
 * @param {string} vaultId - Target vault ID.
 * @param {number} dekVersion - Active DEK version.
 * @param {string} recipientUsername - Target recipient username.
 * @returns {object} The wrapped DEK envelope.
 */
export function createWrappedDekEnvelope(dek, recipientPublicKeyJwk, vaultId, dekVersion, recipientUsername) {
  if (!Buffer.isBuffer(dek) || dek.length !== 32) {
    throw new TypeError('Invalid DEK: must be a 32-byte Buffer');
  }

  const expectedAad = constructWrappedDekAad(vaultId, dekVersion, recipientUsername);
  const ephemeral = ecdh.generateKeyPair();
  const sharedSecret = ecdh.deriveSharedSecret(ephemeral.privateKey, recipientPublicKeyJwk);

  let wrappingKey;
  try {
    wrappingKey = kdf.hkdfSha512(sharedSecret, Buffer.alloc(0), 'envguard-dek-wrap-v1', 32);
  } finally {
    sharedSecret.fill(0);
  }

  let encrypted;
  try {
    encrypted = aes.encrypt(dek, wrappingKey, expectedAad);
  } finally {
    wrappingKey.fill(0);
  }

  return {
    algorithm: 'aes-256-gcm',
    kdf: {
      algorithm: 'hkdf-sha512',
      info: 'envguard-dek-wrap-v1'
    },
    ephemeralPublicKey: ephemeral.publicKey,
    iv: encrypted.iv.toString('hex'),
    tag: encrypted.tag.toString('hex'),
    encryptedDek: encrypted.ciphertext.toString('hex'),
    aad: expectedAad
  };
}

/**
 * Authenticate and unwrap a wrapped Data Encryption Key (DEK).
 *
 * @param {object} envelope - The wrapped DEK envelope.
 * @param {object} recipientPrivateKeyJwk - Recipient X25519 private key JWK.
 * @param {string} expectedVaultId - Expected vault ID.
 * @param {number} expectedDekVersion - Expected DEK version.
 * @param {string} expectedRecipientUsername - Expected recipient username.
 * @returns {Buffer} The unwrapped 32-byte Data Encryption Key buffer.
 */
export function openWrappedDekEnvelope(envelope, recipientPrivateKeyJwk, expectedVaultId, expectedDekVersion, expectedRecipientUsername) {
  if (typeof envelope !== 'object' || envelope === null) {
    throw new TypeError('Invalid wrapped DEK envelope: must be a non-null object');
  }

  if (envelope.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported envelope algorithm: must be aes-256-gcm');
  }

  if (typeof envelope.kdf !== 'object' || envelope.kdf === null) {
    throw new TypeError('Invalid envelope kdf metadata');
  }

  if (envelope.kdf.algorithm !== 'hkdf-sha512' || envelope.kdf.info !== 'envguard-dek-wrap-v1') {
    throw new Error('Unsupported or invalid KDF parameters in wrapped DEK envelope');
  }

  const expectedAad = constructWrappedDekAad(expectedVaultId, expectedDekVersion, expectedRecipientUsername);
  if (envelope.aad !== expectedAad) {
    throw new Error('AAD mismatch: stored AAD does not match expected canonical AAD');
  }

  const hex24Regex = /^[0-9a-fA-F]{24}$/;
  if (typeof envelope.iv !== 'string' || !hex24Regex.test(envelope.iv)) {
    throw new TypeError('Invalid envelope IV: must be a 24-character hex string');
  }

  const hex32Regex = /^[0-9a-fA-F]{32}$/;
  if (typeof envelope.tag !== 'string' || !hex32Regex.test(envelope.tag)) {
    throw new TypeError('Invalid envelope tag: must be a 32-character hex string');
  }

  const hex64Regex = /^[0-9a-fA-F]{64}$/;
  if (typeof envelope.encryptedDek !== 'string' || !hex64Regex.test(envelope.encryptedDek)) {
    throw new TypeError('Invalid envelope encryptedDek: must be a 64-character hex string');
  }

  const sharedSecret = ecdh.deriveSharedSecret(recipientPrivateKeyJwk, envelope.ephemeralPublicKey);
  let wrappingKey;
  try {
    wrappingKey = kdf.hkdfSha512(sharedSecret, Buffer.alloc(0), 'envguard-dek-wrap-v1', 32);
  } finally {
    sharedSecret.fill(0);
  }

  const ivBuffer = Buffer.from(envelope.iv, 'hex');
  const tagBuffer = Buffer.from(envelope.tag, 'hex');
  const ciphertextBuffer = Buffer.from(envelope.encryptedDek, 'hex');

  let unwrappedDek;
  try {
    unwrappedDek = aes.decrypt(ciphertextBuffer, wrappingKey, ivBuffer, tagBuffer, expectedAad);
  } finally {
    wrappingKey.fill(0);
  }

  if (unwrappedDek.length !== 32) {
    unwrappedDek.fill(0);
    throw new Error('Invalid unwrapped DEK length: expected 32 bytes');
  }

  return unwrappedDek;
}

/**
 * Encrypt a developer private key JWK for local disk storage (key.enc format).
 *
 * @param {object} privateKeyJwk - The X25519 private key JWK to protect.
 * @param {string|Buffer} passphrase - Master developer passphrase (minimum 12 chars).
 * @returns {object} The encrypted private key file envelope.
 */
export function createPrivateKeyEnvelope(privateKeyJwk, passphrase) {
  const derivedPublicKey = ecdh.derivePublicKey(privateKeyJwk);
  const salt = crypto.randomBytes(16);
  const kek = kdf.pbkdf2Sha256(passphrase, salt, 600000, 32);

  const serializedPrivateKey = Buffer.from(JSON.stringify(privateKeyJwk), 'utf8');
  let encrypted;
  try {
    encrypted = aes.encrypt(serializedPrivateKey, kek);
  } finally {
    kek.fill(0);
    serializedPrivateKey.fill(0);
  }

  return {
    version: 1,
    createdAt: new Date().toISOString(),
    publicKey: derivedPublicKey,
    kdf: {
      algorithm: 'pbkdf2',
      digest: 'sha256',
      iterations: 600000,
      salt: salt.toString('hex')
    },
    cipher: {
      algorithm: 'aes-256-gcm',
      iv: encrypted.iv.toString('hex'),
      tag: encrypted.tag.toString('hex'),
      ciphertext: encrypted.ciphertext.toString('hex')
    }
  };
}

/**
 * Authenticate and decrypt an encrypted private key file envelope.
 *
 * @param {object} envelope - The parsed key.enc envelope.
 * @param {string|Buffer} passphrase - Master developer passphrase.
 * @returns {object} The decrypted and verified X25519 private key JWK.
 */
export function openPrivateKeyEnvelope(envelope, passphrase) {
  if (typeof envelope !== 'object' || envelope === null) {
    throw new TypeError('Invalid key envelope: must be a non-null object');
  }

  if (envelope.version !== 1) {
    throw new Error('Unsupported key envelope version');
  }

  if (typeof envelope.kdf !== 'object' || envelope.kdf === null) {
    throw new TypeError('Invalid key envelope KDF metadata');
  }

  if (envelope.kdf.algorithm !== 'pbkdf2' || envelope.kdf.digest !== 'sha256') {
    throw new Error('Unsupported key envelope KDF algorithm or digest');
  }

  if (typeof envelope.cipher !== 'object' || envelope.cipher === null) {
    throw new TypeError('Invalid key envelope cipher metadata');
  }

  if (envelope.cipher.algorithm !== 'aes-256-gcm') {
    throw new Error('Unsupported key envelope cipher algorithm');
  }

  if (typeof envelope.kdf.iterations !== 'number' || envelope.kdf.iterations <= 0 || !Number.isInteger(envelope.kdf.iterations)) {
    throw new TypeError('Invalid key envelope iterations: must be a positive integer');
  }

  const hexSaltRegex = /^[0-9a-fA-F]{32}$/;
  if (typeof envelope.kdf.salt !== 'string' || !hexSaltRegex.test(envelope.kdf.salt)) {
    throw new TypeError('Invalid key envelope salt: must be an exact 32-character hex string (16 bytes)');
  }

  const hex24Regex = /^[0-9a-fA-F]{24}$/;
  if (typeof envelope.cipher.iv !== 'string' || !hex24Regex.test(envelope.cipher.iv)) {
    throw new TypeError('Invalid key envelope IV: must be a 24-character hex string');
  }

  const hex32Regex = /^[0-9a-fA-F]{32}$/;
  if (typeof envelope.cipher.tag !== 'string' || !hex32Regex.test(envelope.cipher.tag)) {
    throw new TypeError('Invalid key envelope tag: must be a 32-character hex string');
  }

  if (typeof envelope.cipher.ciphertext !== 'string' || envelope.cipher.ciphertext.length % 2 !== 0) {
    throw new TypeError('Invalid key envelope ciphertext: must be an even-length hex string');
  }

  const hexRegex = /^[0-9a-fA-F]+$/;
  if (!hexRegex.test(envelope.cipher.ciphertext)) {
    throw new TypeError('Invalid key envelope ciphertext: must be a valid hex string');
  }

  const saltBuffer = Buffer.from(envelope.kdf.salt, 'hex');
  const iterations = envelope.kdf.iterations;
  const kek = kdf.pbkdf2Sha256(passphrase, saltBuffer, iterations, 32);

  const ivBuffer = Buffer.from(envelope.cipher.iv, 'hex');
  const tagBuffer = Buffer.from(envelope.cipher.tag, 'hex');
  const ciphertextBuffer = Buffer.from(envelope.cipher.ciphertext, 'hex');

  let decryptedPlaintext;
  try {
    decryptedPlaintext = aes.decrypt(ciphertextBuffer, kek, ivBuffer, tagBuffer);
  } finally {
    kek.fill(0);
  }

  let privateKeyJwk;
  try {
    privateKeyJwk = JSON.parse(decryptedPlaintext.toString('utf8'));
  } catch (err) {
    throw new Error('Decrypted private key payload is not valid JSON');
  } finally {
    decryptedPlaintext.fill(0);
  }

  const isVerified = ecdh.verifyKeyPair(privateKeyJwk, envelope.publicKey);
  if (!isVerified) {
    throw new Error('Private key integrity check failed: derived public key does not match stored public key');
  }

  return privateKeyJwk;
}
