/**
 * Key Derivation Functions module implementing HKDF-SHA512 and PBKDF2-HMAC-SHA256.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Provides deterministic key derivation primitives using Node.js native crypto APIs.
 * Supports domain-separated HKDF derivation (envguard-dek-wrap-v1, envguard-client-signing-v1)
 * and high-iteration PBKDF2 master key derivation.
 * Later phases (Phases 3, 4, 5, 6) will compose this module for DEK wrapping,
 * client request signing, and local key file encryption.
 */

import crypto from 'node:crypto';

/**
 * Derive cryptographic key material using HKDF with SHA-512.
 *
 * @param {Buffer} ikm - Initial Keying Material.
 * @param {Buffer} salt - Salt buffer (can be empty Buffer.alloc(0) or non-empty).
 * @param {string|Buffer} info - Context and application-specific domain separation info.
 * @param {number} keylen - Desired output key length in bytes.
 * @returns {Buffer} The derived key material buffer.
 */
export function hkdfSha512(ikm, salt, info, keylen) {
  if (!Buffer.isBuffer(ikm) || ikm.length === 0) {
    throw new TypeError('Invalid IKM: must be a non-empty Buffer');
  }

  if (!Buffer.isBuffer(salt)) {
    throw new TypeError('Invalid salt: must be a Buffer');
  }

  let infoBuffer;
  if (Buffer.isBuffer(info)) {
    infoBuffer = info;
  } else if (typeof info === 'string') {
    infoBuffer = Buffer.from(info, 'utf8');
  } else {
    throw new TypeError('Invalid info: must be a string or Buffer');
  }

  if (typeof keylen !== 'number' || keylen <= 0 || !Number.isInteger(keylen)) {
    throw new TypeError('Invalid keylen: must be a positive integer');
  }

  const derived = crypto.hkdfSync('sha512', ikm, salt, infoBuffer, keylen);
  return Buffer.from(derived);
}

/**
 * Derive a key encryption key using PBKDF2 with HMAC-SHA256.
 *
 * @param {string|Buffer} passphrase - Master passphrase (minimum 12 characters).
 * @param {Buffer} salt - Salt buffer (minimum 16 bytes).
 * @param {number} iterations - Iteration count (minimum 600,000 for standard security).
 * @param {number} keylen - Desired derived key length in bytes (default 32 bytes).
 * @returns {Buffer} The derived key buffer.
 */
export function pbkdf2Sha256(passphrase, salt, iterations, keylen) {
  let passphraseBuffer;
  if (Buffer.isBuffer(passphrase)) {
    if (passphrase.length < 12) {
      throw new TypeError('Passphrase must be at least 12 characters in length');
    }
    passphraseBuffer = passphrase;
  } else if (typeof passphrase === 'string') {
    if (passphrase.length < 12) {
      throw new TypeError('Passphrase must be at least 12 characters in length');
    }
    passphraseBuffer = Buffer.from(passphrase, 'utf8');
  } else {
    throw new TypeError('Invalid passphrase: must be a string or Buffer');
  }

  if (!Buffer.isBuffer(salt) || salt.length < 16) {
    throw new TypeError('Invalid salt: must be a Buffer of at least 16 bytes');
  }

  if (typeof iterations !== 'number' || iterations <= 0 || !Number.isInteger(iterations)) {
    throw new TypeError('Invalid iterations: must be a positive integer');
  }

  if (typeof keylen !== 'number' || keylen <= 0 || !Number.isInteger(keylen)) {
    throw new TypeError('Invalid keylen: must be a positive integer');
  }

  const derived = crypto.pbkdf2Sync(passphraseBuffer, salt, iterations, keylen, 'sha256');
  return Buffer.from(derived);
}
