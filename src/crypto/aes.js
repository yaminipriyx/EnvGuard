/**
 * Authenticated symmetric encryption module using AES-256-GCM.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Provides raw AES-256-GCM authenticated encryption and decryption primitives
 * with 256-bit key enforcement, 96-bit random IV generation, 128-bit auth tags,
 * and explicit Additional Authenticated Data (AAD) binding.
 * Later phases (Phases 3, 4, 5, 6) will compose this module for envelope operations,
 * local key protection, and secret payload handling.
 */

import crypto from 'node:crypto';

/**
 * Encrypt a plaintext buffer or string with AES-256-GCM.
 *
 * @param {Buffer|string} plaintext - The plaintext payload to encrypt.
 * @param {Buffer} key - The 32-byte symmetric encryption key.
 * @param {Buffer|string} [aad] - Additional Authenticated Data to bind to the ciphertext.
 * @returns {{ciphertext: Buffer, iv: Buffer, tag: Buffer}} The encrypted payload, IV, and auth tag.
 */
export function encrypt(plaintext, key, aad) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Invalid key: must be a 32-byte Buffer');
  }

  let plaintextBuffer;
  if (Buffer.isBuffer(plaintext)) {
    plaintextBuffer = plaintext;
  } else if (typeof plaintext === 'string') {
    plaintextBuffer = Buffer.from(plaintext, 'utf8');
  } else {
    throw new TypeError('Invalid plaintext: must be a Buffer or string');
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  if (aad !== undefined && aad !== null) {
    let aadBuffer;
    if (Buffer.isBuffer(aad)) {
      aadBuffer = aad;
    } else if (typeof aad === 'string') {
      aadBuffer = Buffer.from(aad, 'utf8');
    } else {
      throw new TypeError('Invalid AAD: must be a Buffer or string');
    }
    cipher.setAAD(aadBuffer);
  }

  const ciphertextPart1 = cipher.update(plaintextBuffer);
  const ciphertextPart2 = cipher.final();
  const ciphertext = Buffer.concat([ciphertextPart1, ciphertextPart2]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext,
    iv: iv,
    tag: tag
  };
}

/**
 * Decrypt an AES-256-GCM ciphertext buffer.
 *
 * @param {Buffer} ciphertext - The encrypted payload.
 * @param {Buffer} key - The 32-byte symmetric key.
 * @param {Buffer} iv - The 12-byte initialization vector.
 * @param {Buffer} tag - The 16-byte authentication tag.
 * @param {Buffer|string} [aad] - Additional Authenticated Data required to match encryption AAD.
 * @returns {Buffer} The authenticated decrypted plaintext.
 */
export function decrypt(ciphertext, key, iv, tag, aad) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Invalid key: must be a 32-byte Buffer');
  }

  if (!Buffer.isBuffer(iv) || iv.length !== 12) {
    throw new TypeError('Invalid IV: must be a 12-byte Buffer');
  }

  if (!Buffer.isBuffer(tag) || tag.length !== 16) {
    throw new TypeError('Invalid auth tag: must be a 16-byte Buffer');
  }

  if (!Buffer.isBuffer(ciphertext)) {
    throw new TypeError('Invalid ciphertext: must be a Buffer');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

  if (aad !== undefined && aad !== null) {
    let aadBuffer;
    if (Buffer.isBuffer(aad)) {
      aadBuffer = aad;
    } else if (typeof aad === 'string') {
      aadBuffer = Buffer.from(aad, 'utf8');
    } else {
      throw new TypeError('Invalid AAD: must be a Buffer or string');
    }
    decipher.setAAD(aadBuffer);
  }

  decipher.setAuthTag(tag);

  let decryptedPart1 = null;
  let decryptedPart2 = null;
  try {
    decryptedPart1 = decipher.update(ciphertext);
    decryptedPart2 = decipher.final();
  } catch (err) {
    if (decryptedPart1 !== null) {
      decryptedPart1.fill(0);
    }
    throw new Error('Decryption failed: authentication tag verification failed or ciphertext corrupted');
  }

  return Buffer.concat([decryptedPart1, decryptedPart2]);
}
