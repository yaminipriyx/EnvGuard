/**
 * HMAC-SHA512 message authentication module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Implements HMAC generation and constant-time signature verification
 * with strict buffer length validation before comparison.
 * Later phases (Phases 3, 4, 5, 6) will compose this module for request
 * authentication between the CLI client and Vault Server.
 */

import crypto from 'node:crypto';

/**
 * Generate an HMAC-SHA512 signature in hexadecimal format.
 *
 * @param {Buffer|string} key - The HMAC secret key (typically 64-byte derived signing key).
 * @param {Buffer|string} data - The message or canonical string to authenticate.
 * @returns {string} The 64-byte HMAC signature encoded as a 128-character hex string.
 */
export function generateHmacSha512(key, data) {
  let keyBuffer;
  if (Buffer.isBuffer(key)) {
    if (key.length === 0) {
      throw new TypeError('Invalid key: cannot be empty');
    }
    keyBuffer = key;
  } else if (typeof key === 'string') {
    if (key.length === 0) {
      throw new TypeError('Invalid key: cannot be empty');
    }
    keyBuffer = Buffer.from(key, 'utf8');
  } else {
    throw new TypeError('Invalid key: must be a Buffer or string');
  }

  let dataBuffer;
  if (Buffer.isBuffer(data)) {
    dataBuffer = data;
  } else if (typeof data === 'string') {
    dataBuffer = Buffer.from(data, 'utf8');
  } else {
    throw new TypeError('Invalid data: must be a Buffer or string');
  }

  return crypto.createHmac('sha512', keyBuffer).update(dataBuffer).digest('hex');
}

/**
 * Verify an HMAC-SHA512 signature using constant-time comparison.
 *
 * @param {Buffer|string} key - The HMAC secret key.
 * @param {Buffer|string} data - The message or canonical string to verify.
 * @param {string} expectedSignatureHex - The expected hex-encoded HMAC signature.
 * @returns {boolean} True if the signature matches, false otherwise.
 */
export function verifyHmacSha512(key, data, expectedSignatureHex) {
  if (typeof expectedSignatureHex !== 'string') {
    return false;
  }

  if (expectedSignatureHex.length !== 128) {
    return false;
  }

  const hexRegex = /^[0-9a-fA-F]{128}$/;
  if (!hexRegex.test(expectedSignatureHex)) {
    return false;
  }

  let expectedBuffer;
  try {
    expectedBuffer = Buffer.from(expectedSignatureHex, 'hex');
  } catch (err) {
    return false;
  }

  let computedHex;
  try {
    computedHex = generateHmacSha512(key, data);
  } catch (err) {
    return false;
  }

  const computedBuffer = Buffer.from(computedHex, 'hex');

  if (expectedBuffer.length !== computedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(computedBuffer, expectedBuffer);
}
