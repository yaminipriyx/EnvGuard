/**
 * Elliptic Curve Diffie-Hellman module using X25519.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Implements native X25519 keypair generation, JWK representation handling,
 * public-key integrity verification, fingerprint calculation, and constant-time
 * shared-secret derivation with all-zero reject guards.
 * Later phases (Phases 3, 4, 5, 6) will compose this module for developer identity,
 * DEK wrapping, and access management.
 */

import crypto from 'node:crypto';

/**
 * Validate that an object has the required X25519 public key JWK structure.
 *
 * @param {object} jwk - The public key JWK to validate.
 */
function validatePublicKeyJwk(jwk) {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new TypeError('Invalid public key: must be a non-null object');
  }

  if (jwk.kty !== 'OKP') {
    throw new TypeError('Invalid public key: kty must be "OKP"');
  }

  if (jwk.crv !== 'X25519') {
    throw new TypeError('Invalid public key: crv must be "X25519"');
  }

  if (typeof jwk.x !== 'string' || jwk.x.length === 0) {
    throw new TypeError('Invalid public key: x coordinate must be a non-empty string');
  }

  const rawBytes = Buffer.from(jwk.x, 'base64url');
  if (rawBytes.length !== 32) {
    throw new TypeError('Invalid public key: x coordinate must decode to exactly 32 bytes');
  }
}

/**
 * Validate that an object has the required X25519 private key JWK structure.
 *
 * @param {object} jwk - The private key JWK to validate.
 */
function validatePrivateKeyJwk(jwk) {
  if (typeof jwk !== 'object' || jwk === null) {
    throw new TypeError('Invalid private key: must be a non-null object');
  }

  if (jwk.kty !== 'OKP') {
    throw new TypeError('Invalid private key: kty must be "OKP"');
  }

  if (jwk.crv !== 'X25519') {
    throw new TypeError('Invalid private key: crv must be "X25519"');
  }

  if (typeof jwk.d !== 'string' || jwk.d.length === 0) {
    throw new TypeError('Invalid private key: d coordinate must be a non-empty string');
  }

  const rawBytes = Buffer.from(jwk.d, 'base64url');
  if (rawBytes.length !== 32) {
    throw new TypeError('Invalid private key: d coordinate must decode to exactly 32 bytes');
  }
}

/**
 * Generate a new X25519 asymmetric key pair represented as JWK objects.
 *
 * @returns {{publicKey: object, privateKey: object}} The generated public and private key JWKs.
 */
export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');

  const pubJwk = publicKey.export({ format: 'jwk' });
  const privJwk = privateKey.export({ format: 'jwk' });

  return {
    publicKey: pubJwk,
    privateKey: privJwk
  };
}

/**
 * Derive the corresponding public key JWK from an X25519 private key JWK.
 *
 * @param {object} privateKeyJwk - The private key JWK.
 * @returns {object} The derived public key JWK.
 */
export function derivePublicKey(privateKeyJwk) {
  validatePrivateKeyJwk(privateKeyJwk);

  const privKeyObject = crypto.createPrivateKey({
    key: privateKeyJwk,
    format: 'jwk'
  });

  const pubKeyObject = crypto.createPublicKey(privKeyObject);
  return pubKeyObject.export({ format: 'jwk' });
}

/**
 * Verify that a public key matches the public component derived from a private key.
 *
 * @param {object} privateKeyJwk - The private key JWK.
 * @param {object} publicKeyJwk - The expected public key JWK.
 * @returns {boolean} True if the public key corresponds to the private key.
 */
export function verifyKeyPair(privateKeyJwk, publicKeyJwk) {
  validatePrivateKeyJwk(privateKeyJwk);
  validatePublicKeyJwk(publicKeyJwk);

  const derived = derivePublicKey(privateKeyJwk);

  if (derived.kty !== publicKeyJwk.kty) {
    return false;
  }
  if (derived.crv !== publicKeyJwk.crv) {
    return false;
  }
  if (derived.x !== publicKeyJwk.x) {
    return false;
  }

  return true;
}

/**
 * Calculate the SHA-256 fingerprint of an X25519 public key.
 *
 * @param {object} publicKeyJwk - The public key JWK.
 * @returns {string} The formatted fingerprint string (e.g. SHA256:<hex>).
 */
export function calculateFingerprint(publicKeyJwk) {
  validatePublicKeyJwk(publicKeyJwk);

  const rawBytes = Buffer.from(publicKeyJwk.x, 'base64url');
  const digest = crypto.createHash('sha256').update(rawBytes).digest('hex');

  return `SHA256:${digest}`;
}

/**
 * Perform X25519 ECDH shared secret derivation between a private key and public key.
 *
 * @param {object} privateKeyJwk - The recipient/sender private key JWK.
 * @param {object} publicKeyJwk - The counterparty public key JWK.
 * @returns {Buffer} The derived 32-byte shared secret.
 */
export function deriveSharedSecret(privateKeyJwk, publicKeyJwk) {
  validatePrivateKeyJwk(privateKeyJwk);
  validatePublicKeyJwk(publicKeyJwk);

  let privKeyObject;
  let pubKeyObject;
  try {
    privKeyObject = crypto.createPrivateKey({
      key: privateKeyJwk,
      format: 'jwk'
    });
    pubKeyObject = crypto.createPublicKey({
      key: publicKeyJwk,
      format: 'jwk'
    });
  } catch (err) {
    throw new Error('Failed to create cryptographic key objects from provided JWKs');
  }

  let sharedSecret;
  try {
    sharedSecret = crypto.diffieHellman({
      privateKey: privKeyObject,
      publicKey: pubKeyObject
    });
  } catch (err) {
    throw new Error('ECDH key agreement computation failed');
  }

  if (sharedSecret.length !== 32) {
    throw new Error('Invalid shared secret length: expected 32 bytes');
  }

  const zeroBuffer = Buffer.alloc(32, 0);
  if (crypto.timingSafeEqual(sharedSecret, zeroBuffer)) {
    throw new Error('Invalid shared secret: all-zero result rejected');
  }

  return sharedSecret;
}
