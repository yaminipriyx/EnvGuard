/**
 * Unit tests for Key Derivation Functions module (HKDF-SHA512 & PBKDF2-HMAC-SHA256).
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Validates determinism, input sensitivity, salt sensitivity, context info sensitivity,
 * key length output accuracy, and parameter bounds.
 * Later phases (Phases 3, 4, 5, 6) rely on these verified invariants.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as kdf from '../src/crypto/kdf.js';

describe('Key Derivation Functions', () => {
  it('HKDF: deterministic behavior for identical inputs', () => {
    const ikm = crypto.randomBytes(32);
    const salt = crypto.randomBytes(16);
    const info = 'envguard-dek-wrap-v1';

    const key1 = kdf.hkdfSha512(ikm, salt, info, 32);
    const key2 = kdf.hkdfSha512(ikm, salt, info, 32);

    assert.equal(key1.length, 32);
    assert.ok(key1.equals(key2));
  });

  it('HKDF: input sensitivity produces distinct keys when IKM changes', () => {
    const ikm1 = crypto.randomBytes(32);
    const ikm2 = crypto.randomBytes(32);
    const salt = Buffer.alloc(0);
    const info = 'envguard-dek-wrap-v1';

    const key1 = kdf.hkdfSha512(ikm1, salt, info, 32);
    const key2 = kdf.hkdfSha512(ikm2, salt, info, 32);

    assert.ok(!key1.equals(key2));
  });

  it('HKDF: salt sensitivity produces distinct keys when salt changes', () => {
    const ikm = crypto.randomBytes(32);
    const salt1 = crypto.randomBytes(16);
    const salt2 = crypto.randomBytes(16);
    const info = 'envguard-client-signing-v1';

    const key1 = kdf.hkdfSha512(ikm, salt1, info, 64);
    const key2 = kdf.hkdfSha512(ikm, salt2, info, 64);

    assert.equal(key1.length, 64);
    assert.equal(key2.length, 64);
    assert.ok(!key1.equals(key2));
  });

  it('HKDF: info sensitivity produces distinct keys for different domain strings', () => {
    const ikm = crypto.randomBytes(32);
    const salt = Buffer.alloc(0);

    const key1 = kdf.hkdfSha512(ikm, salt, 'envguard-dek-wrap-v1', 32);
    const key2 = kdf.hkdfSha512(ikm, salt, 'envguard-client-signing-v1', 32);

    assert.ok(!key1.equals(key2));
  });

  it('HKDF: rejects malformed or invalid inputs', () => {
    const ikm = crypto.randomBytes(32);
    const salt = Buffer.alloc(0);

    assert.throws(
      () => {
        kdf.hkdfSha512(Buffer.alloc(0), salt, 'info', 32);
      },
      /Invalid IKM: must be a non-empty Buffer/
    );

    assert.throws(
      () => {
        kdf.hkdfSha512(ikm, 'not-a-buffer', 'info', 32);
      },
      /Invalid salt: must be a Buffer/
    );

    assert.throws(
      () => {
        kdf.hkdfSha512(ikm, salt, 12345, 32);
      },
      /Invalid info: must be a string or Buffer/
    );

    assert.throws(
      () => {
        kdf.hkdfSha512(ikm, salt, 'info', 0);
      },
      /Invalid keylen: must be a positive integer/
    );
  });

  it('PBKDF2: deterministic behavior for identical inputs', () => {
    const passphrase = 'correct-horse-battery-staple-secure';
    const salt = crypto.randomBytes(16);
    const iterations = 10000;

    const key1 = kdf.pbkdf2Sha256(passphrase, salt, iterations, 32);
    const key2 = kdf.pbkdf2Sha256(passphrase, salt, iterations, 32);

    assert.equal(key1.length, 32);
    assert.ok(key1.equals(key2));
  });

  it('PBKDF2: passphrase sensitivity produces distinct keys', () => {
    const salt = crypto.randomBytes(16);
    const iterations = 10000;

    const key1 = kdf.pbkdf2Sha256('passphrase-number-one-1234', salt, iterations, 32);
    const key2 = kdf.pbkdf2Sha256('passphrase-number-two-5678', salt, iterations, 32);

    assert.ok(!key1.equals(key2));
  });

  it('PBKDF2: salt sensitivity produces distinct keys', () => {
    const passphrase = 'shared-passphrase-minimum-length';
    const salt1 = crypto.randomBytes(16);
    const salt2 = crypto.randomBytes(16);
    const iterations = 10000;

    const key1 = kdf.pbkdf2Sha256(passphrase, salt1, iterations, 32);
    const key2 = kdf.pbkdf2Sha256(passphrase, salt2, iterations, 32);

    assert.ok(!key1.equals(key2));
  });

  it('PBKDF2: enforces minimum passphrase length and parameter validation', () => {
    const salt = crypto.randomBytes(16);

    assert.throws(
      () => {
        kdf.pbkdf2Sha256('short-pass', salt, 1000, 32);
      },
      /Passphrase must be at least 12 characters/
    );

    assert.throws(
      () => {
        kdf.pbkdf2Sha256('valid-passphrase-length', crypto.randomBytes(10), 1000, 32);
      },
      /Invalid salt: must be a Buffer of at least 16 bytes/
    );

    assert.throws(
      () => {
        kdf.pbkdf2Sha256('valid-passphrase-length', salt, -5, 32);
      },
      /Invalid iterations: must be a positive integer/
    );
  });
});
