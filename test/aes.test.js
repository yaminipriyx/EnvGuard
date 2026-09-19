/**
 * Unit tests for AES-256-GCM authenticated encryption module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Validates round-trip encryption, key-length enforcement, authentication tag verification,
 * and fail-closed behavior on ciphertext/tag/IV/AAD tampering.
 * Later phases (Phases 3, 4, 5, 6) rely on these verified invariants.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as aes from '../src/crypto/aes.js';

describe('AES-256-GCM Primitives', () => {
  it('Test A: round trip encryption and decryption recovers original plaintext', () => {
    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from('DATABASE_URL=postgres://user:pass@localhost:5432/db', 'utf8');
    const aad = Buffer.from('vault-123:1', 'utf8');

    const encrypted = aes.encrypt(plaintext, key, aad);
    assert.equal(encrypted.iv.length, 12);
    assert.equal(encrypted.tag.length, 16);
    assert.ok(encrypted.ciphertext.length > 0);

    const decrypted = aes.decrypt(encrypted.ciphertext, key, encrypted.iv, encrypted.tag, aad);
    assert.equal(decrypted.toString('utf8'), plaintext.toString('utf8'));
  });

  it('Test B: decryption fails when wrong DEK is supplied', () => {
    const key1 = crypto.randomBytes(32);
    const key2 = crypto.randomBytes(32);
    const plaintext = Buffer.from('SECRET_VALUE', 'utf8');
    const aad = 'vault-test:1';

    const encrypted = aes.encrypt(plaintext, key1, aad);
    assert.throws(
      () => {
        aes.decrypt(encrypted.ciphertext, key2, encrypted.iv, encrypted.tag, aad);
      },
      /Decryption failed/
    );
  });

  it('Test C: decryption fails when ciphertext is modified', () => {
    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from('AUTHENTICATED_DATA', 'utf8');
    const aad = 'vault-test:1';

    const encrypted = aes.encrypt(plaintext, key, aad);
    const corruptedCiphertext = Buffer.from(encrypted.ciphertext);
    corruptedCiphertext[0] = corruptedCiphertext[0] ^ 0xff;

    assert.throws(
      () => {
        aes.decrypt(corruptedCiphertext, key, encrypted.iv, encrypted.tag, aad);
      },
      /Decryption failed/
    );
  });

  it('Test D: decryption fails when authentication tag is modified', () => {
    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from('AUTHENTICATED_DATA', 'utf8');
    const aad = 'vault-test:1';

    const encrypted = aes.encrypt(plaintext, key, aad);
    const corruptedTag = Buffer.from(encrypted.tag);
    corruptedTag[0] = corruptedTag[0] ^ 0xff;

    assert.throws(
      () => {
        aes.decrypt(encrypted.ciphertext, key, encrypted.iv, corruptedTag, aad);
      },
      /Decryption failed/
    );
  });

  it('Test E: decryption fails when IV is modified', () => {
    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from('AUTHENTICATED_DATA', 'utf8');
    const aad = 'vault-test:1';

    const encrypted = aes.encrypt(plaintext, key, aad);
    const corruptedIv = Buffer.from(encrypted.iv);
    corruptedIv[0] = corruptedIv[0] ^ 0xff;

    assert.throws(
      () => {
        aes.decrypt(encrypted.ciphertext, key, corruptedIv, encrypted.tag, aad);
      },
      /Decryption failed/
    );
  });

  it('Test F: decryption fails when AAD is modified', () => {
    const key = crypto.randomBytes(32);
    const plaintext = Buffer.from('AUTHENTICATED_DATA', 'utf8');
    const aad = 'vault-test:1';
    const tamperedAad = 'vault-test:2';

    const encrypted = aes.encrypt(plaintext, key, aad);

    assert.throws(
      () => {
        aes.decrypt(encrypted.ciphertext, key, encrypted.iv, encrypted.tag, tamperedAad);
      },
      /Decryption failed/
    );
  });

  it('Test G: handles string and buffer plaintexts consistently', () => {
    const key = crypto.randomBytes(32);
    const stringMessage = 'HELLO_ENVGUARD';
    const encrypted = aes.encrypt(stringMessage, key);
    const decrypted = aes.decrypt(encrypted.ciphertext, key, encrypted.iv, encrypted.tag);

    assert.equal(decrypted.toString('utf8'), stringMessage);
  });

  it('Test H: malformed key length is rejected', () => {
    const shortKey = crypto.randomBytes(16);
    const longKey = crypto.randomBytes(64);
    const plaintext = Buffer.from('test', 'utf8');

    assert.throws(
      () => {
        aes.encrypt(plaintext, shortKey);
      },
      /Invalid key: must be a 32-byte Buffer/
    );

    assert.throws(
      () => {
        aes.encrypt(plaintext, longKey);
      },
      /Invalid key: must be a 32-byte Buffer/
    );
  });

  it('Test I: malformed parameter types are rejected', () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const tag = crypto.randomBytes(16);
    const ciphertext = crypto.randomBytes(32);

    assert.throws(
      () => {
        aes.encrypt(12345, key);
      },
      /Invalid plaintext: must be a Buffer or string/
    );

    assert.throws(
      () => {
        aes.decrypt('not-a-buffer', key, iv, tag);
      },
      /Invalid ciphertext: must be a Buffer/
    );

    assert.throws(
      () => {
        aes.decrypt(ciphertext, key, crypto.randomBytes(10), tag);
      },
      /Invalid IV: must be a 12-byte Buffer/
    );

    assert.throws(
      () => {
        aes.decrypt(ciphertext, key, iv, crypto.randomBytes(8));
      },
      /Invalid auth tag: must be a 16-byte Buffer/
    );
  });
});
