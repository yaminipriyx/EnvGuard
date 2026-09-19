/**
 * Unit tests for HMAC-SHA512 message authentication module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Validates HMAC generation, constant-time signature verification, sensitivity to key
 * or message alteration, signature tampering detection, and length check safety.
 * Later phases (Phases 3, 4, 5, 6) rely on these verified invariants.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as hmac from '../src/crypto/hmac.js';

describe('HMAC-SHA512 Primitives', () => {
  it('generates 128-character hex HMAC and verifies matching signature', () => {
    const key = crypto.randomBytes(64);
    const message = 'GET\n/api/v1/vault/test/secrets\n2026-09-19T10:00:00.000Z\nnonce123\nbodyhash';

    const signature = hmac.generateHmacSha512(key, message);
    assert.equal(signature.length, 128);

    const isValid = hmac.verifyHmacSha512(key, message, signature);
    assert.equal(isValid, true);
  });

  it('fails verification when message is modified', () => {
    const key = crypto.randomBytes(64);
    const originalMessage = 'CANONICAL_STRING_A';
    const tamperedMessage = 'CANONICAL_STRING_B';

    const signature = hmac.generateHmacSha512(key, originalMessage);
    const isValid = hmac.verifyHmacSha512(key, tamperedMessage, signature);

    assert.equal(isValid, false);
  });

  it('fails verification when key is modified', () => {
    const key1 = crypto.randomBytes(64);
    const key2 = crypto.randomBytes(64);
    const message = 'CANONICAL_STRING';

    const signature = hmac.generateHmacSha512(key1, message);
    const isValid = hmac.verifyHmacSha512(key2, message, signature);

    assert.equal(isValid, false);
  });

  it('fails verification when signature is modified', () => {
    const key = crypto.randomBytes(64);
    const message = 'CANONICAL_STRING';

    const signature = hmac.generateHmacSha512(key, message);
    let charToFlip = '0';
    if (signature[0] === '0') {
      charToFlip = '1';
    }
    const corruptedSignature = charToFlip + signature.slice(1);

    const isValid = hmac.verifyHmacSha512(key, message, corruptedSignature);
    assert.equal(isValid, false);
  });

  it('safely handles wrong signature length without error', () => {
    const key = crypto.randomBytes(64);
    const message = 'CANONICAL_STRING';

    assert.equal(hmac.verifyHmacSha512(key, message, 'short'), false);
    assert.equal(hmac.verifyHmacSha512(key, message, ''), false);
    assert.equal(hmac.verifyHmacSha512(key, message, 'a'.repeat(64)), false);
    assert.equal(hmac.verifyHmacSha512(key, message, 'a'.repeat(256)), false);
    assert.equal(hmac.verifyHmacSha512(key, message, null), false);
    assert.equal(hmac.verifyHmacSha512(key, message, 12345), false);
  });

  it('handles empty message body appropriately', () => {
    const key = crypto.randomBytes(64);
    const emptyMessage = '';

    const signature = hmac.generateHmacSha512(key, emptyMessage);
    assert.equal(signature.length, 128);

    const isValid = hmac.verifyHmacSha512(key, emptyMessage, signature);
    assert.equal(isValid, true);
  });
});
