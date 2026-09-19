/**
 * Unit tests for X25519 ECDH key agreement and representation module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Validates keypair generation, JWK structure enforcement, mutual shared secret agreement,
 * keypair integrity verification, and fingerprint calculation.
 * Later phases (Phases 3, 4, 5, 6) rely on these verified invariants.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as ecdh from '../src/crypto/ecdh.js';

describe('X25519 ECDH Primitives', () => {
  it('Test A: two generated key pairs establish the identical shared secret from both perspectives', () => {
    const alice = ecdh.generateKeyPair();
    const bob = ecdh.generateKeyPair();

    const aliceShared = ecdh.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const bobShared = ecdh.deriveSharedSecret(bob.privateKey, alice.publicKey);

    assert.equal(aliceShared.length, 32);
    assert.equal(bobShared.length, 32);
    assert.ok(aliceShared.equals(bobShared));
  });

  it('Test B: different key pairs produce different shared secrets', () => {
    const alice = ecdh.generateKeyPair();
    const bob = ecdh.generateKeyPair();
    const charlie = ecdh.generateKeyPair();

    const secret1 = ecdh.deriveSharedSecret(alice.privateKey, bob.publicKey);
    const secret2 = ecdh.deriveSharedSecret(alice.privateKey, charlie.publicKey);

    assert.ok(!secret1.equals(secret2));
  });

  it('Test C: invalid JWK structures are rejected', () => {
    const validPair = ecdh.generateKeyPair();

    assert.throws(
      () => {
        ecdh.deriveSharedSecret(null, validPair.publicKey);
      },
      /Invalid private key: must be a non-null object/
    );

    assert.throws(
      () => {
        ecdh.deriveSharedSecret({ kty: 'RSA', crv: 'X25519', d: 'abc' }, validPair.publicKey);
      },
      /kty must be "OKP"/
    );

    assert.throws(
      () => {
        ecdh.deriveSharedSecret({ kty: 'OKP', crv: 'Ed25519', d: 'abc' }, validPair.publicKey);
      },
      /crv must be "X25519"/
    );

    assert.throws(
      () => {
        ecdh.deriveSharedSecret(validPair.privateKey, { kty: 'OKP', crv: 'X25519', x: 'short' });
      },
      /x coordinate must decode to exactly 32 bytes/
    );
  });

  it('Test D: private and public key correspondence verification', () => {
    const keyPair1 = ecdh.generateKeyPair();
    const keyPair2 = ecdh.generateKeyPair();

    const matches = ecdh.verifyKeyPair(keyPair1.privateKey, keyPair1.publicKey);
    assert.equal(matches, true);

    const mismatches = ecdh.verifyKeyPair(keyPair1.privateKey, keyPair2.publicKey);
    assert.equal(mismatches, false);
  });

  it('Test E: derived public key from private key matches generated public key', () => {
    const keyPair = ecdh.generateKeyPair();
    const derivedPub = ecdh.derivePublicKey(keyPair.privateKey);

    assert.equal(derivedPub.kty, 'OKP');
    assert.equal(derivedPub.crv, 'X25519');
    assert.equal(derivedPub.x, keyPair.publicKey.x);
  });

  it('Test F: generated keys conform to the canonical JWK specification', () => {
    const { publicKey, privateKey } = ecdh.generateKeyPair();

    assert.equal(publicKey.kty, 'OKP');
    assert.equal(publicKey.crv, 'X25519');
    assert.equal(typeof publicKey.x, 'string');
    assert.equal(Buffer.from(publicKey.x, 'base64url').length, 32);

    assert.equal(privateKey.kty, 'OKP');
    assert.equal(privateKey.crv, 'X25519');
    assert.equal(typeof privateKey.x, 'string');
    assert.equal(typeof privateKey.d, 'string');
    assert.equal(Buffer.from(privateKey.d, 'base64url').length, 32);
  });

  it('Test G: calculateFingerprint produces expected SHA256 prefix format', () => {
    const { publicKey } = ecdh.generateKeyPair();
    const fingerprint = ecdh.calculateFingerprint(publicKey);

    assert.ok(fingerprint.startsWith('SHA256:'));
    assert.equal(fingerprint.length, 7 + 64);

    const secondCalc = ecdh.calculateFingerprint(publicKey);
    assert.equal(fingerprint, secondCalc);
  });
});
