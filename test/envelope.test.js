/**
 * Unit tests for cryptographic envelope module.
 *
 * This file is part of Phase 2 (Core Cryptography).
 * Validates secret blob envelopes, wrapped DEK envelopes, private key envelopes,
 * AAD enforcement contracts, parameter tampering rejection, and recipient isolation.
 * Later phases (Phases 3, 4, 5, 6) rely on these verified invariants.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as envelope from '../src/crypto/envelope.js';
import * as ecdh from '../src/crypto/ecdh.js';

describe('Cryptographic Envelopes', () => {
  describe('Secret Blob Envelope', () => {
    it('round trip: creates and opens valid secret envelope', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-1234567890abcdef';
      const dekVersion = 1;
      const secretPayload = JSON.stringify({
        API_KEY: 'secret-token-value',
        DATABASE_URL: 'postgres://db.internal:5432/app'
      });

      const env = envelope.createSecretEnvelope(secretPayload, dek, vaultId, dekVersion);

      assert.equal(env.algorithm, 'aes-256-gcm');
      assert.equal(env.dekVersion, 1);
      assert.equal(env.aad, `${vaultId}:1`);
      assert.equal(typeof env.iv, 'string');
      assert.equal(typeof env.tag, 'string');
      assert.equal(typeof env.ciphertext, 'string');

      const decrypted = envelope.openSecretEnvelope(env, dek, vaultId, dekVersion);
      assert.equal(decrypted.toString('utf8'), secretPayload);
    });

    it('tampering: rejects tampered ciphertext', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-123';
      const dekVersion = 1;
      const env = envelope.createSecretEnvelope('DATA', dek, vaultId, dekVersion);

      let flippedChar = '0';
      if (env.ciphertext[0] === '0') {
        flippedChar = '1';
      }
      env.ciphertext = flippedChar + env.ciphertext.slice(1);

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, vaultId, dekVersion);
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered authentication tag', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-123';
      const dekVersion = 1;
      const env = envelope.createSecretEnvelope('DATA', dek, vaultId, dekVersion);

      let flippedChar = '0';
      if (env.tag[0] === '0') {
        flippedChar = '1';
      }
      env.tag = flippedChar + env.tag.slice(1);

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, vaultId, dekVersion);
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered IV', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-123';
      const dekVersion = 1;
      const env = envelope.createSecretEnvelope('DATA', dek, vaultId, dekVersion);

      let flippedChar = '0';
      if (env.iv[0] === '0') {
        flippedChar = '1';
      }
      env.iv = flippedChar + env.iv.slice(1);

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, vaultId, dekVersion);
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered stored AAD', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-123';
      const dekVersion = 1;
      const env = envelope.createSecretEnvelope('DATA', dek, vaultId, dekVersion);

      env.aad = `${vaultId}:2`;

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, vaultId, dekVersion);
        },
        /AAD mismatch/
      );
    });

    it('tampering: rejects mismatched expected DEK version', () => {
      const dek = crypto.randomBytes(32);
      const vaultId = 'proj-dev-123';
      const env = envelope.createSecretEnvelope('DATA', dek, vaultId, 1);

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, vaultId, 2);
        },
        /DEK version mismatch/
      );
    });

    it('tampering: rejects mismatched expected vault ID', () => {
      const dek = crypto.randomBytes(32);
      const env = envelope.createSecretEnvelope('DATA', dek, 'vault-A', 1);

      assert.throws(
        () => {
          envelope.openSecretEnvelope(env, dek, 'vault-B', 1);
        },
        /AAD mismatch/
      );
    });
  });

  describe('Wrapped DEK Envelope', () => {
    it('round trip: wraps DEK for recipient and recipient successfully unwraps it', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();
      const vaultId = 'vault-test-wrap';
      const dekVersion = 1;
      const recipientUsername = 'bob';

      const wrappedEnv = envelope.createWrappedDekEnvelope(
        dek,
        recipient.publicKey,
        vaultId,
        dekVersion,
        recipientUsername
      );

      assert.equal(wrappedEnv.algorithm, 'aes-256-gcm');
      assert.equal(wrappedEnv.kdf.algorithm, 'hkdf-sha512');
      assert.equal(wrappedEnv.kdf.info, 'envguard-dek-wrap-v1');
      assert.equal(wrappedEnv.aad, `${vaultId}:${dekVersion}:${recipientUsername}`);

      const unwrappedDek = envelope.openWrappedDekEnvelope(
        wrappedEnv,
        recipient.privateKey,
        vaultId,
        dekVersion,
        recipientUsername
      );

      assert.equal(unwrappedDek.length, 32);
      assert.ok(unwrappedDek.equals(dek));
    });

    it('recipient isolation: recipient B cannot unwrap DEK wrapped for recipient A', () => {
      const dek = crypto.randomBytes(32);
      const alice = ecdh.generateKeyPair();
      const bob = ecdh.generateKeyPair();
      const vaultId = 'vault-test-isolation';
      const dekVersion = 1;

      const wrappedForAlice = envelope.createWrappedDekEnvelope(
        dek,
        alice.publicKey,
        vaultId,
        dekVersion,
        'alice'
      );

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(wrappedForAlice, bob.privateKey, vaultId, dekVersion, 'alice');
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered encrypted DEK ciphertext', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();
      const vaultId = 'vault-test';
      const dekVersion = 1;
      const username = 'bob';

      const env = envelope.createWrappedDekEnvelope(dek, recipient.publicKey, vaultId, dekVersion, username);

      let flippedChar = '0';
      if (env.encryptedDek[0] === '0') {
        flippedChar = '1';
      }
      env.encryptedDek = flippedChar + env.encryptedDek.slice(1);

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, vaultId, dekVersion, username);
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered ephemeral public key', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();
      const otherPair = ecdh.generateKeyPair();
      const vaultId = 'vault-test';
      const dekVersion = 1;
      const username = 'bob';

      const env = envelope.createWrappedDekEnvelope(dek, recipient.publicKey, vaultId, dekVersion, username);
      env.ephemeralPublicKey = otherPair.publicKey;

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, vaultId, dekVersion, username);
        },
        /Decryption failed/
      );
    });

    it('tampering: rejects tampered wrapped DEK AAD', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();
      const vaultId = 'vault-test';
      const dekVersion = 1;
      const username = 'bob';

      const env = envelope.createWrappedDekEnvelope(dek, recipient.publicKey, vaultId, dekVersion, username);
      env.aad = `${vaultId}:${dekVersion}:mallory`;

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, vaultId, dekVersion, username);
        },
        /AAD mismatch/
      );
    });

    it('tampering: rejects mismatched recipient username', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();
      const vaultId = 'vault-test';
      const dekVersion = 1;

      const env = envelope.createWrappedDekEnvelope(dek, recipient.publicKey, vaultId, dekVersion, 'alice');

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, vaultId, dekVersion, 'bob');
        },
        /AAD mismatch/
      );
    });

    it('tampering: rejects mismatched vault ID or DEK version', () => {
      const dek = crypto.randomBytes(32);
      const recipient = ecdh.generateKeyPair();

      const env = envelope.createWrappedDekEnvelope(dek, recipient.publicKey, 'vault-1', 1, 'alice');

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, 'vault-2', 1, 'alice');
        },
        /AAD mismatch/
      );

      assert.throws(
        () => {
          envelope.openWrappedDekEnvelope(env, recipient.privateKey, 'vault-1', 2, 'alice');
        },
        /AAD mismatch/
      );
    });
  });

  describe('Private Key File Envelope', () => {
    it('round trip: encrypts and decrypts private key JWK with passphrase', () => {
      const keyPair = ecdh.generateKeyPair();
      const passphrase = 'my-ultra-secure-master-passphrase';

      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);
      assert.equal(keyEnvelope.version, 1);
      assert.equal(keyEnvelope.kdf.algorithm, 'pbkdf2');
      assert.equal(keyEnvelope.cipher.algorithm, 'aes-256-gcm');
      assert.equal(keyEnvelope.publicKey.x, keyPair.publicKey.x);

      const decryptedPrivateKey = envelope.openPrivateKeyEnvelope(keyEnvelope, passphrase);
      assert.equal(decryptedPrivateKey.kty, 'OKP');
      assert.equal(decryptedPrivateKey.crv, 'X25519');
      assert.equal(decryptedPrivateKey.d, keyPair.privateKey.d);
    });

    it('fails when incorrect passphrase is provided', () => {
      const keyPair = ecdh.generateKeyPair();
      const passphrase = 'correct-passphrase-1234';
      const wrongPassphrase = 'wrong-passphrase-5678';

      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

      assert.throws(
        () => {
          envelope.openPrivateKeyEnvelope(keyEnvelope, wrongPassphrase);
        },
        /Decryption failed/
      );
    });

    it('tampering: fails when private key ciphertext is corrupted', () => {
      const keyPair = ecdh.generateKeyPair();
      const passphrase = 'correct-passphrase-1234';
      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

      let flippedChar = '0';
      if (keyEnvelope.cipher.ciphertext[0] === '0') {
        flippedChar = '1';
      }
      keyEnvelope.cipher.ciphertext = flippedChar + keyEnvelope.cipher.ciphertext.slice(1);

      assert.throws(
        () => {
          envelope.openPrivateKeyEnvelope(keyEnvelope, passphrase);
        },
        /Decryption failed/
      );
    });

    it('tampering: fails when private key auth tag is corrupted', () => {
      const keyPair = ecdh.generateKeyPair();
      const passphrase = 'correct-passphrase-1234';
      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

      let flippedChar = '0';
      if (keyEnvelope.cipher.tag[0] === '0') {
        flippedChar = '1';
      }
      keyEnvelope.cipher.tag = flippedChar + keyEnvelope.cipher.tag.slice(1);

      assert.throws(
        () => {
          envelope.openPrivateKeyEnvelope(keyEnvelope, passphrase);
        },
        /Decryption failed/
      );
    });

    it('tampering: fails when public key does not correspond to private key', () => {
      const keyPair1 = ecdh.generateKeyPair();
      const keyPair2 = ecdh.generateKeyPair();
      const passphrase = 'correct-passphrase-1234';
      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair1.privateKey, passphrase);

      keyEnvelope.publicKey = keyPair2.publicKey;

      assert.throws(
        () => {
          envelope.openPrivateKeyEnvelope(keyEnvelope, passphrase);
        },
        /Private key integrity check failed/
      );
    });

    it('tampering: fails when salt is not exactly 32 hex characters (16 bytes)', () => {
      const keyPair = ecdh.generateKeyPair();
      const passphrase = 'correct-passphrase-1234';
      const keyEnvelope = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

      keyEnvelope.kdf.salt = keyEnvelope.kdf.salt + 'abcd';

      assert.throws(
        () => {
          envelope.openPrivateKeyEnvelope(keyEnvelope, passphrase);
        },
        /Invalid key envelope salt: must be an exact 32-character hex string/
      );
    });
  });
});
