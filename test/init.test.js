/**
 * Comprehensive Test Suite for Phase 4: 'envguard init' & Client Identity.
 *
 * Validates:
 * 1. Identity generation (X25519 keypair, canonical JWK, SHA256 fingerprint).
 * 2. Private key protection (PBKDF2 + AES-256-GCM envelope, decrypts with valid passphrase, fails closed on tamper/wrong passphrase).
 * 3. Keystore persistence (atomic write, credentials format, absence of forbidden fields, rejection of existing keystore).
 * 4. Server registration contract (POST /api/v1/auth/register, verifier transmission, zero token/private-key leakage).
 * 5. Transport security policy (loopback HTTP permitted, non-loopback HTTP rejected).
 * 6. Error handling, input validation, and sanitization (no secrets in error messages or logs).
 *
 * Syntax Rules: Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import crypto from 'node:crypto';
import { Readable, Writable } from 'node:stream';

import { createServer } from '../src/server/server.js';
import * as keystore from '../src/client/keystore.js';
import * as api from '../src/client/api.js';
import * as ecdh from '../src/crypto/ecdh.js';
import * as envelope from '../src/crypto/envelope.js';
import * as kdf from '../src/crypto/kdf.js';
import { executeInit, promptInput } from '../src/commands/init.js';

const TEST_BASE_DIR = path.resolve('test-init-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-12345';

let testServerInstance = null;
let testServerPort = 0;
let testServerUrl = '';

/**
 * Setup a test Vault Server instance for registration tests.
 */
test.before(async () => {
  await fsp.mkdir(TEST_BASE_DIR, { recursive: true });
  const serverStorageDir = path.join(TEST_BASE_DIR, 'vault-server');

  testServerInstance = createServer({
    dataDir: serverStorageDir,
    enrollmentKey: ENROLLMENT_KEY,
    host: '127.0.0.1'
  });

  const addr = await testServerInstance.listen(0, '127.0.0.1');
  testServerPort = addr.port;
  testServerUrl = `http://127.0.0.1:${testServerPort}`;
});

/**
 * Teardown test server and clean up filesystem after all tests.
 */
test.after(async () => {
  if (testServerInstance) {
    await testServerInstance.close();
  }
  if (fs.existsSync(TEST_BASE_DIR)) {
    await fsp.rm(TEST_BASE_DIR, { recursive: true, force: true });
  }
});

test('Phase 4: Identity Generation & Cryptographic Correctness', async (t) => {
  await t.test('generates X25519 keypair in canonical JWK format', () => {
    const keyPair = ecdh.generateKeyPair();
    assert.equal(typeof keyPair, 'object');
    assert.notEqual(keyPair, null);

    const pub = keyPair.publicKey;
    assert.equal(pub.kty, 'OKP');
    assert.equal(pub.crv, 'X25519');
    assert.equal(typeof pub.x, 'string');
    assert.equal(pub.x.length, 43);
    assert.equal(Object.prototype.hasOwnProperty.call(pub, 'd'), false);

    const priv = keyPair.privateKey;
    assert.equal(priv.kty, 'OKP');
    assert.equal(priv.crv, 'X25519');
    assert.equal(typeof priv.d, 'string');
    assert.equal(priv.d.length, 43);
  });

  await t.test('calculates exact SHA256:<hex> public key fingerprint', () => {
    const keyPair = ecdh.generateKeyPair();
    const fingerprint = ecdh.calculateFingerprint(keyPair.publicKey);

    assert.equal(typeof fingerprint, 'string');
    assert.match(fingerprint, /^SHA256:[0-9a-f]{64}$/);

    const rawPubBytes = Buffer.from(keyPair.publicKey.x, 'base64url');
    const expectedHash = crypto.createHash('sha256').update(rawPubBytes).digest('hex');
    assert.equal(fingerprint, `SHA256:${expectedHash}`);
  });

  await t.test('derives K_sign using HKDF-SHA512 domain separation', () => {
    const rawToken = crypto.randomBytes(32);
    const userSalt = crypto.randomBytes(16);
    const kSign = kdf.hkdfSha512(rawToken, userSalt, 'envguard-client-signing-v1', 64);

    assert.equal(Buffer.isBuffer(kSign), true);
    assert.equal(kSign.length, 64);

    // Verify deterministic derivation with same inputs
    const kSignRepeat = kdf.hkdfSha512(rawToken, userSalt, 'envguard-client-signing-v1', 64);
    assert.equal(crypto.timingSafeEqual(kSign, kSignRepeat), true);

    // Verify domain separation alters derived key
    const differentInfo = kdf.hkdfSha512(rawToken, userSalt, 'different-domain-info', 64);
    assert.equal(crypto.timingSafeEqual(kSign, differentInfo), false);
  });
});

test('Phase 4: Private Key Protection & Envelope Authentication', async (t) => {
  const passphrase = 'correct-master-passphrase-12345';
  const wrongPassphrase = 'wrong-master-passphrase-99999';

  await t.test('encrypts private key into envelope without persisting plaintext d', () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

    assert.equal(env.version, 1);
    assert.equal(env.kdf.algorithm, 'pbkdf2');
    assert.equal(env.kdf.digest, 'sha256');
    assert.equal(env.kdf.iterations, 600000);
    assert.match(env.kdf.salt, /^[0-9a-f]{32}$/);
    assert.equal(env.cipher.algorithm, 'aes-256-gcm');
    assert.match(env.cipher.iv, /^[0-9a-f]{24}$/);
    assert.match(env.cipher.tag, /^[0-9a-f]{32}$/);
    assert.match(env.cipher.ciphertext, /^[0-9a-f]+$/);

    // Ensure raw private key does not appear anywhere in serialized envelope
    const serialized = JSON.stringify(env);
    assert.equal(serialized.includes(keyPair.privateKey.d), false);
  });

  await t.test('decrypts successfully with valid master passphrase', () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);
    const recoveredPrivKey = envelope.openPrivateKeyEnvelope(env, passphrase);

    assert.equal(recoveredPrivKey.kty, 'OKP');
    assert.equal(recoveredPrivKey.crv, 'X25519');
    assert.equal(recoveredPrivKey.d, keyPair.privateKey.d);
  });

  await t.test('fails closed when incorrect passphrase is supplied', () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

    assert.throws(() => {
      envelope.openPrivateKeyEnvelope(env, wrongPassphrase);
    }, /Decryption failed: authentication tag verification failed or ciphertext corrupted/);
  });

  await t.test('fails closed when ciphertext is tampered', () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

    const tampered = JSON.parse(JSON.stringify(env));
    const rawCipher = Buffer.from(tampered.cipher.ciphertext, 'hex');
    rawCipher[0] = rawCipher[0] ^ 0xff;
    tampered.cipher.ciphertext = rawCipher.toString('hex');

    assert.throws(() => {
      envelope.openPrivateKeyEnvelope(tampered, passphrase);
    }, /Decryption failed: authentication tag verification failed or ciphertext corrupted/);
  });

  await t.test('fails closed when auth tag is tampered', () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, passphrase);

    const tampered = JSON.parse(JSON.stringify(env));
    const rawTag = Buffer.from(tampered.cipher.tag, 'hex');
    rawTag[0] = rawTag[0] ^ 0xff;
    tampered.cipher.tag = rawTag.toString('hex');

    assert.throws(() => {
      envelope.openPrivateKeyEnvelope(tampered, passphrase);
    }, /Decryption failed: authentication tag verification failed or ciphertext corrupted/);
  });
});

test('Phase 4: Keystore Atomic Persistence & Integrity', async (t) => {
  const ksDir = path.join(TEST_BASE_DIR, 'keystore-test-1');

  await t.test('isInitialized returns false before write, true after write', async () => {
    assert.equal(keystore.isInitialized(ksDir), false);

    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, 'test-passphrase-12345');
    const creds = {
      version: 1,
      username: 'alice',
      apiToken: crypto.randomBytes(32).toString('hex'),
      userSalt: crypto.randomBytes(16).toString('hex')
    };

    await keystore.atomicWriteKeystore(ksDir, env, creds);
    assert.equal(keystore.isInitialized(ksDir), true);
  });

  await t.test('atomicWriteKeystore creates key.enc and credentials.json', async () => {
    const keyPath = keystore.getKeyFilePath(ksDir);
    const credPath = keystore.getCredentialsFilePath(ksDir);

    assert.equal(fs.existsSync(keyPath), true);
    assert.equal(fs.existsSync(credPath), true);

    const loadedCreds = await keystore.loadCredentials(ksDir);
    assert.equal(loadedCreds.version, 1);
    assert.equal(loadedCreds.username, 'alice');
    assert.equal(loadedCreds.apiToken.length, 64);
    assert.equal(loadedCreds.userSalt.length, 32);

    const loadedEnv = await keystore.loadKeyEnvelope(ksDir);
    assert.equal(loadedEnv.version, 1);
    assert.equal(loadedEnv.publicKey.kty, 'OKP');
    assert.equal(loadedEnv.publicKey.crv, 'X25519');
  });

  await t.test('refuses to overwrite existing keystore', async () => {
    const keyPair = ecdh.generateKeyPair();
    const env = envelope.createPrivateKeyEnvelope(keyPair.privateKey, 'test-passphrase-12345');
    const creds = {
      version: 1,
      username: 'alice_duplicate',
      apiToken: crypto.randomBytes(32).toString('hex'),
      userSalt: crypto.randomBytes(16).toString('hex')
    };

    await assert.rejects(async () => {
      await keystore.atomicWriteKeystore(ksDir, env, creds);
    }, /Identity already exists: refusing to overwrite existing keystore/);
  });

  await t.test('credentials.json strictly excludes forbidden sensitive fields', async () => {
    const loadedCreds = await keystore.loadCredentials(ksDir);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedCreds, 'passphrase'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedCreds, 'privateKey'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedCreds, 'd'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedCreds, 'authVerifier'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedCreds, 'dek'), false);
  });

  await t.test('key.enc strictly excludes forbidden unencrypted private key material', async () => {
    const loadedEnv = await keystore.loadKeyEnvelope(ksDir);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedEnv, 'privateKey'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedEnv, 'rawPrivateKey'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(loadedEnv, 'd'), false);
  });

  await t.test('loadCredentials rejects corrupted credentials file', async () => {
    const badKsDir = path.join(TEST_BASE_DIR, 'keystore-bad-creds');
    await fsp.mkdir(badKsDir, { recursive: true });
    const credPath = keystore.getCredentialsFilePath(badKsDir);
    await fsp.writeFile(credPath, 'NOT_VALID_JSON{{{', 'utf8');

    await assert.rejects(async () => {
      await keystore.loadCredentials(badKsDir);
    }, /Credentials file is corrupted: invalid JSON/);
  });

  await t.test('loadKeyEnvelope rejects corrupted key file', async () => {
    const badKsDir = path.join(TEST_BASE_DIR, 'keystore-bad-key');
    await fsp.mkdir(badKsDir, { recursive: true });
    const keyPath = keystore.getKeyFilePath(badKsDir);
    await fsp.writeFile(keyPath, 'NOT_VALID_JSON{{{', 'utf8');

    await assert.rejects(async () => {
      await keystore.loadKeyEnvelope(badKsDir);
    }, /Key file is corrupted: invalid JSON/);
  });
});

test('Phase 4: Server Registration Contract & API Execution', async (t) => {
  const ksDir = path.join(TEST_BASE_DIR, 'keystore-reg-user');

  await t.test('executeInit registers user successfully with Vault Server', async () => {
    const result = await executeInit({
      username: 'charlie',
      passphrase: 'secure-passphrase-charlie-12345',
      enrollmentKey: ENROLLMENT_KEY,
      serverUrl: testServerUrl,
      keystoreDir: ksDir
    });

    assert.equal(result.username, 'charlie');
    assert.match(result.publicKeyFingerprint, /^SHA256:[0-9a-f]{64}$/);
    assert.equal(keystore.isInitialized(ksDir), true);

    const creds = await keystore.loadCredentials(ksDir);
    assert.equal(creds.username, 'charlie');
  });

  await t.test('server stored verifier but never received or stored raw API token', async () => {
    const creds = await keystore.loadCredentials(ksDir);
    const usersJsonPath = path.join(TEST_BASE_DIR, 'vault-server', 'users.json');
    const usersJson = JSON.parse(await fsp.readFile(usersJsonPath, 'utf8'));

    const charlieRecord = usersJson.charlie;
    assert.equal(typeof charlieRecord, 'object');
    assert.notEqual(charlieRecord, null);

    // Verify server has authVerifier (K_sign)
    assert.match(charlieRecord.authVerifier, /^[0-9a-f]{128}$/);

    // Verify raw API token from client credentials DOES NOT MATCH authVerifier
    assert.notEqual(charlieRecord.authVerifier, creds.apiToken);

    // Verify raw API token does not appear anywhere in users.json
    const rawUsersContent = await fsp.readFile(usersJsonPath, 'utf8');
    assert.equal(rawUsersContent.includes(creds.apiToken), false);
  });

  await t.test('executeInit rejects duplicate username registration with 409 Conflict', async () => {
    const duplicateKsDir = path.join(TEST_BASE_DIR, 'keystore-duplicate-user');

    await assert.rejects(async () => {
      await executeInit({
        username: 'charlie',
        passphrase: 'secure-passphrase-charlie-12345',
        enrollmentKey: ENROLLMENT_KEY,
        serverUrl: testServerUrl,
        keystoreDir: duplicateKsDir
      });
    }, /Registration failed \(conflict\): Username already registered/);

    // Verify keystore was not created for failed registration
    assert.equal(keystore.isInitialized(duplicateKsDir), false);
  });

  await t.test('executeInit rejects invalid enrollment key with 403 Forbidden', async () => {
    const forbiddenKsDir = path.join(TEST_BASE_DIR, 'keystore-forbidden-user');

    await assert.rejects(async () => {
      await executeInit({
        username: 'david',
        passphrase: 'secure-passphrase-david-12345',
        enrollmentKey: 'WRONG_ENROLLMENT_KEY_123',
        serverUrl: testServerUrl,
        keystoreDir: forbiddenKsDir
      });
    }, /Registration failed \(forbidden\): Invalid enrollment key/);

    assert.equal(keystore.isInitialized(forbiddenKsDir), false);
  });

  await t.test('executeInit rejects invalid username before network call', async () => {
    const invalidKsDir = path.join(TEST_BASE_DIR, 'keystore-invalid-username');

    await assert.rejects(async () => {
      await executeInit({
        username: 'invalid@username!',
        passphrase: 'secure-passphrase-12345',
        enrollmentKey: ENROLLMENT_KEY,
        serverUrl: testServerUrl,
        keystoreDir: invalidKsDir
      });
    }, /Invalid username: must be 1-64 characters matching \[a-zA-Z0-9_.-]/);
  });

  await t.test('executeInit rejects passphrase shorter than 12 characters', async () => {
    const shortKsDir = path.join(TEST_BASE_DIR, 'keystore-short-pass');

    await assert.rejects(async () => {
      await executeInit({
        username: 'elena',
        passphrase: 'short-pass',
        enrollmentKey: ENROLLMENT_KEY,
        serverUrl: testServerUrl,
        keystoreDir: shortKsDir
      });
    }, /Invalid passphrase: master passphrase must be at least 12 characters/);
  });
});

test('Phase 4: Network & Transport Security Boundary', async (t) => {
  await t.test('resolveServerUrl follows resolution priority', () => {
    // 1. CLI option
    const fromCli = api.resolveServerUrl('https://cli.vault.internal');
    assert.equal(fromCli, 'https://cli.vault.internal');

    // 2. ENV var
    process.env.ENVGUARD_SERVER = 'https://env.vault.internal';
    const fromEnv = api.resolveServerUrl('');
    assert.equal(fromEnv, 'https://env.vault.internal');
    delete process.env.ENVGUARD_SERVER;

    // 3. Fallback
    const fallback = api.resolveServerUrl('');
    assert.equal(fallback, 'http://localhost:3000');
  });

  await t.test('permits http:// only on loopback hostnames', () => {
    assert.doesNotThrow(() => {
      api.validateServerUrl('http://localhost:3000');
    });
    assert.doesNotThrow(() => {
      api.validateServerUrl('http://127.0.0.1:8080');
    });
    assert.doesNotThrow(() => {
      api.validateServerUrl('http://[::1]:8443');
    });
  });

  await t.test('rejects http:// on remote non-loopback hostnames', () => {
    assert.throws(() => {
      api.validateServerUrl('http://vault.example.com');
    }, /Insecure transport: http:\/\/ is only permitted for loopback addresses/);

    assert.throws(() => {
      api.validateServerUrl('http://192.168.1.10:3000');
    }, /Insecure transport: http:\/\/ is only permitted for loopback addresses/);
  });

  await t.test('permits https:// on any hostname', () => {
    assert.doesNotThrow(() => {
      api.validateServerUrl('https://vault.example.com');
    });
    assert.doesNotThrow(() => {
      api.validateServerUrl('https://127.0.0.1:8443');
    });
  });

  await t.test('handles connection refused cleanly when server is offline', async () => {
    const offlineKsDir = path.join(TEST_BASE_DIR, 'keystore-offline');

    await assert.rejects(async () => {
      await executeInit({
        username: 'offline_user',
        passphrase: 'secure-passphrase-offline-12345',
        enrollmentKey: ENROLLMENT_KEY,
        serverUrl: 'http://127.0.0.1:59999',
        keystoreDir: offlineKsDir
      });
    }, /ECONNREFUSED|connect ECONNREFUSED/);

    assert.equal(keystore.isInitialized(offlineKsDir), false);
  });
});

test('Phase 4: Input Prompting & Stream Handling', async (t) => {
  await t.test('reads line correctly from simulated input stream', async () => {
    const inStream = new Readable({
      read() {
        this.push('test_username\n');
        this.push(null);
      }
    });

    let outData = '';
    const outStream = new Writable({
      write(chunk, encoding, callback) {
        outData = outData + chunk.toString();
        callback();
      }
    });

    const result = await promptInput('Enter: ', false, inStream, outStream);
    assert.equal(result, 'test_username');
    assert.equal(outData.includes('Enter: '), true);
  });

  await t.test('handles SIGINT cancellation cleanly', async () => {
    const inStream = new Readable({
      read() {}
    });

    const outStream = new Writable({
      write(chunk, encoding, callback) {
        callback();
      }
    });

    const promptPromise = promptInput('Secret: ', true, inStream, outStream);

    // Emit SIGINT after next tick
    process.nextTick(() => {
      inStream.emit('SIGINT');
    });

    await assert.rejects(async () => {
      await promptPromise;
    }, /Operation cancelled by user/);
  });
});

test('Phase 4: Security Invariants & Leak Prevention', async (t) => {
  const ksDir = path.join(TEST_BASE_DIR, 'keystore-security-audit');
  const passphrase = 'audit-passphrase-super-secret-12345';
  const username = 'audituser';

  let loggedErrorMessages = [];
  const origError = console.error;
  console.error = function (...args) {
    loggedErrorMessages.push(args.join(' '));
    origError.apply(console, args);
  };

  let initResult;
  try {
    initResult = await executeInit({
      username: username,
      passphrase: passphrase,
      enrollmentKey: ENROLLMENT_KEY,
      serverUrl: testServerUrl,
      keystoreDir: ksDir
    });
  } finally {
    console.error = origError;
  }

  await t.test('no master passphrase appears in any logs or outputs', () => {
    for (let i = 0; i < loggedErrorMessages.length; i = i + 1) {
      assert.equal(loggedErrorMessages[i].includes(passphrase), false);
    }
  });

  await t.test('no enrollment key appears in any logs or outputs', () => {
    for (let i = 0; i < loggedErrorMessages.length; i = i + 1) {
      assert.equal(loggedErrorMessages[i].includes(ENROLLMENT_KEY), false);
    }
  });

  await t.test('no raw API token appears in error messages on failure', async () => {
    let capturedError = '';
    try {
      await executeInit({
        username: 'audituser', // Duplicate user
        passphrase: passphrase,
        enrollmentKey: ENROLLMENT_KEY,
        serverUrl: testServerUrl,
        keystoreDir: path.join(TEST_BASE_DIR, 'keystore-fail')
      });
    } catch (err) {
      capturedError = err.message;
    }

    const creds = await keystore.loadCredentials(ksDir);
    assert.equal(capturedError.includes(creds.apiToken), false);
    assert.equal(capturedError.includes(passphrase), false);
    assert.equal(capturedError.includes(ENROLLMENT_KEY), false);
  });

  await t.test('registerUser rejects payloads with raw secrets before transmission', async () => {
    const leakPayload = {
      username: 'leaker',
      publicKey: { kty: 'OKP', crv: 'X25519', x: '1234567890123456789012345678901234567890123' },
      salt: '0123456789abcdef0123456789abcdef',
      authVerifier: 'a'.repeat(128),
      enrollmentKey: ENROLLMENT_KEY,
      apiToken: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    };

    await assert.rejects(async () => {
      await api.registerUser(testServerUrl, leakPayload);
    }, /Security violation: raw secrets detected in registration payload/);
  });
});
