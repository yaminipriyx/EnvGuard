/**
 * Comprehensive Test Suite for Phase 5: 'envguard set' & Secret Encryption.
 *
 * Validates:
 * 1. Input handling (valid/invalid key names, missing values, '=', spaces, special chars, stdin).
 * 2. New vault creation (DEK generation, dekVersion=1, vaultVersion=1, owner wrapped DEK, AAD binding, .envguard.json update).
 * 3. Existing vault update (DEK reuse, dekVersion unchanged, vaultVersion increment, secret merging, expectedVersion).
 * 4. Cryptographic integrity & fail-closed authentication (tampered ciphertext, tag, AAD).
 * 5. Role authorization (owner, admin, member can set; readonly rejected with 403).
 * 6. Optimistic concurrency conflict (409 Conflict handling without overwrite).
 * 7. Security invariants & confidentiality (no secrets, raw DEKs, tokens, or private keys sent to server or logged).
 *
 * Syntax Rules: Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import crypto from 'node:crypto';

import { createServer } from '../src/server/server.js';
import * as keystore from '../src/client/keystore.js';
import * as api from '../src/client/api.js';
import * as ecdh from '../src/crypto/ecdh.js';
import * as envelope from '../src/crypto/envelope.js';
import * as kdf from '../src/crypto/kdf.js';
import { executeInit } from '../src/commands/init.js';
import { validateKeyName, parseStdinSecrets, executeSet } from '../src/commands/set.js';

const TEST_BASE_DIR = path.resolve('test-set-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-phase5';

let testServerInstance = null;
let testServerPort = 0;
let testServerUrl = '';

// Shared users for multi-role testing
const ALICE_PASSPHRASE = 'alice-master-passphrase-12345';
const BOB_PASSPHRASE = 'bob-master-passphrase-12345';
const CHARLIE_PASSPHRASE = 'charlie-master-passphrase-12345';
const DAVID_PASSPHRASE = 'david-master-passphrase-12345';

let aliceKeystoreDir = '';
let bobKeystoreDir = '';
let charlieKeystoreDir = '';
let davidKeystoreDir = '';

/**
 * Setup test Vault Server and register test users.
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

  // Initialize Alice (Vault Owner)
  aliceKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-alice');
  await executeInit({
    username: 'alice',
    passphrase: ALICE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir
  });

  // Initialize Bob (Admin)
  bobKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-bob');
  await executeInit({
    username: 'bob',
    passphrase: BOB_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir
  });

  // Initialize Charlie (Member)
  charlieKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-charlie');
  await executeInit({
    username: 'charlie',
    passphrase: CHARLIE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir
  });

  // Initialize David (Readonly)
  davidKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-david');
  await executeInit({
    username: 'david',
    passphrase: DAVID_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: davidKeystoreDir
  });
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

test('Phase 5: Secret Input Validation & Stdin Parsing', async (t) => {
  await t.test('validateKeyName accepts valid POSIX identifiers', () => {
    assert.doesNotThrow(() => validateKeyName('API_KEY'));
    assert.doesNotThrow(() => validateKeyName('PORT'));
    assert.doesNotThrow(() => validateKeyName('_PRIVATE_VAR'));
    assert.doesNotThrow(() => validateKeyName('DATABASE_URL_V2'));
    assert.doesNotThrow(() => validateKeyName('a'));
    assert.doesNotThrow(() => validateKeyName('_'));
  });

  await t.test('validateKeyName rejects invalid identifiers', () => {
    assert.throws(() => validateKeyName('123BAD'), /Invalid secret key name/);
    assert.throws(() => validateKeyName('BAD-KEY'), /Invalid secret key name/);
    assert.throws(() => validateKeyName('BAD.KEY'), /Invalid secret key name/);
    assert.throws(() => validateKeyName('BAD KEY'), /Invalid secret key name/);
    assert.throws(() => validateKeyName(''), /Invalid secret key name/);
    assert.throws(() => validateKeyName(null), /Invalid secret key name/);
  });

  await t.test('parseStdinSecrets parses multi-line KEY=VALUE pairs correctly', () => {
    const raw = '# Comment line\n\nAPI_KEY=secret123\nDATABASE_URL=postgres://user:pass@host:5432/db?ssl=true\n_TIMEOUT=30\n';
    const parsed = parseStdinSecrets(raw);

    assert.equal(parsed.API_KEY, 'secret123');
    assert.equal(parsed.DATABASE_URL, 'postgres://user:pass@host:5432/db?ssl=true');
    assert.equal(parsed._TIMEOUT, '30');
  });

  await t.test('parseStdinSecrets preserves values with spaces and special characters', () => {
    const raw = 'GREETING=Hello World from EnvGuard!\nSPECIAL_CHARS=!@#$%^&*()_+-=[]{}|;:,.<>?\n';
    const parsed = parseStdinSecrets(raw);

    assert.equal(parsed.GREETING, 'Hello World from EnvGuard!');
    assert.equal(parsed.SPECIAL_CHARS, '!@#$%^&*()_+-=[]{}|;:,.<>?');
  });

  await t.test('parseStdinSecrets rejects lines missing equal sign', () => {
    const raw = 'VALID=ok\nINVALID_LINE_WITHOUT_EQUALS\n';
    assert.throws(() => parseStdinSecrets(raw), /Invalid stdin format on line 2: expected KEY=VALUE/);
  });

  await t.test('parseStdinSecrets rejects empty value', () => {
    const raw = 'EMPTY_KEY=\n';
    assert.throws(() => parseStdinSecrets(raw), /Secret value for key "EMPTY_KEY" cannot be empty/);
  });

  await t.test('parseStdinSecrets rejects input with no valid secrets', () => {
    assert.throws(() => parseStdinSecrets('# Only comments\n\n'), /No valid secrets found on stdin/);
    assert.throws(() => parseStdinSecrets(''), /No secrets provided on stdin/);
  });
});

test('Phase 5: Initial Vault Creation (New Vault)', async (t) => {
  const projectDir = path.join(TEST_BASE_DIR, 'project-new-vault');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const initialConfig = {
    version: 1,
    project: 'demo-service',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(initialConfig, null, 2) + '\n', 'utf8');

  let setResult;

  await t.test('executeSet creates new vault with generated vaultId, dekVersion=1, vaultVersion=1', async () => {
    setResult = await executeSet({
      secretsToSet: {
        API_KEY: 'super-secret-key-1',
        DATABASE_URL: 'postgres://localhost:5432/demo'
      },
      env: 'development',
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      projectConfig: initialConfig,
      projectConfigPath: configPath
    });

    assert.equal(setResult.isNewVault, true);
    assert.equal(setResult.vaultVersion, 1);
    assert.equal(setResult.dekVersion, 1);
    assert.match(setResult.vaultId, /^demo-service-development-[0-9a-f]{16}$/);
    assert.deepEqual(setResult.keysSet, ['API_KEY', 'DATABASE_URL']);
  });

  await t.test('persists generated vaultId to .envguard.json preserving existing properties', async () => {
    const rawSaved = await fsp.readFile(configPath, 'utf8');
    const savedConfig = JSON.parse(rawSaved);

    assert.equal(savedConfig.version, 1);
    assert.equal(savedConfig.project, 'demo-service');
    assert.equal(savedConfig.serverUrl, testServerUrl);
    assert.equal(savedConfig.environments.development, setResult.vaultId);
  });

  await t.test('server stored encrypted secret blob and wrapped DEK without plaintext', async () => {
    const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
    const vaultState = await api.getVaultSecrets(testServerUrl, setResult.vaultId, aliceCreds);

    assert.equal(vaultState.vaultVersion, 1);
    assert.equal(vaultState.dekVersion, 1);
    assert.equal(vaultState.blob.algorithm, 'aes-256-gcm');
    assert.equal(vaultState.blob.dekVersion, 1);
    assert.equal(vaultState.blob.aad, `${setResult.vaultId}:1`);

    // Verify raw secret text does not appear anywhere in stored vault file
    const vaultFilePath = path.join(TEST_BASE_DIR, 'vault-server', 'vaults', `${setResult.vaultId}.json`);
    const rawVaultFile = await fsp.readFile(vaultFilePath, 'utf8');

    assert.equal(rawVaultFile.includes('super-secret-key-1'), false);
    assert.equal(rawVaultFile.includes('postgres://localhost:5432/demo'), false);

    // Verify wrapped DEK exists for Alice with correct AAD
    const aliceWrappedDek = vaultState.wrappedDeks.alice;
    assert.equal(typeof aliceWrappedDek, 'object');
    assert.notEqual(aliceWrappedDek, null);
    assert.equal(aliceWrappedDek.algorithm, 'aes-256-gcm');
    assert.equal(aliceWrappedDek.aad, `${setResult.vaultId}:1:alice`);
  });
});

test('Phase 5: Existing Vault Update & Secret Merging', async (t) => {
  const projectDir = path.join(TEST_BASE_DIR, 'project-existing-vault');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const config = {
    version: 1,
    project: 'orders-api',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

  // 1. Create initial vault with SECRET_A
  const initialResult = await executeSet({
    secretsToSet: { SECRET_A: 'val-a' },
    env: 'production',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: config,
    projectConfigPath: configPath
  });

  const vaultId = initialResult.vaultId;
  assert.equal(initialResult.vaultVersion, 1);
  assert.equal(initialResult.dekVersion, 1);

  // 2. Perform second set to update SECRET_B
  let secondResult;
  await t.test('subsequent set reuses existing DEK, increments vaultVersion, keeps dekVersion unchanged', async () => {
    secondResult = await executeSet({
      secretsToSet: { SECRET_B: 'val-b' },
      env: 'production',
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      projectConfig: config,
      projectConfigPath: configPath,
      passphrase: ALICE_PASSPHRASE
    });

    assert.equal(secondResult.isNewVault, false);
    assert.equal(secondResult.vaultId, vaultId);
    assert.equal(secondResult.vaultVersion, 2);
    assert.equal(secondResult.dekVersion, 1); // DEK version unchanged!
  });

  // 3. Verify that both SECRET_A and SECRET_B exist in the decrypted vault state
  await t.test('both SECRET_A and SECRET_B are merged and preserved in vault', async () => {
    const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
    const vaultState = await api.getVaultSecrets(testServerUrl, vaultId, aliceCreds);

    const aliceKeyEnv = await keystore.loadKeyEnvelope(aliceKeystoreDir);
    const privKey = envelope.openPrivateKeyEnvelope(aliceKeyEnv, ALICE_PASSPHRASE);
    const dek = envelope.openWrappedDekEnvelope(vaultState.wrappedDeks.alice, privKey, vaultId, 1, 'alice');

    const plaintext = envelope.openSecretEnvelope(vaultState.blob, dek, vaultId, 1);
    const secrets = JSON.parse(plaintext.toString('utf8'));

    assert.equal(secrets.SECRET_A, 'val-a');
    assert.equal(secrets.SECRET_B, 'val-b');

    plaintext.fill(0);
    dek.fill(0);
  });

  // 4. Perform third set overwriting SECRET_A with new value
  await t.test('overwriting an existing key updates the value and increments vaultVersion to 3', async () => {
    const thirdResult = await executeSet({
      secretsToSet: { SECRET_A: 'val-a-updated' },
      env: 'production',
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      projectConfig: config,
      projectConfigPath: configPath,
      passphrase: ALICE_PASSPHRASE
    });

    assert.equal(thirdResult.vaultVersion, 3);
    assert.equal(thirdResult.dekVersion, 1);

    const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
    const vaultState = await api.getVaultSecrets(testServerUrl, vaultId, aliceCreds);
    const aliceKeyEnv = await keystore.loadKeyEnvelope(aliceKeystoreDir);
    const privKey = envelope.openPrivateKeyEnvelope(aliceKeyEnv, ALICE_PASSPHRASE);
    const dek = envelope.openWrappedDekEnvelope(vaultState.wrappedDeks.alice, privKey, vaultId, 1, 'alice');

    const plaintext = envelope.openSecretEnvelope(vaultState.blob, dek, vaultId, 1);
    const secrets = JSON.parse(plaintext.toString('utf8'));

    assert.equal(secrets.SECRET_A, 'val-a-updated');
    assert.equal(secrets.SECRET_B, 'val-b');

    plaintext.fill(0);
    dek.fill(0);
  });
});

test('Phase 5: Concurrency Control & Optimistic Conflict Handling', async (t) => {
  const projectDir = path.join(TEST_BASE_DIR, 'project-concurrency');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const config = {
    version: 1,
    project: 'concurrency-test',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

  // Create initial vault (vaultVersion = 1)
  const initial = await executeSet({
    secretsToSet: { INIT: '1' },
    env: 'staging',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: config,
    projectConfigPath: configPath
  });

  const vaultId = initial.vaultId;

  // Stale update simulation: caller sends expectedVersion = 999 instead of current version 1
  await t.test('detects optimistic concurrency conflict and aborts without overwriting', async () => {
    const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
    const aliceKeyEnv = await keystore.loadKeyEnvelope(aliceKeystoreDir);
    const privKey = envelope.openPrivateKeyEnvelope(aliceKeyEnv, ALICE_PASSPHRASE);

    const vaultState = await api.getVaultSecrets(testServerUrl, vaultId, aliceCreds);
    const dek = envelope.openWrappedDekEnvelope(vaultState.wrappedDeks.alice, privKey, vaultId, 1, 'alice');
    const newBlob = envelope.createSecretEnvelope(Buffer.from('{"CONFLICT":"true"}', 'utf8'), dek, vaultId, 1);
    dek.fill(0);

    // Update with wrong expectedVersion
    await assert.rejects(async () => {
      await api.updateVaultSecrets(testServerUrl, vaultId, { expectedVersion: 999, blob: newBlob }, aliceCreds);
    }, (err) => {
      assert.equal(err.statusCode, 409);
      assert.match(err.message, /conflict|mismatch/i);
      return true;
    });

    // Verify vault state on server was NOT modified
    const currentVault = await api.getVaultSecrets(testServerUrl, vaultId, aliceCreds);
    assert.equal(currentVault.vaultVersion, 1);
  });
});

test('Phase 5: Multi-Role Authorization Matrix for set', async (t) => {
  const projectDir = path.join(TEST_BASE_DIR, 'project-roles');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const config = {
    version: 1,
    project: 'role-test',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

  // 1. Alice (Owner) creates the vault
  const initial = await executeSet({
    secretsToSet: { KEY1: 'val1' },
    env: 'development',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: config,
    projectConfigPath: configPath
  });
  const vaultId = initial.vaultId;

  // Load public keys of Bob, Charlie, David for granting
  const bobKeyEnv = await keystore.loadKeyEnvelope(bobKeystoreDir);
  const charlieKeyEnv = await keystore.loadKeyEnvelope(charlieKeystoreDir);
  const davidKeyEnv = await keystore.loadKeyEnvelope(davidKeystoreDir);

  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const aliceKeyEnv = await keystore.loadKeyEnvelope(aliceKeystoreDir);
  const alicePrivKey = envelope.openPrivateKeyEnvelope(aliceKeyEnv, ALICE_PASSPHRASE);
  const vaultState = await api.getVaultSecrets(testServerUrl, vaultId, aliceCreds);
  const currentDek = envelope.openWrappedDekEnvelope(vaultState.wrappedDeks.alice, alicePrivKey, vaultId, 1, 'alice');

  // Wrap DEK for Bob, Charlie, David
  const bobWrapped = envelope.createWrappedDekEnvelope(currentDek, bobKeyEnv.publicKey, vaultId, 1, 'bob');
  const charlieWrapped = envelope.createWrappedDekEnvelope(currentDek, charlieKeyEnv.publicKey, vaultId, 1, 'charlie');
  const davidWrapped = envelope.createWrappedDekEnvelope(currentDek, davidKeyEnv.publicKey, vaultId, 1, 'david');
  currentDek.fill(0);

  // Directly grant roles on server to test set permissions:
  // Alice grants Bob admin
  await api.sendAuthenticatedRequest(testServerUrl, 'POST', `/api/v1/vault/${vaultId}/members`, {
    expectedVersion: 1,
    username: 'bob',
    role: 'admin',
    wrappedDek: bobWrapped,
    publicKeyFingerprint: ecdh.calculateFingerprint(bobKeyEnv.publicKey)
  }, aliceCreds);

  // Alice grants Charlie member
  await api.sendAuthenticatedRequest(testServerUrl, 'POST', `/api/v1/vault/${vaultId}/members`, {
    expectedVersion: 2,
    username: 'charlie',
    role: 'member',
    wrappedDek: charlieWrapped,
    publicKeyFingerprint: ecdh.calculateFingerprint(charlieKeyEnv.publicKey)
  }, aliceCreds);

  // Alice grants David readonly
  await api.sendAuthenticatedRequest(testServerUrl, 'POST', `/api/v1/vault/${vaultId}/members`, {
    expectedVersion: 3,
    username: 'david',
    role: 'readonly',
    wrappedDek: davidWrapped,
    publicKeyFingerprint: ecdh.calculateFingerprint(davidKeyEnv.publicKey)
  }, aliceCreds);

  // Now vaultVersion is 4. Test set operations across all 4 roles:

  await t.test('admin (Bob) can set secrets', async () => {
    const result = await executeSet({
      secretsToSet: { BOB_SECRET: 'bob-val' },
      env: 'development',
      serverUrl: testServerUrl,
      keystoreDir: bobKeystoreDir,
      projectConfig: config,
      projectConfigPath: configPath,
      passphrase: BOB_PASSPHRASE
    });

    assert.equal(result.vaultVersion, 5);
    assert.equal(result.dekVersion, 1);
  });

  await t.test('member (Charlie) can set secrets', async () => {
    const result = await executeSet({
      secretsToSet: { CHARLIE_SECRET: 'charlie-val' },
      env: 'development',
      serverUrl: testServerUrl,
      keystoreDir: charlieKeystoreDir,
      projectConfig: config,
      projectConfigPath: configPath,
      passphrase: CHARLIE_PASSPHRASE
    });

    assert.equal(result.vaultVersion, 6);
    assert.equal(result.dekVersion, 1);
  });

  await t.test('readonly (David) is rejected from setting secrets with 403 Forbidden', async () => {
    await assert.rejects(async () => {
      await executeSet({
        secretsToSet: { DAVID_SECRET: 'david-val' },
        env: 'development',
        serverUrl: testServerUrl,
        keystoreDir: davidKeystoreDir,
        projectConfig: config,
        projectConfigPath: configPath,
        passphrase: DAVID_PASSPHRASE
      });
    }, (err) => {
      assert.equal(err.statusCode, 403);
      assert.match(err.message, /Readonly members are not permitted to modify secrets/);
      return true;
    });
  });
});

test('Phase 5: Cryptographic Integrity & Tamper Resistance', async (t) => {
  const projectDir = path.join(TEST_BASE_DIR, 'project-tamper');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const config = {
    version: 1,
    project: 'tamper-test',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

  const initial = await executeSet({
    secretsToSet: { KEY: 'original' },
    env: 'dev',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: config,
    projectConfigPath: configPath
  });
  const vaultId = initial.vaultId;

  await t.test('fails closed when wrong passphrase is provided to unwrap DEK', async () => {
    await assert.rejects(async () => {
      await executeSet({
        secretsToSet: { KEY2: 'newval' },
        env: 'dev',
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        projectConfig: config,
        projectConfigPath: configPath,
        passphrase: 'WRONG_PASSPHRASE_12345'
      });
    }, /Master passphrase authentication failed/);
  });

  await t.test('fails closed if wrapped DEK ciphertext is tampered', () => {
    const keyPair = ecdh.generateKeyPair();
    const dek = crypto.randomBytes(32);
    const wrapped = envelope.createWrappedDekEnvelope(dek, keyPair.publicKey, vaultId, 1, 'alice');
    dek.fill(0);

    const tampered = JSON.parse(JSON.stringify(wrapped));
    const rawBuf = Buffer.from(tampered.encryptedDek, 'hex');
    rawBuf[0] = rawBuf[0] ^ 0xff;
    tampered.encryptedDek = rawBuf.toString('hex');

    assert.throws(() => {
      envelope.openWrappedDekEnvelope(tampered, keyPair.privateKey, vaultId, 1, 'alice');
    }, /Decryption failed/);
  });

  await t.test('fails closed if wrapped DEK recipient is mismatched in AAD', () => {
    const keyPair = ecdh.generateKeyPair();
    const dek = crypto.randomBytes(32);
    const wrapped = envelope.createWrappedDekEnvelope(dek, keyPair.publicKey, vaultId, 1, 'alice');
    dek.fill(0);

    // Expecting bob instead of alice
    assert.throws(() => {
      envelope.openWrappedDekEnvelope(wrapped, keyPair.privateKey, vaultId, 1, 'bob');
    }, /AAD mismatch/);
  });

  await t.test('fails closed if secret blob ciphertext is tampered', () => {
    const dek = crypto.randomBytes(32);
    const blob = envelope.createSecretEnvelope(Buffer.from('{"K":"V"}', 'utf8'), dek, vaultId, 1);

    const tampered = JSON.parse(JSON.stringify(blob));
    const rawBuf = Buffer.from(tampered.ciphertext, 'hex');
    rawBuf[0] = rawBuf[0] ^ 0xff;
    tampered.ciphertext = rawBuf.toString('hex');

    assert.throws(() => {
      envelope.openSecretEnvelope(tampered, dek, vaultId, 1);
    }, /Decryption failed/);

    dek.fill(0);
  });
});

test('Phase 5: Security Invariants & Leak Prevention', async (t) => {
  const secretKey = 'TOP_SECRET_PASSWORD';
  const secretVal = 'SuperSecretCleartextPass12345!@#$';

  const projectDir = path.join(TEST_BASE_DIR, 'project-leak-check');
  await fsp.mkdir(projectDir, { recursive: true });
  const configPath = path.join(projectDir, '.envguard.json');

  const config = {
    version: 1,
    project: 'leak-check',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');

  let loggedMessages = [];
  const origLog = console.log;
  const origError = console.error;
  console.log = function (...args) {
    loggedMessages.push(args.join(' '));
    origLog.apply(console, args);
  };
  console.error = function (...args) {
    loggedMessages.push(args.join(' '));
    origError.apply(console, args);
  };

  let setResult;
  try {
    setResult = await executeSet({
      secretsToSet: { [secretKey]: secretVal },
      env: 'development',
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      projectConfig: config,
      projectConfigPath: configPath
    });
  } finally {
    console.log = origLog;
    console.error = origError;
  }

  await t.test('secret plaintext never appears in any console log or error output', () => {
    for (let i = 0; i < loggedMessages.length; i = i + 1) {
      assert.equal(loggedMessages[i].includes(secretVal), false);
    }
  });

  await t.test('.envguard.json never contains plaintext secret values', async () => {
    const rawConfig = await fsp.readFile(configPath, 'utf8');
    assert.equal(rawConfig.includes(secretVal), false);
  });

  await t.test('vault server storage files never contain plaintext secret values', async () => {
    const vaultFilePath = path.join(TEST_BASE_DIR, 'vault-server', 'vaults', `${setResult.vaultId}.json`);
    const rawVaultFile = await fsp.readFile(vaultFilePath, 'utf8');
    assert.equal(rawVaultFile.includes(secretVal), false);
  });

  await t.test('local keystore files never contain plaintext secret values', async () => {
    const credsPath = keystore.getCredentialsFilePath(aliceKeystoreDir);
    const keyPath = keystore.getKeyFilePath(aliceKeystoreDir);
    const credsContent = await fsp.readFile(credsPath, 'utf8');
    const keyContent = await fsp.readFile(keyPath, 'utf8');

    assert.equal(credsContent.includes(secretVal), false);
    assert.equal(keyContent.includes(secretVal), false);
  });
});
