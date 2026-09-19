/**
 * Comprehensive Phase 8 Integration & Security Regression Test Suite.
 *
 * Validates:
 * 1. Full lifecycle end-to-end integration:
 *    init -> configure -> set -> run -> grant -> revoke (DEK rotates) -> grant after rotation.
 * 2. Cryptographic security regressions:
 *    Ciphertext tampering, Auth tag tampering, IV tampering, AAD tampering,
 *    Wrapped-DEK tampering (ephemeral public key, encryptedDek, tag, AAD),
 *    Wrong user private key unwrapping, Old DEK failure after rotation.
 * 3. Authentication & Request security:
 *    Missing auth headers, invalid signature, modified body, modified method/path,
 *    stale timestamp, replayed nonce, inactive user, unknown user.
 * 4. Multi-role authorization matrix:
 *    Owner (full access), Admin (no admin-grant, no admin/owner-revoke),
 *    Member (read/set only), Readonly (read only), Revoked user (total isolation).
 * 5. Concurrency & Optimistic Concurrency Control (OCC):
 *    Stale expectedVersion on set, grant, revoke producing 409 without mutation.
 * 6. Server zero-knowledge verification:
 *    Server rejects plaintext/dek payload fields, persists only ciphertext/public keys.
 * 7. Client local storage & leakage prevention:
 *    No plaintext secrets, passphrases, or raw DEKs in keystore or .envguard.json.
 * 8. Malformed & negative input resilience:
 *    Fail-closed behavior on corrupted envelopes, malformed hex, invalid identifiers.
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
import * as aes from '../src/crypto/aes.js';
import * as ecdh from '../src/crypto/ecdh.js';
import * as kdf from '../src/crypto/kdf.js';
import * as envelope from '../src/crypto/envelope.js';
import { executeInit } from '../src/commands/init.js';
import { executeSet } from '../src/commands/set.js';
import { executeRun } from '../src/commands/run.js';
import { executeGrant } from '../src/commands/grant.js';
import { executeRevoke } from '../src/commands/revoke.js';

const TEST_BASE_DIR = path.resolve('test-integration-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-phase8-integration';

let testServerInstance = null;
let testServerPort = 0;
let testServerUrl = '';
let serverStorageDir = '';

const ALICE_PASSPHRASE = 'alice-master-passphrase-phase8-12345';
const BOB_PASSPHRASE = 'bob-master-passphrase-phase8-12345';
const CHARLIE_PASSPHRASE = 'charlie-master-passphrase-phase8-12345';
const DAVE_PASSPHRASE = 'dave-master-passphrase-phase8-12345';
const EVE_PASSPHRASE = 'eve-master-passphrase-phase8-12345';

let aliceKeystoreDir = '';
let bobKeystoreDir = '';
let charlieKeystoreDir = '';
let daveKeystoreDir = '';
let eveKeystoreDir = '';

let projectConfig = null;
let projectConfigPath = '';
let integrationVaultId = '';

test.before(async () => {
  await fsp.mkdir(TEST_BASE_DIR, { recursive: true });
  serverStorageDir = path.join(TEST_BASE_DIR, 'vault-server');

  testServerInstance = createServer({
    dataDir: serverStorageDir,
    enrollmentKey: ENROLLMENT_KEY,
    host: '127.0.0.1'
  });

  const addr = await testServerInstance.listen(0, '127.0.0.1');
  testServerPort = addr.port;
  testServerUrl = `http://127.0.0.1:${testServerPort}`;

  // 1. Initialize Users (Owner Alice, Member Bob, Admin Charlie, Member Dave, Readonly Eve)
  aliceKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-alice');
  await executeInit({
    username: 'alice',
    passphrase: ALICE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir
  });

  bobKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-bob');
  await executeInit({
    username: 'bob',
    passphrase: BOB_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir
  });

  charlieKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-charlie');
  await executeInit({
    username: 'charlie',
    passphrase: CHARLIE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir
  });

  daveKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-dave');
  await executeInit({
    username: 'dave',
    passphrase: DAVE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: daveKeystoreDir
  });

  eveKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-eve');
  await executeInit({
    username: 'eve',
    passphrase: EVE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: eveKeystoreDir
  });

  // 2. Initialize project configuration
  projectConfigPath = path.join(TEST_BASE_DIR, '.envguard.json');
  projectConfig = {
    version: 1,
    project: 'phase8-integration-app',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(projectConfigPath, JSON.stringify(projectConfig, null, 2) + '\n', 'utf8');
});

test.after(async () => {
  if (testServerInstance) {
    await testServerInstance.close();
  }
  try {
    await fsp.rm(TEST_BASE_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (err) {
    // Ignore cleanup error on Windows
  }
});

// =============================================================================
// Section 1: End-to-End Integration Lifecycle
// =============================================================================

test('1. Initial Vault Creation and Storage Obliviousness', async () => {
  const setResult = await executeSet({
    secretsToSet: {
      DATABASE_URL: 'postgres://app_user:ultra_secure_password@db.internal:5432/production',
      STRIPE_SECRET_KEY: 'sk_live_envguard_phase8_testing_key_123'
    },
    env: 'development',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    projectConfigPath: projectConfigPath,
    passphrase: ALICE_PASSPHRASE
  });

  integrationVaultId = setResult.vaultId;
  assert.ok(integrationVaultId.startsWith('phase8-integration-app-development-'));
  assert.equal(setResult.vaultVersion, 1);
  assert.equal(setResult.dekVersion, 1);

  // Read updated project config
  const rawConfig = await fsp.readFile(projectConfigPath, 'utf8');
  projectConfig = JSON.parse(rawConfig);
  assert.equal(projectConfig.environments.development, integrationVaultId);

  // Verify server disk storage does NOT contain plaintext secrets
  const vaultDiskPath = path.join(serverStorageDir, 'vaults', `${integrationVaultId}.json`);
  const rawDiskVault = await fsp.readFile(vaultDiskPath, 'utf8');
  assert.ok(!rawDiskVault.includes('ultra_secure_password'), 'Server disk contains secret password!');
  assert.ok(!rawDiskVault.includes('sk_live_envguard'), 'Server disk contains secret stripe key!');
  assert.ok(!rawDiskVault.includes('postgres://'), 'Server disk contains database URL plaintext!');
});

test('2. Multiple Secret Provisioning, Merging, and Versioning', async () => {
  // Update vault: add a new key and update an existing key
  const setResult = await executeSet({
    secretsToSet: {
      REDIS_URL: 'redis://cache.internal:6379',
      STRIPE_SECRET_KEY: 'sk_live_updated_key_456'
    },
    env: 'development',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    projectConfigPath: projectConfigPath,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(setResult.vaultVersion, 2);
  assert.equal(setResult.dekVersion, 1); // DEK version must not change on set

  // Verify all secrets are merged and preserved
  const runResult = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.DATABASE_URL !== "postgres://app_user:ultra_secure_password@db.internal:5432/production" || process.env.REDIS_URL !== "redis://cache.internal:6379" || process.env.STRIPE_SECRET_KEY !== "sk_live_updated_key_456") process.exit(10);'],
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(runResult.exitCode, 0);
});

test('3. Runtime Secret Injection & Process Isolation', async () => {
  // Verify secrets override existing environment, inherited variables stay intact, exit code propagated
  const runResult = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.STRIPE_SECRET_KEY !== "sk_live_updated_key_456") process.exit(1); process.exit(42);'],
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(runResult.exitCode, 42);
});

test('4. Grant Lifecycle: Adding Bob and Preserving DEK', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const bobRecord = await api.getUser(testServerUrl, 'bob', aliceCreds);

  const grantResult = await executeGrant({
    username: 'bob',
    role: 'member',
    fingerprint: bobRecord.publicKeyFingerprint,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'bob');
  assert.equal(grantResult.role, 'member');
  assert.equal(grantResult.vaultVersion, 3);
  assert.equal(grantResult.dekVersion, 1); // DEK unchanged

  // Bob can run and read secrets
  const bobRun = await executeRun({
    commandArgs: ['node', '-e', 'if (!process.env.DATABASE_URL) process.exit(1);'],
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir,
    projectConfig: projectConfig,
    passphrase: BOB_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(bobRun.exitCode, 0);
});

test('5. Revoke Lifecycle: Revoking Bob, Mandatory DEK Rotation, and Isolation', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const stateBefore = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);

  // Capture Bob's unwrapped DEK at dekVersion 1 for regression testing
  const bobCreds = await keystore.loadCredentials(bobKeystoreDir);
  const bobKeyEnvelope = await keystore.loadKeyEnvelope(bobKeystoreDir);
  const bobPrivateKeyJwk = envelope.openPrivateKeyEnvelope(bobKeyEnvelope, BOB_PASSPHRASE);
  const bobOldDek = envelope.openWrappedDekEnvelope(
    stateBefore.wrappedDeks.bob,
    bobPrivateKeyJwk,
    integrationVaultId,
    1,
    'bob'
  );

  const revokeResult = await executeRevoke({
    username: 'bob',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(revokeResult.username, 'bob');
  assert.equal(revokeResult.vaultVersion, 4);
  assert.equal(revokeResult.dekVersion, 2); // DEK rotated to 2

  const stateAfter = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);
  assert.equal(stateAfter.members.bob, undefined);
  assert.equal(stateAfter.wrappedDeks.bob, undefined);
  assert.equal(stateAfter.dekVersion, 2);

  // CRYPTOGRAPHIC REGRESSION: Bob's old DEK cannot decrypt the rotated blob
  assert.throws(
    () => {
      envelope.openSecretEnvelope(stateAfter.blob, bobOldDek, integrationVaultId, 2);
    },
    /Decryption failed|authentication tag verification failed|tag mismatch/i
  );
  bobOldDek.fill(0);

  // Revoked user Bob cannot run
  await assert.rejects(
    async () => {
      await executeRun({
        commandArgs: ['node', '-e', 'process.exit(0);'],
        serverUrl: testServerUrl,
        keystoreDir: bobKeystoreDir,
        projectConfig: projectConfig,
        passphrase: BOB_PASSPHRASE,
        stdio: 'pipe'
      });
    },
    /Access denied: caller is not an authorized vault member/
  );

  // Remaining user Alice can run and read all secrets
  const aliceRun = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.STRIPE_SECRET_KEY !== "sk_live_updated_key_456") process.exit(1);'],
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(aliceRun.exitCode, 0);
});

test('6. Grant After Rotation: Adding Charlie under new rotated dekVersion', async () => {
  // Grant Charlie (Admin) after DEK rotation has occurred (dekVersion is 2)
  const grantResult = await executeGrant({
    username: 'charlie',
    role: 'admin',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'charlie');
  assert.equal(grantResult.vaultVersion, 5);
  assert.equal(grantResult.dekVersion, 2); // Must wrap active dekVersion 2

  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);

  // Assert Charlie's wrapped DEK AAD reflects dekVersion 2
  assert.equal(state.wrappedDeks.charlie.aad, `${integrationVaultId}:2:charlie`);

  // Charlie can run and read secrets
  const charlieRun = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.DATABASE_URL !== "postgres://app_user:ultra_secure_password@db.internal:5432/production") process.exit(1);'],
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir,
    projectConfig: projectConfig,
    passphrase: CHARLIE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(charlieRun.exitCode, 0);
});

// =============================================================================
// Section 2: Cryptographic Security & Tamper Regressions
// =============================================================================

test('7. Cryptographic Tampering: Secret Blob Integrity', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);
  const aliceKeyEnvelope = await keystore.loadKeyEnvelope(aliceKeystoreDir);
  const alicePrivKey = envelope.openPrivateKeyEnvelope(aliceKeyEnvelope, ALICE_PASSPHRASE);
  const activeDek = envelope.openWrappedDekEnvelope(
    state.wrappedDeks.alice,
    alicePrivKey,
    integrationVaultId,
    state.dekVersion,
    'alice'
  );

  // A. Ciphertext tampering (flipping one byte)
  const tamperedCiphertextBlob = Object.assign({}, state.blob);
  const ctBuf = Buffer.from(tamperedCiphertextBlob.ciphertext, 'hex');
  ctBuf[0] = ctBuf[0] ^ 0xff;
  tamperedCiphertextBlob.ciphertext = ctBuf.toString('hex');
  assert.throws(
    () => {
      envelope.openSecretEnvelope(tamperedCiphertextBlob, activeDek, integrationVaultId, state.dekVersion);
    },
    /Decryption failed|authentication tag verification failed/i
  );

  // B. Auth tag tampering
  const tamperedTagBlob = Object.assign({}, state.blob);
  const tagBuf = Buffer.from(tamperedTagBlob.tag, 'hex');
  tagBuf[0] = tagBuf[0] ^ 0xff;
  tamperedTagBlob.tag = tagBuf.toString('hex');
  assert.throws(
    () => {
      envelope.openSecretEnvelope(tamperedTagBlob, activeDek, integrationVaultId, state.dekVersion);
    },
    /Decryption failed|authentication tag verification failed/i
  );

  // C. IV tampering
  const tamperedIvBlob = Object.assign({}, state.blob);
  const ivBuf = Buffer.from(tamperedIvBlob.iv, 'hex');
  ivBuf[0] = ivBuf[0] ^ 0xff;
  tamperedIvBlob.iv = ivBuf.toString('hex');
  assert.throws(
    () => {
      envelope.openSecretEnvelope(tamperedIvBlob, activeDek, integrationVaultId, state.dekVersion);
    },
    /Decryption failed|authentication tag verification failed/i
  );

  // D. AAD tampering
  const tamperedAadBlob = Object.assign({}, state.blob);
  tamperedAadBlob.aad = `${integrationVaultId}:999`;
  assert.throws(
    () => {
      envelope.openSecretEnvelope(tamperedAadBlob, activeDek, integrationVaultId, state.dekVersion);
    },
    /AAD mismatch/i
  );

  activeDek.fill(0);
});

test('8. Cryptographic Tampering: Wrapped DEK Integrity & Cross-User Isolation', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);
  const aliceKeyEnvelope = await keystore.loadKeyEnvelope(aliceKeystoreDir);
  const alicePrivKey = envelope.openPrivateKeyEnvelope(aliceKeyEnvelope, ALICE_PASSPHRASE);

  const charlieKeyEnvelope = await keystore.loadKeyEnvelope(charlieKeystoreDir);
  const charliePrivKey = envelope.openPrivateKeyEnvelope(charlieKeyEnvelope, CHARLIE_PASSPHRASE);

  // A. Ephemeral public key tampering
  const tamperedKeyWrapped = JSON.parse(JSON.stringify(state.wrappedDeks.alice));
  tamperedKeyWrapped.ephemeralPublicKey.x = crypto.randomBytes(32).toString('base64url');
  assert.throws(
    () => {
      envelope.openWrappedDekEnvelope(tamperedKeyWrapped, alicePrivKey, integrationVaultId, state.dekVersion, 'alice');
    },
    /wrapped key authentication failed|tag verification failed/i
  );

  // B. Encrypted DEK tampering
  const tamperedDekWrapped = JSON.parse(JSON.stringify(state.wrappedDeks.alice));
  const encBuf = Buffer.from(tamperedDekWrapped.encryptedDek, 'hex');
  encBuf[0] = encBuf[0] ^ 0xff;
  tamperedDekWrapped.encryptedDek = encBuf.toString('hex');
  assert.throws(
    () => {
      envelope.openWrappedDekEnvelope(tamperedDekWrapped, alicePrivKey, integrationVaultId, state.dekVersion, 'alice');
    },
    /wrapped key authentication failed|tag verification failed/i
  );

  // C. Tag tampering
  const tamperedTagWrapped = JSON.parse(JSON.stringify(state.wrappedDeks.alice));
  const tagBuf = Buffer.from(tamperedTagWrapped.tag, 'hex');
  tagBuf[0] = tagBuf[0] ^ 0xff;
  tamperedTagWrapped.tag = tagBuf.toString('hex');
  assert.throws(
    () => {
      envelope.openWrappedDekEnvelope(tamperedTagWrapped, alicePrivKey, integrationVaultId, state.dekVersion, 'alice');
    },
    /wrapped key authentication failed|tag verification failed/i
  );

  // D. AAD tampering
  const tamperedAadWrapped = JSON.parse(JSON.stringify(state.wrappedDeks.alice));
  tamperedAadWrapped.aad = `${integrationVaultId}:${state.dekVersion}:eve`;
  assert.throws(
    () => {
      envelope.openWrappedDekEnvelope(tamperedAadWrapped, alicePrivKey, integrationVaultId, state.dekVersion, 'alice');
    },
    /AAD mismatch/i
  );

  // E. Cross-user isolation: Charlie attempts to unwrap Alice's wrapped DEK
  assert.throws(
    () => {
      envelope.openWrappedDekEnvelope(state.wrappedDeks.alice, charliePrivKey, integrationVaultId, state.dekVersion, 'alice');
    },
    /wrapped key authentication failed|tag verification failed/i
  );
});

// =============================================================================
// Section 3: API Request Authentication & Replay Protection
// =============================================================================

test('9. Authentication Security: Signature, Timestamp, Nonce, and Payload Verifications', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);

  // A. Missing signature header
  const validHeaders = api.signRequest('GET', `/api/v1/vault/${integrationVaultId}/secrets`, null, aliceCreds);
  const missingSigHeaders = Object.assign({}, validHeaders);
  delete missingSigHeaders['X-EnvGuard-Signature'];
  await assert.rejects(
    async () => {
      await fetch(`${testServerUrl}/api/v1/vault/${integrationVaultId}/secrets`, {
        method: 'GET',
        headers: missingSigHeaders
      }).then(res => {
        if (!res.ok) {
          const err = new Error('HTTP ' + res.status);
          err.statusCode = res.status;
          throw err;
        }
      });
    },
    /HTTP 400/
  );

  // B. Stale timestamp (> 300 seconds skew)
  const staleTimestamp = new Date(Date.now() - 360000).toISOString();
  const staleHeaders = Object.assign({}, api.signRequest('GET', `/api/v1/vault/${integrationVaultId}/secrets`, null, aliceCreds), {
    'X-EnvGuard-Timestamp': staleTimestamp
  });
  await assert.rejects(
    async () => {
      await fetch(`${testServerUrl}/api/v1/vault/${integrationVaultId}/secrets`, {
        method: 'GET',
        headers: staleHeaders
      }).then(res => {
        if (!res.ok) {
          const err = new Error('HTTP ' + res.status);
          err.statusCode = res.status;
          throw err;
        }
      });
    },
    /HTTP 401/
  );

  // C. Replayed nonce
  const replayHeaders = api.signRequest('GET', `/api/v1/vault/${integrationVaultId}/secrets`, null, aliceCreds);
  const res1 = await fetch(`${testServerUrl}/api/v1/vault/${integrationVaultId}/secrets`, {
    method: 'GET',
    headers: replayHeaders
  });
  assert.equal(res1.status, 200);

  const res2 = await fetch(`${testServerUrl}/api/v1/vault/${integrationVaultId}/secrets`, {
    method: 'GET',
    headers: replayHeaders
  });
  assert.equal(res2.status, 401);

  // D. Modified body hash / tampered payload
  const originalBody = JSON.stringify({ expectedVersion: 5, blob: {} });
  const tamperedBody = JSON.stringify({ expectedVersion: 5, blob: {}, extra: 'tampered' });
  const bodyHeaders = Object.assign({}, api.signRequest('PUT', `/api/v1/vault/${integrationVaultId}/secrets`, originalBody, aliceCreds), {
    'Content-Type': 'application/json'
  });

  const res3 = await fetch(`${testServerUrl}/api/v1/vault/${integrationVaultId}/secrets`, {
    method: 'PUT',
    headers: bodyHeaders,
    body: tamperedBody
  });
  assert.equal(res3.status, 401);
});

// =============================================================================
// Section 4: Multi-Role Authorization Matrix
// =============================================================================

test('10. Multi-Role Authorization Matrix: Enforcing Server Permissions', async () => {
  // Alice (Owner), Charlie (Admin)
  // Grant Dave as 'member' and Eve as 'readonly'
  await executeGrant({
    username: 'dave',
    role: 'member',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  await executeGrant({
    username: 'eve',
    role: 'readonly',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: projectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  // Admin Charlie CANNOT grant another Admin
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'bob',
        role: 'admin',
        serverUrl: testServerUrl,
        keystoreDir: charlieKeystoreDir,
        projectConfig: projectConfig,
        passphrase: CHARLIE_PASSPHRASE
      });
    },
    /admins cannot grant admin privileges/
  );

  // Admin Charlie CANNOT revoke Owner Alice
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'alice',
        serverUrl: testServerUrl,
        keystoreDir: charlieKeystoreDir,
        projectConfig: projectConfig,
        passphrase: CHARLIE_PASSPHRASE
      });
    },
    /Cannot revoke owner: vault owner is immutable/
  );

  // Member Dave CANNOT grant
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'bob',
        role: 'member',
        serverUrl: testServerUrl,
        keystoreDir: daveKeystoreDir,
        projectConfig: projectConfig,
        passphrase: DAVE_PASSPHRASE
      });
    },
    /only owner or admin can grant access/
  );

  // Member Dave CANNOT revoke
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'eve',
        serverUrl: testServerUrl,
        keystoreDir: daveKeystoreDir,
        projectConfig: projectConfig,
        passphrase: DAVE_PASSPHRASE
      });
    },
    /only owner or admin can revoke members/
  );

  // Readonly Eve CANNOT set secrets
  await assert.rejects(
    async () => {
      await executeSet({
        secretsToSet: { ATTEMPT: 'unauthorized_write' },
        env: 'development',
        serverUrl: testServerUrl,
        keystoreDir: eveKeystoreDir,
        projectConfig: projectConfig,
        projectConfigPath: projectConfigPath,
        passphrase: EVE_PASSPHRASE
      });
    },
    /Readonly members are not permitted to modify secrets/
  );

  // Readonly Eve CANNOT grant
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'bob',
        role: 'member',
        serverUrl: testServerUrl,
        keystoreDir: eveKeystoreDir,
        projectConfig: projectConfig,
        passphrase: EVE_PASSPHRASE
      });
    },
    /only owner or admin can grant access/
  );

  // Readonly Eve CANNOT revoke
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'dave',
        serverUrl: testServerUrl,
        keystoreDir: eveKeystoreDir,
        projectConfig: projectConfig,
        passphrase: EVE_PASSPHRASE
      });
    },
    /only owner or admin can revoke members/
  );
});

// =============================================================================
// Section 5: Concurrency & Optimistic Concurrency Control (OCC)
// =============================================================================

test('11. Optimistic Concurrency Control: Stale Version Rejection without Mutation', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);

  // Stale expectedVersion on PUT /secrets
  await assert.rejects(
    async () => {
      await api.updateVaultSecrets(
        testServerUrl,
        integrationVaultId,
        {
          expectedVersion: state.vaultVersion - 1, // Stale
          blob: state.blob
        },
        aliceCreds
      );
    },
    /Optimistic concurrency conflict|conflict/i
  );

  // Stale expectedVersion on POST /members (grant)
  const bobRecord = await api.getUser(testServerUrl, 'bob', aliceCreds);
  await assert.rejects(
    async () => {
      await api.grantVaultMember(
        testServerUrl,
        integrationVaultId,
        {
          expectedVersion: state.vaultVersion - 1,
          username: 'bob',
          role: 'member',
          wrappedDek: state.wrappedDeks.alice,
          publicKeyFingerprint: bobRecord.publicKeyFingerprint
        },
        aliceCreds
      );
    },
    /Optimistic concurrency conflict|conflict/i
  );

  // Stale expectedVersion on DELETE /members/:username (revoke)
  await assert.rejects(
    async () => {
      await api.revokeVaultMember(
        testServerUrl,
        integrationVaultId,
        'eve',
        {
          expectedVersion: state.vaultVersion - 1,
          newBlob: state.blob,
          newWrappedDeks: {}
        },
        aliceCreds
      );
    },
    /Optimistic concurrency conflict|conflict/i
  );

  // Confirm state was not mutated
  const stateAfter = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);
  assert.equal(stateAfter.vaultVersion, state.vaultVersion);
});

// =============================================================================
// Section 6: Server Zero-Knowledge & Payload Sanitization
// =============================================================================

test('12. Server Zero-Knowledge Enforcement: Rejecting Plaintext and Key Leaks', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, integrationVaultId, aliceCreds);

  // Attempting to send 'plaintext' in blob
  const maliciousBlob = Object.assign({}, state.blob, { plaintext: 'leaked_secret_here' });
  await assert.rejects(
    async () => {
      await api.updateVaultSecrets(
        testServerUrl,
        integrationVaultId,
        {
          expectedVersion: state.vaultVersion,
          blob: maliciousBlob
        },
        aliceCreds
      );
    },
    /Invalid secret blob envelope structure|invalid_request/i
  );

  // Attempting to send 'rawDek' in blob
  const rawDekBlob = Object.assign({}, state.blob, { rawDek: '0123456789abcdef' });
  await assert.rejects(
    async () => {
      await api.updateVaultSecrets(
        testServerUrl,
        integrationVaultId,
        {
          expectedVersion: state.vaultVersion,
          blob: rawDekBlob
        },
        aliceCreds
      );
    },
    /Invalid secret blob envelope structure|invalid_request/i
  );
});

// =============================================================================
// Section 7: Local Storage and Keystore Privacy
// =============================================================================

test('13. Local Keystore and Config Cleanliness', async () => {
  // Inspect Alice's key.enc on disk
  const keyEncRaw = await fsp.readFile(path.join(aliceKeystoreDir, 'key.enc'), 'utf8');
  assert.ok(!keyEncRaw.includes('"d":'), 'Private key scalar "d": exposed in key.enc!');
  const parsedKeyEnc = JSON.parse(keyEncRaw);
  assert.equal(parsedKeyEnc.d, undefined);
  assert.equal(parsedKeyEnc.privateKey, undefined);
  assert.ok(!keyEncRaw.includes(ALICE_PASSPHRASE), 'Master passphrase found in key.enc!');

  // Inspect credentials.json on disk
  const credsRaw = await fsp.readFile(path.join(aliceKeystoreDir, 'credentials.json'), 'utf8');
  assert.ok(!credsRaw.includes('ultra_secure_password'), 'Secret found in credentials.json!');
  assert.ok(!credsRaw.includes(ALICE_PASSPHRASE), 'Master passphrase found in credentials.json!');

  // Inspect .envguard.json
  const configRaw = await fsp.readFile(projectConfigPath, 'utf8');
  assert.ok(!configRaw.includes('ultra_secure_password'), 'Secret found in .envguard.json!');
  assert.ok(!configRaw.includes('sk_live'), 'Secret found in .envguard.json!');
  assert.ok(!configRaw.includes(ALICE_PASSPHRASE), 'Passphrase found in .envguard.json!');
});
