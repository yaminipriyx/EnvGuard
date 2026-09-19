/**
 * Comprehensive Test Suite for Phase 7: 'envguard revoke' & DEK Rotation.
 *
 * Validates:
 * 1. Target validation (cannot revoke self, target must be member).
 * 2. Owner immutability (owner cannot be revoked by anyone).
 * 3. Member / Readonly revoking permissions rejected (403 forbidden).
 * 4. Admin revoking restrictions (cannot revoke owner, cannot revoke another admin).
 * 5. Admin can revoke regular member.
 * 6. Owner can revoke member.
 * 7. Mandatory DEK rotation: dekVersion increments, vaultVersion increments, fresh DEK generated.
 * 8. Authoritative membership: remaining members source of truth is authoritative members map.
 * 9. Cryptographic Regression Tests:
 *    - Revoked user's old DEK CANNOT decrypt the rotated secret blob (fails auth tag verification).
 *    - Revoked user is completely absent from new wrappedDeks.
 *    - Revoked user's 'run' command fails (access denied).
 *    - Remaining members successfully decrypt rotated secrets via 'run'.
 *    - Each remaining member's wrapped DEK AAD is ${vaultId}:${newDekVersion}:${username}.
 *    - Rotated secret blob AAD is ${vaultId}:${newDekVersion}.
 * 10. Optimistic concurrency conflict handling (409).
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
import * as envelope from '../src/crypto/envelope.js';
import { executeInit } from '../src/commands/init.js';
import { executeSet } from '../src/commands/set.js';
import { executeRun } from '../src/commands/run.js';
import { executeGrant } from '../src/commands/grant.js';
import { executeRevoke } from '../src/commands/revoke.js';

const TEST_BASE_DIR = path.resolve('test-revoke-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-phase7-revoke';

let testServerInstance = null;
let testServerPort = 0;
let testServerUrl = '';

const ALICE_PASSPHRASE = 'alice-master-passphrase-12345';
const BOB_PASSPHRASE = 'bob-master-passphrase-12345';
const CHARLIE_PASSPHRASE = 'charlie-master-passphrase-12345';
const DAVE_PASSPHRASE = 'dave-master-passphrase-12345';
const EVE_PASSPHRASE = 'eve-master-passphrase-12345';

let aliceKeystoreDir = '';
let bobKeystoreDir = '';
let charlieKeystoreDir = '';
let daveKeystoreDir = '';
let eveKeystoreDir = '';

let testProjectConfig = null;
let testProjectConfigPath = '';
let sharedVaultId = '';

let bobOldUnwrappedDek = null;

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

  // 1. Initialize Alice (Owner)
  aliceKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-alice');
  await executeInit({
    username: 'alice',
    passphrase: ALICE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir
  });

  // 2. Initialize Bob (Member to be revoked)
  bobKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-bob');
  await executeInit({
    username: 'bob',
    passphrase: BOB_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir
  });

  // 3. Initialize Charlie (Admin)
  charlieKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-charlie');
  await executeInit({
    username: 'charlie',
    passphrase: CHARLIE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir
  });

  // 4. Initialize Dave (Second admin candidate)
  daveKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-dave');
  await executeInit({
    username: 'dave',
    passphrase: DAVE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: daveKeystoreDir
  });

  // 5. Initialize Eve (Readonly member)
  eveKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-eve');
  await executeInit({
    username: 'eve',
    passphrase: EVE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: eveKeystoreDir
  });

  // 6. Project configuration
  testProjectConfigPath = path.join(TEST_BASE_DIR, '.envguard.json');
  testProjectConfig = {
    version: 1,
    project: 'phase7-revoke-test-app',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(testProjectConfigPath, JSON.stringify(testProjectConfig, null, 2) + '\n', 'utf8');

  // 7. Alice creates initial vault with secrets
  const setResult = await executeSet({
    secretsToSet: {
      API_SECRET: 'production-super-secret-token-v1',
      DATABASE_HOST: 'db.prod.internal'
    },
    env: 'development',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    projectConfigPath: testProjectConfigPath,
    passphrase: ALICE_PASSPHRASE
  });

  sharedVaultId = setResult.vaultId;
  testProjectConfig.environments.development = sharedVaultId;
  await fsp.writeFile(testProjectConfigPath, JSON.stringify(testProjectConfig, null, 2) + '\n', 'utf8');

  // 8. Grant Bob (member), Charlie (admin), Dave (admin), Eve (readonly)
  await executeGrant({
    username: 'bob',
    role: 'member',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  await executeGrant({
    username: 'charlie',
    role: 'admin',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  await executeGrant({
    username: 'dave',
    role: 'admin',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  await executeGrant({
    username: 'eve',
    role: 'readonly',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  // 9. Bob unwraps and saves a copy of old DEK (dekVersion = 1) for regression verification
  const bobCreds = await keystore.loadCredentials(bobKeystoreDir);
  const initialVaultState = await api.getVaultSecrets(testServerUrl, sharedVaultId, bobCreds);
  const bobKeyEnvelope = await keystore.loadKeyEnvelope(bobKeystoreDir);
  const bobPrivateKeyJwk = envelope.openPrivateKeyEnvelope(bobKeyEnvelope, BOB_PASSPHRASE);
  bobOldUnwrappedDek = envelope.openWrappedDekEnvelope(
    initialVaultState.wrappedDeks.bob,
    bobPrivateKeyJwk,
    sharedVaultId,
    1,
    'bob'
  );
});

test.after(async () => {
  if (bobOldUnwrappedDek) {
    bobOldUnwrappedDek.fill(0);
  }
  if (testServerInstance) {
    await testServerInstance.close();
  }
  try {
    await fsp.rm(TEST_BASE_DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch (err) {
    // Ignore cleanup error on Windows
  }
});

test('executeRevoke rejects caller attempting to revoke self', async () => {
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'alice',
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: ALICE_PASSPHRASE
      });
    },
    /Cannot revoke yourself/
  );
});

test('executeRevoke rejects revoking the vault owner', async () => {
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'alice',
        serverUrl: testServerUrl,
        keystoreDir: charlieKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: CHARLIE_PASSPHRASE
      });
    },
    /Cannot revoke owner: vault owner is immutable/
  );
});

test('executeRevoke rejects revoking non-member', async () => {
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'nonexistent_user',
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: ALICE_PASSPHRASE
      });
    },
    /is not a member of vault/
  );
});

test('Member (Bob) CANNOT revoke another member (permission denied)', async () => {
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'eve',
        serverUrl: testServerUrl,
        keystoreDir: bobKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: BOB_PASSPHRASE
      });
    },
    /only owner or admin can revoke members/
  );
});

test('Admin (Charlie) CANNOT revoke another Admin (Dave)', async () => {
  await assert.rejects(
    async () => {
      await executeRevoke({
        username: 'dave',
        serverUrl: testServerUrl,
        keystoreDir: charlieKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: CHARLIE_PASSPHRASE
      });
    },
    /admins cannot revoke another admin or owner/
  );
});

test('Admin (Charlie) can revoke a regular member (Eve)', async () => {
  const charlieCreds = await keystore.loadCredentials(charlieKeystoreDir);
  const beforeState = await api.getVaultSecrets(testServerUrl, sharedVaultId, charlieCreds);

  const revokeResult = await executeRevoke({
    username: 'eve',
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: CHARLIE_PASSPHRASE
  });

  assert.equal(revokeResult.username, 'eve');
  assert.equal(revokeResult.vaultVersion, beforeState.vaultVersion + 1);
  assert.equal(revokeResult.dekVersion, beforeState.dekVersion + 1);

  const afterState = await api.getVaultSecrets(testServerUrl, sharedVaultId, charlieCreds);
  assert.equal(afterState.members.eve, undefined);
  assert.equal(afterState.wrappedDeks.eve, undefined);
});

test('Owner (Alice) revokes Bob with DEK rotation and atomic commitment', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const stateBefore = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);

  const revokeResult = await executeRevoke({
    username: 'bob',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(revokeResult.username, 'bob');
  assert.equal(revokeResult.vaultVersion, stateBefore.vaultVersion + 1);
  assert.equal(revokeResult.dekVersion, stateBefore.dekVersion + 1);
  assert.deepEqual(revokeResult.remainingMembers.sort(), ['alice', 'charlie', 'dave'].sort());

  const stateAfter = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);

  // 1. Authoritative membership verification
  assert.equal(stateAfter.members.bob, undefined);
  assert.equal(stateAfter.wrappedDeks.bob, undefined);
  assert.ok(stateAfter.members.alice);
  assert.ok(stateAfter.members.charlie);
  assert.ok(stateAfter.members.dave);

  // 2. AAD Verification
  const expectedBlobAad = `${sharedVaultId}:${stateAfter.dekVersion}`;
  assert.equal(stateAfter.blob.aad, expectedBlobAad);
  assert.equal(stateAfter.blob.dekVersion, stateAfter.dekVersion);

  assert.equal(stateAfter.wrappedDeks.alice.aad, `${sharedVaultId}:${stateAfter.dekVersion}:alice`);
  assert.equal(stateAfter.wrappedDeks.charlie.aad, `${sharedVaultId}:${stateAfter.dekVersion}:charlie`);
  assert.equal(stateAfter.wrappedDeks.dave.aad, `${sharedVaultId}:${stateAfter.dekVersion}:dave`);
});

test('CRYPTOGRAPHIC REGRESSION: Bob old DEK cannot decrypt the rotated secret blob', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const rotatedVaultState = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);

  // Attempt to decrypt the new rotated blob using Bob's old unwrapped DEK (from dekVersion = 1)
  assert.throws(
    () => {
      envelope.openSecretEnvelope(
        rotatedVaultState.blob,
        bobOldUnwrappedDek,
        sharedVaultId,
        rotatedVaultState.dekVersion
      );
    },
    /Decryption failed|authentication tag verification failed|tag mismatch/i
  );
});

test('CRYPTOGRAPHIC REGRESSION: Revoked user Bob cannot run and is denied vault access', async () => {
  await assert.rejects(
    async () => {
      await executeRun({
        commandArgs: ['node', '-e', 'process.exit(0);'],
        serverUrl: testServerUrl,
        keystoreDir: bobKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: BOB_PASSPHRASE,
        stdio: 'pipe'
      });
    },
    /Access denied: caller is not an authorized vault member/
  );
});

test('Remaining members (Alice, Charlie, Dave) can successfully unwrap new DEK and read secrets', async () => {
  // Alice runs command and reads secret
  const aliceRun = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.API_SECRET !== "production-super-secret-token-v1") process.exit(20);'],
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(aliceRun.exitCode, 0);

  // Charlie runs command and reads secret
  const charlieRun = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.DATABASE_HOST !== "db.prod.internal") process.exit(21);'],
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: CHARLIE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(charlieRun.exitCode, 0);

  // Dave runs command and reads secret
  const daveRun = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.API_SECRET !== "production-super-secret-token-v1") process.exit(22);'],
    serverUrl: testServerUrl,
    keystoreDir: daveKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: DAVE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(daveRun.exitCode, 0);
});

test('Optimistic concurrency conflict rejects revoke on mismatched expectedVersion', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const state = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);

  // Send an outdated expectedVersion (e.g. 1) to DELETE endpoint
  await assert.rejects(
    async () => {
      await api.revokeVaultMember(
        testServerUrl,
        sharedVaultId,
        'dave',
        {
          expectedVersion: 1, // Stale version
          newBlob: state.blob,
          newWrappedDeks: {}
        },
        aliceCreds
      );
    },
    /Optimistic concurrency conflict|conflict|409/i
  );
});
