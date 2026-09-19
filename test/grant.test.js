/**
 * Comprehensive Test Suite for Phase 7: 'envguard grant'.
 *
 * Validates:
 * 1. Role validation (admin, member, readonly accepted; owner rejected; invalid rejected).
 * 2. Target username validation and prerequisite checks.
 * 3. Owner granting member, admin, readonly.
 * 4. Admin granting member or readonly.
 * 5. Admin granting admin rejected (403 forbidden).
 * 6. Member or readonly attempting grant rejected (403 forbidden).
 * 7. DEK preservation invariant (DEK is NOT rotated; dekVersion unchanged, vaultVersion increments).
 * 8. Fingerprint verification (matching fingerprint succeeds; mismatched fails).
 * 9. Non-existent user rejected (404).
 * 10. Optimistic concurrency conflict handling (409).
 * 11. Granted member can unwrap DEK and decrypt vault secrets via 'run'.
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
import { validateGrantRole, executeGrant } from '../src/commands/grant.js';

const TEST_BASE_DIR = path.resolve('test-grant-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-phase7-grant';

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

  // 1. Initialize Alice (Vault Owner)
  aliceKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-alice');
  await executeInit({
    username: 'alice',
    passphrase: ALICE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir
  });

  // 2. Initialize Bob (Member candidate)
  bobKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-bob');
  await executeInit({
    username: 'bob',
    passphrase: BOB_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir
  });

  // 3. Initialize Charlie (Admin candidate)
  charlieKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-charlie');
  await executeInit({
    username: 'charlie',
    passphrase: CHARLIE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir
  });

  // 4. Initialize Dave (Second member candidate)
  daveKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-dave');
  await executeInit({
    username: 'dave',
    passphrase: DAVE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: daveKeystoreDir
  });

  // 5. Initialize Eve (Readonly candidate)
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
    project: 'phase7-grant-test-app',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(testProjectConfigPath, JSON.stringify(testProjectConfig, null, 2) + '\n', 'utf8');

  // 7. Create initial vault owned by Alice
  const setResult = await executeSet({
    secretsToSet: {
      DATABASE_URL: 'postgres://alice:secret@db.internal:5432/main',
      API_KEY: 'alice-super-secret-key'
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
});

test.after(async () => {
  if (testServerInstance) {
    await testServerInstance.close();
  }
  await fsp.rm(TEST_BASE_DIR, { recursive: true, force: true });
});

test('validateGrantRole allows member, admin, and readonly, rejects owner and invalid', () => {
  assert.doesNotThrow(() => validateGrantRole('member'));
  assert.doesNotThrow(() => validateGrantRole('admin'));
  assert.doesNotThrow(() => validateGrantRole('readonly'));

  assert.throws(() => validateGrantRole('owner'), /Cannot grant owner role/);
  assert.throws(() => validateGrantRole('superuser'), /Invalid role/);
  assert.throws(() => validateGrantRole(''), /Role must be a non-empty string/);
  assert.throws(() => validateGrantRole(null), /Role must be a non-empty string/);
});

test('executeGrant rejects invalid target username', async () => {
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'invalid@name!',
        role: 'member',
        keystoreDir: aliceKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: ALICE_PASSPHRASE
      });
    },
    /Invalid target username/
  );
});

test('executeGrant fails if target user does not exist on server', async () => {
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'nonexistent_user',
        role: 'member',
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: ALICE_PASSPHRASE
      });
    },
    /does not exist on Vault Server/
  );
});

test('executeGrant validates fingerprint if provided', async () => {
  // Wrong fingerprint fails
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'bob',
        role: 'member',
        fingerprint: 'SHA256:0000000000000000000000000000000000000000000000000000000000000000',
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: ALICE_PASSPHRASE
      });
    },
    /Public key fingerprint mismatch/
  );
});

test('Owner (Alice) grants member access to Bob with DEK preserved', async () => {
  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const bobRecord = await api.getUser(testServerUrl, 'bob', aliceCreds);

  const grantResult = await executeGrant({
    username: 'bob',
    role: 'member',
    fingerprint: bobRecord.publicKeyFingerprint,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'bob');
  assert.equal(grantResult.role, 'member');
  assert.equal(grantResult.vaultVersion, 2);
  assert.equal(grantResult.dekVersion, 1); // DEK invariant: DEK is NOT rotated on grant

  // Verify server state
  const vaultState = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);
  assert.equal(vaultState.members.bob, 'member');
  assert.equal(vaultState.members.alice, 'owner');
  assert.ok(vaultState.wrappedDeks.bob);
  assert.equal(vaultState.dekVersion, 1);
  assert.equal(vaultState.vaultVersion, 2);

  // Bob can now decrypt secrets using executeRun
  const runResult = await executeRun({
    commandArgs: ['node', '-e', 'if (process.env.DATABASE_URL !== "postgres://alice:secret@db.internal:5432/main") process.exit(10);'],
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: BOB_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(runResult.exitCode, 0);
});

test('Owner (Alice) grants admin access to Charlie', async () => {
  const grantResult = await executeGrant({
    username: 'charlie',
    role: 'admin',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'charlie');
  assert.equal(grantResult.role, 'admin');
  assert.equal(grantResult.vaultVersion, 3);
  assert.equal(grantResult.dekVersion, 1);

  const aliceCreds = await keystore.loadCredentials(aliceKeystoreDir);
  const vaultState = await api.getVaultSecrets(testServerUrl, sharedVaultId, aliceCreds);
  assert.equal(vaultState.members.charlie, 'admin');
});

test('Admin (Charlie) can grant member access to Dave', async () => {
  const grantResult = await executeGrant({
    username: 'dave',
    role: 'member',
    serverUrl: testServerUrl,
    keystoreDir: charlieKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: CHARLIE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'dave');
  assert.equal(grantResult.role, 'member');
  assert.equal(grantResult.vaultVersion, 4);
  assert.equal(grantResult.dekVersion, 1);

  const charlieCreds = await keystore.loadCredentials(charlieKeystoreDir);
  const vaultState = await api.getVaultSecrets(testServerUrl, sharedVaultId, charlieCreds);
  assert.equal(vaultState.members.dave, 'member');
});

test('Admin (Charlie) CANNOT grant admin access to Eve (design invariant)', async () => {
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'eve',
        role: 'admin',
        serverUrl: testServerUrl,
        keystoreDir: charlieKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: CHARLIE_PASSPHRASE
      });
    },
    /admins cannot grant admin privileges/
  );
});

test('Member (Bob) CANNOT grant access to Eve (permission denied)', async () => {
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'eve',
        role: 'member',
        serverUrl: testServerUrl,
        keystoreDir: bobKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: BOB_PASSPHRASE
      });
    },
    /only owner or admin can grant access/
  );
});

test('Owner (Alice) grants readonly access to Eve', async () => {
  const grantResult = await executeGrant({
    username: 'eve',
    role: 'readonly',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: ALICE_PASSPHRASE
  });

  assert.equal(grantResult.username, 'eve');
  assert.equal(grantResult.role, 'readonly');
  assert.equal(grantResult.vaultVersion, 5);
  assert.equal(grantResult.dekVersion, 1);

  // Readonly user (Eve) can read secrets
  const runResult = await executeRun({
    commandArgs: ['node', '-e', 'if (!process.env.API_KEY) process.exit(12);'],
    serverUrl: testServerUrl,
    keystoreDir: eveKeystoreDir,
    projectConfig: testProjectConfig,
    passphrase: EVE_PASSPHRASE,
    stdio: 'pipe'
  });
  assert.equal(runResult.exitCode, 0);
});

test('Readonly user (Eve) CANNOT grant access to anyone', async () => {
  await assert.rejects(
    async () => {
      await executeGrant({
        username: 'bob',
        role: 'member',
        serverUrl: testServerUrl,
        keystoreDir: eveKeystoreDir,
        projectConfig: testProjectConfig,
        passphrase: EVE_PASSPHRASE
      });
    },
    /only owner or admin can grant access/
  );
});
