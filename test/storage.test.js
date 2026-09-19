/**
 * Test suite for Vault Server storage layer.
 *
 * This file is part of Phase 3 (Vault Server & Storage).
 * Tests atomic writes, concurrency mutex serialization, path traversal rejection,
 * exclusive vault creation races, and failure cleanup.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Storage, isValidVaultId, isValidUsername, atomicWriteJson } from '../src/server/storage.js';

const TEST_DATA_DIR = path.resolve('test-storage-data-' + crypto.randomBytes(4).toString('hex'));

test.before(async function() {
  await fs.promises.mkdir(TEST_DATA_DIR, { recursive: true });
});

test.after(async function() {
  try {
    await fs.promises.rm(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch (err) {
    // Ignore cleanup error
  }
});

test('Storage: Path Traversal and Identifier Validation', async function(t) {
  await t.test('isValidVaultId accepts safe identifiers', function() {
    assert.strictEqual(isValidVaultId('my-app-development-a7f3c92b8e14d056'), true);
    assert.strictEqual(isValidVaultId('vault_123'), true);
    assert.strictEqual(isValidVaultId('a-b-c'), true);
  });

  await t.test('isValidVaultId rejects traversal and dangerous characters', function() {
    assert.strictEqual(isValidVaultId('..'), false);
    assert.strictEqual(isValidVaultId('.'), false);
    assert.strictEqual(isValidVaultId('../users.json'), false);
    assert.strictEqual(isValidVaultId('../../users.json'), false);
    assert.strictEqual(isValidVaultId('vault/sub'), false);
    assert.strictEqual(isValidVaultId('vault\\sub'), false);
    assert.strictEqual(isValidVaultId('C:\\Windows\\System32'), false);
    assert.strictEqual(isValidVaultId('/etc/passwd'), false);
    assert.strictEqual(isValidVaultId(''), false);
    assert.strictEqual(isValidVaultId('a'.repeat(129)), false);
    assert.strictEqual(isValidVaultId('vault@name'), false);
    assert.strictEqual(isValidVaultId('vault$name'), false);
    assert.strictEqual(isValidVaultId(null), false);
    assert.strictEqual(isValidVaultId(123), false);
  });

  await t.test('isValidUsername rejects dangerous usernames', function() {
    assert.strictEqual(isValidUsername('alice'), true);
    assert.strictEqual(isValidUsername('bob.smith_1'), true);
    assert.strictEqual(isValidUsername('..'), false);
    assert.strictEqual(isValidUsername('.'), false);
    assert.strictEqual(isValidUsername('../alice'), false);
    assert.strictEqual(isValidUsername('alice/admin'), false);
    assert.strictEqual(isValidUsername('alice\\admin'), false);
    assert.strictEqual(isValidUsername(''), false);
    assert.strictEqual(isValidUsername('a'.repeat(65)), false);
  });
});

test('Storage: Directory Initialization & Atomic Writes', async function(t) {
  const subDataDir = path.join(TEST_DATA_DIR, 'init-test');
  const storage = new Storage(subDataDir);

  await t.test('init creates directory layout and empty users.json', async function() {
    await storage.init();

    const usersExists = await fs.promises.access(storage.usersFilePath, fs.constants.F_OK)
      .then(function() { return true; })
      .catch(function() { return false; });
    assert.strictEqual(usersExists, true);

    const vaultsDirExists = await fs.promises.access(storage.vaultsDirPath, fs.constants.F_OK)
      .then(function() { return true; })
      .catch(function() { return false; });
    assert.strictEqual(vaultsDirExists, true);

    const initialUsers = await storage.readUsersRaw();
    assert.deepStrictEqual(initialUsers, {});
  });

  await t.test('atomicWriteJson flushes and renames safely', async function() {
    const testFile = path.join(subDataDir, 'atomic-test.json');
    const data = { hello: 'world', version: 1 };
    await atomicWriteJson(testFile, data);

    const content = await fs.promises.readFile(testFile, 'utf8');
    assert.deepStrictEqual(JSON.parse(content), data);

    // Ensure no dangling .tmp files in the directory
    const files = await fs.promises.readdir(subDataDir);
    const tmpFiles = files.filter(function(f) {
      return f.endsWith('.tmp');
    });
    assert.strictEqual(tmpFiles.length, 0);
  });

  await t.test('path traversal in getVaultFilePath throws error', function() {
    assert.throws(function() {
      storage.getVaultFilePath('../escaped');
    }, function(err) {
      return err.code === 'ERR_INVALID_VAULT_ID' || err.code === 'ERR_PATH_TRAVERSAL';
    });
  });
});

test('Storage: Users Serialization and Mutex', async function(t) {
  const subDataDir = path.join(TEST_DATA_DIR, 'users-test');
  const storage = new Storage(subDataDir);
  await storage.init();

  await t.test('createUser persists user safely', async function() {
    const userRecord = {
      username: 'alice',
      publicKey: { kty: 'OKP', crv: 'X25519', x: '3p9XoqpxbmgqwSqtWzg5VSDppE1plEL8y0zO2bZ_V0U' },
      publicKeyFingerprint: 'SHA256:7b5d92a1c4e8f0b3e6d9a2c5b8e1f4a7d0c3e6b9a2c5d8e1f4a7b0c3e6d9a2c5',
      authVerifier: 'a'.repeat(128),
      salt: 'b'.repeat(32),
      createdAt: new Date().toISOString(),
      status: 'active'
    };

    await storage.createUser(userRecord);
    const fetched = await storage.getUser('alice');
    assert.strictEqual(fetched.username, 'alice');
    assert.strictEqual(fetched.publicKeyFingerprint, userRecord.publicKeyFingerprint);
  });

  await t.test('duplicate username creation is rejected with ERR_USER_EXISTS', async function() {
    const userRecord = {
      username: 'alice',
      authVerifier: 'c'.repeat(128)
    };

    await assert.rejects(async function() {
      await storage.createUser(userRecord);
    }, function(err) {
      return err.code === 'ERR_USER_EXISTS';
    });
  });

  await t.test('concurrent createUser operations are serialized without corruption', async function() {
    const operations = [];
    for (let i = 0; i < 10; i++) {
      const uname = 'user_' + i;
      const rec = {
        username: uname,
        authVerifier: 'x'.repeat(128),
        status: 'active'
      };
      operations.push(storage.createUser(rec));
    }

    await Promise.all(operations);

    const allUsers = await storage.readUsersRaw();
    for (let i = 0; i < 10; i++) {
      assert.strictEqual(allUsers['user_' + i].username, 'user_' + i);
    }
  });
});

test('Storage: Vault Creation Races and Per-Vault Mutex', async function(t) {
  const subDataDir = path.join(TEST_DATA_DIR, 'vault-test');
  const storage = new Storage(subDataDir);
  await storage.init();

  const vaultId = 'project-dev-1234567890abcdef';
  const initialVault = {
    vaultId: vaultId,
    vaultVersion: 1,
    dekVersion: 1,
    owner: 'alice',
    members: { alice: 'owner' },
    blob: { algorithm: 'aes-256-gcm', dekVersion: 1, iv: 'a'.repeat(24), tag: 'b'.repeat(32), ciphertext: 'c'.repeat(32), aad: vaultId + ':1' },
    wrappedDeks: {}
  };

  await t.test('createVault creates vault successfully', async function() {
    await storage.createVault(vaultId, initialVault);
    const fetched = await storage.getVault(vaultId);
    assert.strictEqual(fetched.vaultId, vaultId);
    assert.strictEqual(fetched.vaultVersion, 1);
  });

  await t.test('exclusive creation rejects duplicate vault creation with ERR_VAULT_EXISTS', async function() {
    await assert.rejects(async function() {
      await storage.createVault(vaultId, initialVault);
    }, function(err) {
      return err.code === 'ERR_VAULT_EXISTS';
    });
  });

  await t.test('mutateVault serializes concurrent mutations and updates state atomically', async function() {
    const increments = 10;
    const promises = [];

    for (let i = 0; i < increments; i++) {
      promises.push(storage.mutateVault(vaultId, function(current) {
        current.vaultVersion = current.vaultVersion + 1;
        return current;
      }));
    }

    await Promise.all(promises);

    const finalVault = await storage.getVault(vaultId);
    // Initial was 1, 10 sequential increments -> 11
    assert.strictEqual(finalVault.vaultVersion, 1 + increments);
  });

  await t.test('mutateVault throws ERR_VAULT_NOT_FOUND when vault does not exist', async function() {
    await assert.rejects(async function() {
      await storage.mutateVault('nonexistent-vault', function(current) {
        return current;
      });
    }, function(err) {
      return err.code === 'ERR_VAULT_NOT_FOUND';
    });
  });
});
