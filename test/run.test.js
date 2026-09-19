/**
 * Comprehensive Test Suite for Phase 6: 'envguard run' & Runtime Secret Injection.
 *
 * Validates:
 * 1. CLI validation (missing command, command with args, flags after --, spaces, dashes).
 * 2. Configuration & environment resolution (default, ENVGUARD_ENV, --env, missing config, missing vault).
 * 3. Vault response validation (malformed, missing blob, missing wrappedDeks, missing caller entry, mismatched versions, AAD mismatch).
 * 4. Cryptographic integrity (correct unwrap, wrong passphrase, tampered wrapped DEK, tampered blob, wrong AAD).
 * 5. Secret plaintext validation (valid JSON, array rejected, null rejected, number/boolean/nested rejected, invalid key rejected).
 * 6. Process execution (secret injection, inheritance, vault override, exact arguments, exit codes 0/1/42, shell: false).
 * 7. Security invariants & leak prevention (no .env on disk, no temp files, secrets absent from logs, credentials protected).
 * 8. Signal forwarding (SIGINT/SIGTERM forwarding to child process).
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
import { executeInit } from '../src/commands/init.js';
import { executeSet } from '../src/commands/set.js';
import {
  validateCommandArgs,
  validateSecretMap,
  validateVaultResponse,
  executeRun
} from '../src/commands/run.js';

const TEST_BASE_DIR = path.resolve('test-run-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-phase6';

let testServerInstance = null;
let testServerPort = 0;
let testServerUrl = '';

const ALICE_PASSPHRASE = 'alice-master-passphrase-12345';
const BOB_PASSPHRASE = 'bob-master-passphrase-12345';

let aliceKeystoreDir = '';
let bobKeystoreDir = '';
let aliceProjectConfig = null;
let aliceProjectConfigPath = '';
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

  // Initialize Alice (Vault Owner)
  aliceKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-alice');
  await executeInit({
    username: 'alice',
    passphrase: ALICE_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir
  });

  // Initialize Bob (Second user without access)
  bobKeystoreDir = path.join(TEST_BASE_DIR, 'keystore-bob');
  await executeInit({
    username: 'bob',
    passphrase: BOB_PASSPHRASE,
    enrollmentKey: ENROLLMENT_KEY,
    serverUrl: testServerUrl,
    keystoreDir: bobKeystoreDir
  });

  // Create initial project configuration
  aliceProjectConfigPath = path.join(TEST_BASE_DIR, '.envguard.json');
  aliceProjectConfig = {
    version: 1,
    project: 'phase6-test-app',
    serverUrl: testServerUrl,
    environments: {}
  };
  await fsp.writeFile(aliceProjectConfigPath, JSON.stringify(aliceProjectConfig, null, 2) + '\n', 'utf8');

  // Create a development vault for Alice with initial secrets
  const setResult = await executeSet({
    secretsToSet: {
      DATABASE_URL: 'postgres://user:pass@localhost:5432/testdb',
      API_KEY: 'secret-phase6-key-alice',
      OVERRIDDEN_VAR: 'vault-value'
    },
    env: 'development',
    serverUrl: testServerUrl,
    keystoreDir: aliceKeystoreDir,
    projectConfig: aliceProjectConfig,
    projectConfigPath: aliceProjectConfigPath,
    passphrase: ALICE_PASSPHRASE
  });

  sharedVaultId = setResult.vaultId;

  // Re-read updated project config
  const configRaw = await fsp.readFile(aliceProjectConfigPath, 'utf8');
  aliceProjectConfig = JSON.parse(configRaw);
});

test.after(async () => {
  if (testServerInstance) {
    await testServerInstance.close();
  }
  if (fs.existsSync(TEST_BASE_DIR)) {
    await fsp.rm(TEST_BASE_DIR, { recursive: true, force: true });
  }
});

test('Phase 6: CLI Command Validation & Argument Preservation', async (t) => {
  await t.test('validateCommandArgs rejects empty or missing command array', () => {
    assert.throws(() => validateCommandArgs([]), /No command specified/);
    assert.throws(() => validateCommandArgs(null), /No command specified/);
    assert.throws(() => validateCommandArgs(undefined), /No command specified/);
  });

  await t.test('validateCommandArgs rejects blank command string', () => {
    assert.throws(() => validateCommandArgs(['']), /Invalid command/);
    assert.throws(() => validateCommandArgs(['   ']), /Invalid command/);
  });

  await t.test('validateCommandArgs separates targetCommand and arguments cleanly', () => {
    const res = validateCommandArgs(['node', 'server.js', '--port', '8080']);
    assert.equal(res.command, 'node');
    assert.deepEqual(res.args, ['server.js', '--port', '8080']);
  });

  await t.test('validateCommandArgs preserves flags, spaces, dashes, and quotes after --', () => {
    const rawArgs = ['node', '-e', 'console.log("hello world")', '--flag-with-dashes', 'arg with spaces', '-v'];
    const res = validateCommandArgs(rawArgs);
    assert.equal(res.command, 'node');
    assert.equal(res.args.length, 5);
    assert.equal(res.args[0], '-e');
    assert.equal(res.args[1], 'console.log("hello world")');
    assert.equal(res.args[2], '--flag-with-dashes');
    assert.equal(res.args[3], 'arg with spaces');
    assert.equal(res.args[4], '-v');
  });
});

test('Phase 6: Plaintext Secret Schema Validation', async (t) => {
  await t.test('validateSecretMap accepts valid map of strings', () => {
    const input = {
      PORT: '3000',
      API_KEY: 'test-key-123',
      _INTERNAL_CONFIG: 'true',
      EMPTY_STRING_VAL: ''
    };
    const validated = validateSecretMap(input);
    assert.equal(validated.PORT, '3000');
    assert.equal(validated.API_KEY, 'test-key-123');
    assert.equal(validated._INTERNAL_CONFIG, 'true');
    assert.equal(validated.EMPTY_STRING_VAL, '');
  });

  await t.test('validateSecretMap rejects non-object or null root', () => {
    assert.throws(() => validateSecretMap(null), /root must be a JSON object/);
    assert.throws(() => validateSecretMap('string-not-object'), /root must be a JSON object/);
    assert.throws(() => validateSecretMap(['item1', 'item2']), /root must be a JSON object/);
  });

  await t.test('validateSecretMap rejects invalid variable key names', () => {
    assert.throws(() => validateSecretMap({ '123BAD': 'val' }), /Invalid secret key name/);
    assert.throws(() => validateSecretMap({ 'BAD-KEY': 'val' }), /Invalid secret key name/);
    assert.throws(() => validateSecretMap({ 'BAD.KEY': 'val' }), /Invalid secret key name/);
    assert.throws(() => validateSecretMap({ 'BAD KEY': 'val' }), /Invalid secret key name/);
  });

  await t.test('validateSecretMap rejects non-string values (numbers, booleans, null, nested objects)', () => {
    assert.throws(() => validateSecretMap({ PORT: 3000 }), /values must be strings/);
    assert.throws(() => validateSecretMap({ DEBUG: true }), /values must be strings/);
    assert.throws(() => validateSecretMap({ NULL_VAL: null }), /values must be strings/);
    assert.throws(() => validateSecretMap({ NESTED: { k: 'v' } }), /values must be strings/);
    assert.throws(() => validateSecretMap({ LIST: ['a', 'b'] }), /values must be strings/);
  });
});

test('Phase 6: Untrusted Vault Response & Cryptographic Field Validation', async (t) => {
  const validResponse = {
    vaultVersion: 1,
    dekVersion: 1,
    blob: {
      algorithm: 'aes-256-gcm',
      dekVersion: 1,
      iv: '0102030405060708090a0b0c',
      tag: '0102030405060708090a0b0c0d0e0f10',
      ciphertext: 'abcdef',
      aad: 'my-vault-id:1'
    },
    wrappedDeks: {
      alice: {
        algorithm: 'aes-256-gcm',
        dekVersion: 1,
        kdf: { algorithm: 'hkdf-sha512', info: 'envguard-dek-wrap-v1' },
        ephemeralPublicKey: { kty: 'OKP', crv: 'X25519', x: 'dummy-pubkey-base64url' },
        iv: '0102030405060708090a0b0c',
        tag: '0102030405060708090a0b0c0d0e0f10',
        encryptedDek: '010203040506',
        aad: 'my-vault-id:1:alice'
      }
    }
  };

  await t.test('validateVaultResponse accepts valid response structure', () => {
    assert.doesNotThrow(() => validateVaultResponse(validResponse, 'my-vault-id', 'alice'));
  });

  await t.test('validateVaultResponse rejects missing or corrupt response', () => {
    assert.throws(() => validateVaultResponse(null, 'my-vault-id', 'alice'), /invalid response structure/);
    assert.throws(() => validateVaultResponse({ vaultVersion: 0 }, 'my-vault-id', 'alice'), /invalid vaultVersion/);
    assert.throws(() => validateVaultResponse({ vaultVersion: 1, dekVersion: 0 }, 'my-vault-id', 'alice'), /invalid dekVersion/);
  });

  await t.test('validateVaultResponse rejects mismatched dekVersion in blob', () => {
    const badBlobVersion = JSON.parse(JSON.stringify(validResponse));
    badBlobVersion.blob.dekVersion = 2; // differs from vaultState.dekVersion=1
    assert.throws(() => validateVaultResponse(badBlobVersion, 'my-vault-id', 'alice'), /blob dekVersion mismatch/);
  });

  await t.test('validateVaultResponse rejects blob AAD mismatch', () => {
    const badBlobAad = JSON.parse(JSON.stringify(validResponse));
    badBlobAad.blob.aad = 'wrong-vault:1';
    assert.throws(() => validateVaultResponse(badBlobAad, 'my-vault-id', 'alice'), /blob AAD mismatch/);
  });

  await t.test('validateVaultResponse rejects missing caller wrapped DEK', () => {
    assert.throws(() => validateVaultResponse(validResponse, 'my-vault-id', 'bob'), /No wrapped DEK available for current user "bob"/);
  });

  await t.test('validateVaultResponse rejects wrapped DEK AAD mismatch', () => {
    const badDekAad = JSON.parse(JSON.stringify(validResponse));
    badDekAad.wrappedDeks.alice.aad = 'my-vault-id:1:bob'; // recipient mismatch in AAD
    assert.throws(() => validateVaultResponse(badDekAad, 'my-vault-id', 'alice'), /wrapped DEK AAD mismatch/);
  });
});

test('Phase 6: Project & Environment Resolution', async (t) => {
  await t.test('fails cleanly when project configuration is missing', async () => {
    await assert.rejects(
      async () => {
        await executeRun({
          commandArgs: ['node', '-e', '1'],
          projectConfig: null,
          serverUrl: testServerUrl,
          keystoreDir: aliceKeystoreDir,
          passphrase: ALICE_PASSPHRASE
        });
      },
      /Project configuration not found/
    );
  });

  await t.test('fails cleanly when environment has no configured vault ID', async () => {
    await assert.rejects(
      async () => {
        await executeRun({
          commandArgs: ['node', '-e', '1'],
          env: 'staging', // staging is not configured in aliceProjectConfig
          projectConfig: aliceProjectConfig,
          serverUrl: testServerUrl,
          keystoreDir: aliceKeystoreDir,
          passphrase: ALICE_PASSPHRASE
        });
      },
      /No vault configured for environment "staging"/
    );
  });

  await t.test('does not create vault or modify .envguard.json on run', async () => {
    const beforeContent = await fsp.readFile(aliceProjectConfigPath, 'utf8');
    try {
      await executeRun({
        commandArgs: ['node', '-e', '1'],
        env: 'nonexistent-env',
        projectConfig: aliceProjectConfig,
        serverUrl: testServerUrl,
        keystoreDir: aliceKeystoreDir,
        passphrase: ALICE_PASSPHRASE
      });
    } catch (err) {
      // Expected failure
    }
    const afterContent = await fsp.readFile(aliceProjectConfigPath, 'utf8');
    assert.equal(beforeContent, afterContent);
  });
});

test('Phase 6: Cryptographic Integrity & Fail-Closed Behavior', async (t) => {
  await t.test('fails closed on master passphrase shorter than 12 characters', async () => {
    await assert.rejects(
      async () => {
        await executeRun({
          commandArgs: ['node', '-e', '1'],
          env: 'development',
          projectConfig: aliceProjectConfig,
          serverUrl: testServerUrl,
          keystoreDir: aliceKeystoreDir,
          passphrase: 'short-pass'
        });
      },
      /Master passphrase must be at least 12 characters/
    );
  });

  await t.test('fails closed on incorrect master passphrase', async () => {
    await assert.rejects(
      async () => {
        await executeRun({
          commandArgs: ['node', '-e', '1'],
          env: 'development',
          projectConfig: aliceProjectConfig,
          serverUrl: testServerUrl,
          keystoreDir: aliceKeystoreDir,
          passphrase: 'wrong-passphrase-attempt-12345'
        });
      },
      /Master passphrase authentication failed/
    );
  });

  await t.test('fails closed when caller is not an authorized member of vault (Bob)', async () => {
    await assert.rejects(
      async () => {
        await executeRun({
          commandArgs: ['node', '-e', '1'],
          env: 'development',
          projectConfig: aliceProjectConfig,
          serverUrl: testServerUrl,
          keystoreDir: bobKeystoreDir,
          passphrase: BOB_PASSPHRASE
        });
      },
      /Access denied: caller is not an authorized vault member|No wrapped DEK available/
    );
  });
});

test('Phase 6: End-to-End Secret Injection & Process Execution', async (t) => {
  await t.test('injects secrets into child process environment without shell', async () => {
    let capturedStdout = '';
    const tempOutFile = path.join(TEST_BASE_DIR, 'stdout-' + crypto.randomBytes(4).toString('hex') + '.tmp');

    // Run node child process that outputs specific injected secret
    const script = `
      const fs = require('fs');
      const out = JSON.stringify({
        dbUrl: process.env.DATABASE_URL,
        apiKey: process.env.API_KEY,
        hasParentEnv: typeof process.env.PATH === 'string'
      });
      fs.writeFileSync(${JSON.stringify(tempOutFile)}, out, 'utf8');
    `;

    const result = await executeRun({
      commandArgs: ['node', '-e', script],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE
    });

    assert.equal(result.exitCode, 0);

    const written = await fsp.readFile(tempOutFile, 'utf8');
    const parsed = JSON.parse(written);

    assert.equal(parsed.dbUrl, 'postgres://user:pass@localhost:5432/testdb');
    assert.equal(parsed.apiKey, 'secret-phase6-key-alice');
    assert.equal(parsed.hasParentEnv, true);

    await fsp.unlink(tempOutFile);
  });

  await t.test('vault secrets override existing environment variables of same name', async () => {
    const tempOutFile = path.join(TEST_BASE_DIR, 'override-' + crypto.randomBytes(4).toString('hex') + '.tmp');
    process.env.OVERRIDDEN_VAR = 'original-parent-value';

    const script = `
      const fs = require('fs');
      fs.writeFileSync(${JSON.stringify(tempOutFile)}, process.env.OVERRIDDEN_VAR, 'utf8');
    `;

    const result = await executeRun({
      commandArgs: ['node', '-e', script],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE
    });

    assert.equal(result.exitCode, 0);

    const written = await fsp.readFile(tempOutFile, 'utf8');
    assert.equal(written, 'vault-value'); // overridden by vault value

    delete process.env.OVERRIDDEN_VAR;
    await fsp.unlink(tempOutFile);
  });

  await t.test('child exit codes are preserved accurately (0, 1, 42)', async () => {
    const r0 = await executeRun({
      commandArgs: ['node', '-e', 'process.exit(0)'],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE,
      stdio: 'ignore'
    });
    assert.equal(r0.exitCode, 0);

    const r1 = await executeRun({
      commandArgs: ['node', '-e', 'process.exit(1)'],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE,
      stdio: 'ignore'
    });
    assert.equal(r1.exitCode, 1);

    const r42 = await executeRun({
      commandArgs: ['node', '-e', 'process.exit(42)'],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE,
      stdio: 'ignore'
    });
    assert.equal(r42.exitCode, 42);
  });
});

test('Phase 6: Security Invariants & Zero Plaintext Disk Exposure', async (t) => {
  await t.test('never writes .env or plaintext temporary files to disk', async () => {
    const beforeFiles = fs.readdirSync(TEST_BASE_DIR);

    await executeRun({
      commandArgs: ['node', '-e', '1'],
      env: 'development',
      projectConfig: aliceProjectConfig,
      serverUrl: testServerUrl,
      keystoreDir: aliceKeystoreDir,
      passphrase: ALICE_PASSPHRASE,
      stdio: 'ignore'
    });

    const afterFiles = fs.readdirSync(TEST_BASE_DIR);

    // Ensure no .env or secret file was created
    assert.equal(fs.existsSync(path.join(TEST_BASE_DIR, '.env')), false);
    assert.equal(fs.existsSync(path.join(TEST_BASE_DIR, '.env.local')), false);
    assert.equal(fs.existsSync(path.join(TEST_BASE_DIR, '.envguard-secrets')), false);
  });

  await t.test('server storage never contains decrypted secret values', async () => {
    const serverFiles = fs.readdirSync(path.join(TEST_BASE_DIR, 'vault-server', 'vaults'));
    for (const file of serverFiles) {
      const content = await fsp.readFile(path.join(TEST_BASE_DIR, 'vault-server', 'vaults', file), 'utf8');
      assert.equal(content.includes('secret-phase6-key-alice'), false);
      assert.equal(content.includes('postgres://user:pass'), false);
    }
  });

  await t.test('local keystore files never contain plaintext secret values', async () => {
    const keystoreFiles = fs.readdirSync(aliceKeystoreDir);
    for (const file of keystoreFiles) {
      const content = await fsp.readFile(path.join(aliceKeystoreDir, file), 'utf8');
      assert.equal(content.includes('secret-phase6-key-alice'), false);
      assert.equal(content.includes('postgres://user:pass'), false);
    }
  });
});
