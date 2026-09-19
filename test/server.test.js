/**
 * Test suite for Vault Server API, Authentication, and Authorization.
 *
 * This file is part of Phase 3 (Vault Server & Storage).
 * Tests registration, canonical HMAC request authentication, replay attacks,
 * rate limiting, role-based access control across all 4 roles, optimistic concurrency,
 * DEK version rotation, structural invariant validation, and error sanitization.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createServer } from '../src/server/server.js';
import * as ecdh from '../src/crypto/ecdh.js';
import * as envelope from '../src/crypto/envelope.js';
import * as kdf from '../src/crypto/kdf.js';

const TEST_DATA_DIR = path.resolve('test-server-data-' + crypto.randomBytes(4).toString('hex'));
const ENROLLMENT_KEY = 'test-enrollment-secret-key-12345';

let serverInstance;
let serverPort;

/**
 * Helper to make HTTP request to the test server.
 */
function makeRequest(options, bodyData) {
  return new Promise(function(resolve, reject) {
    let payload = '';
    if (typeof bodyData === 'string') {
      payload = bodyData;
    } else if (Buffer.isBuffer(bodyData)) {
      payload = bodyData;
    } else if (typeof bodyData === 'object' && bodyData !== null) {
      payload = JSON.stringify(bodyData);
    }

    const reqOptions = {
      hostname: '127.0.0.1',
      port: serverPort,
      path: options.path,
      method: options.method || 'GET',
      headers: Object.assign({}, options.headers || {})
    };

    if (payload.length > 0 && !reqOptions.headers['Content-Length']) {
      reqOptions.headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const req = http.request(reqOptions, function(res) {
      const chunks = [];
      res.on('data', function(chunk) {
        chunks.push(chunk);
      });
      res.on('end', function() {
        const rawResponse = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try {
          parsed = JSON.parse(rawResponse);
        } catch (err) {
          // Leave as raw text if not JSON
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: parsed,
          rawBody: rawResponse
        });
      });
    });

    req.on('error', reject);

    if (payload.length > 0) {
      req.write(payload);
    }
    req.end();
  });
}

/**
 * Helper to generate canonical HMAC authentication headers.
 */
function generateAuthHeaders(method, requestPath, bodyData, username, signingKeyHex, overrides) {
  let bodyBuffer;
  if (Buffer.isBuffer(bodyData)) {
    bodyBuffer = bodyData;
  } else if (typeof bodyData === 'string') {
    bodyBuffer = Buffer.from(bodyData, 'utf8');
  } else if (typeof bodyData === 'object' && bodyData !== null) {
    bodyBuffer = Buffer.from(JSON.stringify(bodyData), 'utf8');
  } else {
    bodyBuffer = Buffer.alloc(0);
  }

  const timestamp = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const bodyHash = crypto.createHash('sha512').update(bodyBuffer).digest('hex');

  let effectiveMethod = method.toUpperCase();
  let effectivePath = requestPath;
  let effectiveTimestamp = timestamp;
  let effectiveNonce = nonce;
  let effectiveBodyHash = bodyHash;
  let effectiveUsername = username;
  let effectiveKeyHex = signingKeyHex;

  if (overrides) {
    if (overrides.method) {
      effectiveMethod = overrides.method;
    }
    if (overrides.path) {
      effectivePath = overrides.path;
    }
    if (overrides.timestamp) {
      effectiveTimestamp = overrides.timestamp;
    }
    if (overrides.nonce) {
      effectiveNonce = overrides.nonce;
    }
    if (overrides.bodyHash) {
      effectiveBodyHash = overrides.bodyHash;
    }
    if (overrides.username) {
      effectiveUsername = overrides.username;
    }
    if (overrides.keyHex) {
      effectiveKeyHex = overrides.keyHex;
    }
  }

  const canonicalString = effectiveMethod + '\n' +
                          effectivePath + '\n' +
                          effectiveTimestamp + '\n' +
                          effectiveNonce + '\n' +
                          effectiveBodyHash;

  let signature = crypto.createHmac('sha512', Buffer.from(effectiveKeyHex, 'hex')).update(canonicalString).digest('hex');
  if (overrides && overrides.signature) {
    signature = overrides.signature;
  }

  const headers = {
    'X-EnvGuard-User': effectiveUsername,
    'X-EnvGuard-Timestamp': effectiveTimestamp,
    'X-EnvGuard-Nonce': effectiveNonce,
    'X-EnvGuard-Signature': signature,
    'Content-Type': 'application/json'
  };

  if (overrides && overrides.headers) {
    Object.assign(headers, overrides.headers);
  }

  return headers;
}

// Global identities for tests
let aliceKeys;
let aliceSalt;
let aliceSigningKeyHex;

let bobKeys;
let bobSalt;
let bobSigningKeyHex;

let charlieKeys;
let charlieSalt;
let charlieSigningKeyHex;

let davidKeys;
let davidSalt;
let davidSigningKeyHex;

test.before(async function() {
  await fs.promises.mkdir(TEST_DATA_DIR, { recursive: true });

  serverInstance = createServer({
    dataDir: TEST_DATA_DIR,
    enrollmentKey: ENROLLMENT_KEY,
    host: '127.0.0.1'
  });

  const addr = await serverInstance.listen(0, '127.0.0.1');
  serverPort = addr.port;

  // Generate identities
  aliceKeys = ecdh.generateKeyPair();
  aliceSalt = crypto.randomBytes(16).toString('hex');
  aliceSigningKeyHex = kdf.hkdfSha512(Buffer.from('alice-raw-token-32bytes-secret!'), Buffer.from(aliceSalt, 'hex'), 'envguard-client-signing-v1', 64).toString('hex');

  bobKeys = ecdh.generateKeyPair();
  bobSalt = crypto.randomBytes(16).toString('hex');
  bobSigningKeyHex = kdf.hkdfSha512(Buffer.from('bob-raw-token-32bytes-secret!!'), Buffer.from(bobSalt, 'hex'), 'envguard-client-signing-v1', 64).toString('hex');

  charlieKeys = ecdh.generateKeyPair();
  charlieSalt = crypto.randomBytes(16).toString('hex');
  charlieSigningKeyHex = kdf.hkdfSha512(Buffer.from('charlie-raw-token-32bytes-sec!'), Buffer.from(charlieSalt, 'hex'), 'envguard-client-signing-v1', 64).toString('hex');

  davidKeys = ecdh.generateKeyPair();
  davidSalt = crypto.randomBytes(16).toString('hex');
  davidSigningKeyHex = kdf.hkdfSha512(Buffer.from('david-raw-token-32bytes-secre!'), Buffer.from(davidSalt, 'hex'), 'envguard-client-signing-v1', 64).toString('hex');
});

test.after(async function() {
  if (serverInstance) {
    await serverInstance.close();
  }
  try {
    await fs.promises.rm(TEST_DATA_DIR, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch (err) {
    // Ignore cleanup error
  }
});

test('Server: Registration / Enrollment Endpoint (POST /api/v1/auth/register)', async function(t) {
  await t.test('rejects registration with invalid enrollment key', async function() {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register'
    }, {
      username: 'alice',
      publicKey: aliceKeys.publicKey,
      salt: aliceSalt,
      authVerifier: aliceSigningKeyHex,
      enrollmentKey: 'wrong-key'
    });

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('rejects registration with malformed JWK or fields', async function() {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register'
    }, {
      username: 'alice',
      publicKey: { kty: 'RSA', crv: 'X25519', x: 'invalid' },
      salt: aliceSalt,
      authVerifier: aliceSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.error, 'invalid_request');
  });

  await t.test('registers alice successfully with 201 Created', async function() {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register'
    }, {
      username: 'alice',
      publicKey: aliceKeys.publicKey,
      salt: aliceSalt,
      authVerifier: aliceSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });

    assert.strictEqual(res.statusCode, 201);
    assert.strictEqual(res.body.status, 'created');
    assert.strictEqual(res.body.username, 'alice');
  });

  await t.test('rejects duplicate username registration with 409 Conflict', async function() {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register'
    }, {
      username: 'alice',
      publicKey: aliceKeys.publicKey,
      salt: aliceSalt,
      authVerifier: aliceSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });

    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.error, 'conflict');
  });

  await t.test('registers bob, charlie, and david for subsequent tests', async function() {
    let res = await makeRequest({ method: 'POST', path: '/api/v1/auth/register' }, {
      username: 'bob',
      publicKey: bobKeys.publicKey,
      salt: bobSalt,
      authVerifier: bobSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });
    assert.strictEqual(res.statusCode, 201);

    res = await makeRequest({ method: 'POST', path: '/api/v1/auth/register' }, {
      username: 'charlie',
      publicKey: charlieKeys.publicKey,
      salt: charlieSalt,
      authVerifier: charlieSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });
    assert.strictEqual(res.statusCode, 201);

    res = await makeRequest({ method: 'POST', path: '/api/v1/auth/register' }, {
      username: 'david',
      publicKey: davidKeys.publicKey,
      salt: davidSalt,
      authVerifier: davidSigningKeyHex,
      enrollmentKey: ENROLLMENT_KEY
    });
    assert.strictEqual(res.statusCode, 201);
  });
});

test('Server: User Lookup Endpoint (GET /api/v1/users/:username)', async function(t) {
  await t.test('unauthenticated lookup is rejected with 400 or 401', async function() {
    const res = await makeRequest({
      method: 'GET',
      path: '/api/v1/users/bob'
    });
    assert.strictEqual(res.statusCode, 400);
  });

  await t.test('authenticated lookup returns canonical public key JWK and fingerprint without verifier or hex', async function() {
    const headers = generateAuthHeaders('GET', '/api/v1/users/bob', '', 'alice', aliceSigningKeyHex);
    const res = await makeRequest({
      method: 'GET',
      path: '/api/v1/users/bob',
      headers: headers
    });

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.username, 'bob');
    assert.strictEqual(res.body.publicKey.x, bobKeys.publicKey.x);
    assert.strictEqual(res.body.publicKeyFingerprint, ecdh.calculateFingerprint(bobKeys.publicKey));
    assert.strictEqual(res.body.status, 'active');
    // Ensure sensitive and redundant fields are never exposed
    assert.strictEqual(res.body.publicKeyHex, undefined);
    assert.strictEqual(res.body.authVerifier, undefined);
    assert.strictEqual(res.body.salt, undefined);
  });

  await t.test('lookup for nonexistent user returns 404', async function() {
    const headers = generateAuthHeaders('GET', '/api/v1/users/nonexistent', '', 'alice', aliceSigningKeyHex);
    const res = await makeRequest({
      method: 'GET',
      path: '/api/v1/users/nonexistent',
      headers: headers
    });

    assert.strictEqual(res.statusCode, 404);
    assert.strictEqual(res.body.error, 'not_found');
  });
});

test('Server: Request Authentication & Replay Protection', async function(t) {
  const reqPath = '/api/v1/users/bob';

  await t.test('rejects tampered HTTP method', async function() {
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      method: 'POST'
    });
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
  });

  await t.test('rejects tampered canonical path', async function() {
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      path: '/api/v1/users/alice'
    });
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
  });

  await t.test('rejects query parameters on authenticated route with 400 Bad Request', async function() {
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex);
    const res = await makeRequest({ method: 'GET', path: reqPath + '?page=1', headers: headers });
    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.error, 'unauthorized');
  });

  await t.test('rejects expired timestamp (>300 seconds past)', async function() {
    const pastTime = new Date(Date.now() - 400000).toISOString();
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      timestamp: pastTime
    });
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
  });

  await t.test('rejects future timestamp (>300 seconds future)', async function() {
    const futureTime = new Date(Date.now() + 400000).toISOString();
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      timestamp: futureTime
    });
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
  });

  await t.test('rejects invalid signature', async function() {
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      signature: 'f'.repeat(128)
    });
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
  });

  await t.test('unknown user executes dummy verifier and returns 401 safely', async function() {
    const dummyKey = crypto.randomBytes(64).toString('hex');
    const headers = generateAuthHeaders('GET', reqPath, '', 'unknown_ghost', dummyKey);
    const res = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.body.error, 'unauthorized');
  });

  await t.test('replayed nonce with valid signature is rejected on second attempt', async function() {
    const headers = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex);
    const firstRes = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(firstRes.statusCode, 200);

    const secondRes = await makeRequest({ method: 'GET', path: reqPath, headers: headers });
    assert.strictEqual(secondRes.statusCode, 401);
    assert.strictEqual(secondRes.body.error, 'unauthorized');
  });

  await t.test('failed authentication does not consume a nonce', async function() {
    const nonce = crypto.randomBytes(16).toString('hex');
    // First attempt: bad signature
    const badHeaders = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      nonce: nonce,
      signature: '0'.repeat(128)
    });
    const resFail = await makeRequest({ method: 'GET', path: reqPath, headers: badHeaders });
    assert.strictEqual(resFail.statusCode, 401);

    // Second attempt: valid signature with same nonce should succeed because failed auth must not consume nonce
    const goodHeaders = generateAuthHeaders('GET', reqPath, '', 'alice', aliceSigningKeyHex, {
      nonce: nonce
    });
    const resSuccess = await makeRequest({ method: 'GET', path: reqPath, headers: goodHeaders });
    assert.strictEqual(resSuccess.statusCode, 200);
  });

  await t.test('rate limiting locks out IP after 10 consecutive failures (429 Too Many Requests)', async function() {
    const rateLimitDataDir = path.join(TEST_DATA_DIR, 'rate-limit-test');
    const rateLimitServer = createServer({
      dataDir: rateLimitDataDir,
      enrollmentKey: ENROLLMENT_KEY,
      host: '127.0.0.1'
    });
    const addr = await rateLimitServer.listen(0, '127.0.0.1');
    const port = addr.port;

    try {
      // 10 consecutive failed attempts
      for (let i = 0; i < 10; i++) {
        const badHeaders = {
          'X-EnvGuard-User': 'alice',
          'X-EnvGuard-Timestamp': new Date().toISOString(),
          'X-EnvGuard-Nonce': crypto.randomBytes(16).toString('hex'),
          'X-EnvGuard-Signature': '0'.repeat(128)
        };

        const res = await new Promise(function(resolve, reject) {
          const req = http.request({
            hostname: '127.0.0.1',
            port: port,
            path: reqPath,
            method: 'GET',
            headers: badHeaders
          }, function(r) {
            r.on('data', function() {});
            r.on('end', function() {
              resolve(r);
            });
          });
          req.on('error', reject);
          req.end();
        });

        assert.strictEqual(res.statusCode, 401);
      }

      // 11th attempt should trigger 429 Too Many Requests
      const resLocked = await new Promise(function(resolve, reject) {
        const req = http.request({
          hostname: '127.0.0.1',
          port: port,
          path: reqPath,
          method: 'GET',
          headers: {
            'X-EnvGuard-User': 'alice',
            'X-EnvGuard-Timestamp': new Date().toISOString(),
            'X-EnvGuard-Nonce': crypto.randomBytes(16).toString('hex'),
            'X-EnvGuard-Signature': '0'.repeat(128)
          }
        }, function(r) {
          const chunks = [];
          r.on('data', function(c) { chunks.push(c); });
          r.on('end', function() {
            resolve({ statusCode: r.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
          });
        });
        req.on('error', reject);
        req.end();
      });

      assert.strictEqual(resLocked.statusCode, 429);
      assert.strictEqual(resLocked.body.error, 'unauthorized');
    } finally {
      await rateLimitServer.close();
    }
  });
});

test('Server: Vault Lifecycle, Versioning, and ACL Matrix', async function(t) {
  const vaultId = 'project-dev-a7f3c92b8e14d056';
  const initialDek = crypto.randomBytes(32);
  const initialPlaintext = JSON.stringify({ DATABASE_URL: 'postgres://localhost/db' });

  const initialBlob = envelope.createSecretEnvelope(initialPlaintext, initialDek, vaultId, 1);
  const aliceWrappedDek = envelope.createWrappedDekEnvelope(initialDek, aliceKeys.publicKey, vaultId, 1, 'alice');

  await t.test('POST /api/v1/vault creates initial vault with caller as owner', async function() {
    const body = {
      vaultId: vaultId,
      blob: initialBlob,
      wrappedDek: aliceWrappedDek
    };
    const headers = generateAuthHeaders('POST', '/api/v1/vault', body, 'alice', aliceSigningKeyHex);

    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/vault',
      headers: headers
    }, body);

    assert.strictEqual(res.statusCode, 201);
    assert.strictEqual(res.body.vaultId, vaultId);
    assert.strictEqual(res.body.vaultVersion, 1);
    assert.strictEqual(res.body.dekVersion, 1);
  });

  await t.test('POST /api/v1/vault rejects duplicate vault ID with 409 Conflict', async function() {
    const body = {
      vaultId: vaultId,
      blob: initialBlob,
      wrappedDek: aliceWrappedDek
    };
    const headers = generateAuthHeaders('POST', '/api/v1/vault', body, 'alice', aliceSigningKeyHex);

    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/vault',
      headers: headers
    }, body);

    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.error, 'conflict');
  });

  await t.test('GET /secrets allows owner and denies non-member', async function() {
    // Alice (owner) can read
    const aliceHeaders = generateAuthHeaders('GET', `/api/v1/vault/${vaultId}/secrets`, '', 'alice', aliceSigningKeyHex);
    const aliceRes = await makeRequest({
      method: 'GET',
      path: `/api/v1/vault/${vaultId}/secrets`,
      headers: aliceHeaders
    });
    assert.strictEqual(aliceRes.statusCode, 200);
    assert.strictEqual(aliceRes.body.vaultVersion, 1);
    assert.strictEqual(aliceRes.body.dekVersion, 1);
    assert.strictEqual(aliceRes.body.blob.tag, initialBlob.tag);

    // Bob (not yet member) is denied with 403
    const bobHeaders = generateAuthHeaders('GET', `/api/v1/vault/${vaultId}/secrets`, '', 'bob', bobSigningKeyHex);
    const bobRes = await makeRequest({
      method: 'GET',
      path: `/api/v1/vault/${vaultId}/secrets`,
      headers: bobHeaders
    });
    assert.strictEqual(bobRes.statusCode, 403);
  });

  await t.test('POST /members: Owner grants admin role to Bob', async function() {
    const bobWrappedDek = envelope.createWrappedDekEnvelope(initialDek, bobKeys.publicKey, vaultId, 1, 'bob');
    const body = {
      expectedVersion: 1,
      username: 'bob',
      role: 'admin',
      wrappedDek: bobWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(bobKeys.publicKey)
    };
    const headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'alice', aliceSigningKeyHex);

    const res = await makeRequest({
      method: 'POST',
      path: `/api/v1/vault/${vaultId}/members`,
      headers: headers
    }, body);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.vaultVersion, 2);
    assert.strictEqual(res.body.dekVersion, 1); // dekVersion unchanged on grant
  });

  await t.test('POST /members: Admin cannot grant admin role (Bob granting Charlie admin rejected with 403)', async function() {
    const charlieWrappedDek = envelope.createWrappedDekEnvelope(initialDek, charlieKeys.publicKey, vaultId, 1, 'charlie');
    const body = {
      expectedVersion: 2,
      username: 'charlie',
      role: 'admin', // Admin granting admin is forbidden!
      wrappedDek: charlieWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(charlieKeys.publicKey)
    };
    const headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'bob', bobSigningKeyHex);

    const res = await makeRequest({
      method: 'POST',
      path: `/api/v1/vault/${vaultId}/members`,
      headers: headers
    }, body);

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('POST /members: Admin grants member role to Charlie, and readonly to David', async function() {
    // Grant Charlie 'member'
    const charlieWrappedDek = envelope.createWrappedDekEnvelope(initialDek, charlieKeys.publicKey, vaultId, 1, 'charlie');
    let body = {
      expectedVersion: 2,
      username: 'charlie',
      role: 'member',
      wrappedDek: charlieWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(charlieKeys.publicKey)
    };
    let headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'bob', bobSigningKeyHex);
    let res = await makeRequest({ method: 'POST', path: `/api/v1/vault/${vaultId}/members`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.vaultVersion, 3);

    // Grant David 'readonly'
    const davidWrappedDek = envelope.createWrappedDekEnvelope(initialDek, davidKeys.publicKey, vaultId, 1, 'david');
    body = {
      expectedVersion: 3,
      username: 'david',
      role: 'readonly',
      wrappedDek: davidWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(davidKeys.publicKey)
    };
    headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'bob', bobSigningKeyHex);
    res = await makeRequest({ method: 'POST', path: `/api/v1/vault/${vaultId}/members`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.vaultVersion, 4);
  });

  await t.test('POST /members: Charlie (member) cannot grant access (rejected with 403)', async function() {
    const davidWrappedDek = envelope.createWrappedDekEnvelope(initialDek, davidKeys.publicKey, vaultId, 1, 'david');
    const body = {
      expectedVersion: 4,
      username: 'david',
      role: 'readonly',
      wrappedDek: davidWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(davidKeys.publicKey)
    };
    const headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'charlie', charlieSigningKeyHex);
    const res = await makeRequest({ method: 'POST', path: `/api/v1/vault/${vaultId}/members`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('POST /members: David (readonly) cannot grant access (rejected with 403)', async function() {
    const charlieWrappedDek = envelope.createWrappedDekEnvelope(initialDek, charlieKeys.publicKey, vaultId, 1, 'charlie');
    const body = {
      expectedVersion: 4,
      username: 'charlie',
      role: 'member',
      wrappedDek: charlieWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(charlieKeys.publicKey)
    };
    const headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, body, 'david', davidSigningKeyHex);
    const res = await makeRequest({ method: 'POST', path: `/api/v1/vault/${vaultId}/members`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('DELETE /members: Member (Charlie) and Readonly (David) cannot revoke (rejected with 403)', async function() {
    const newDek = crypto.randomBytes(32);
    const newBlob = envelope.createSecretEnvelope('{}', newDek, vaultId, 2);
    const body = {
      expectedVersion: 4,
      newBlob: newBlob,
      newWrappedDeks: {}
    };

    // Charlie (member) attempts revoke
    let headers = generateAuthHeaders('DELETE', `/api/v1/vault/${vaultId}/members/bob`, body, 'charlie', charlieSigningKeyHex);
    let res = await makeRequest({ method: 'DELETE', path: `/api/v1/vault/${vaultId}/members/bob`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');

    // David (readonly) attempts revoke
    headers = generateAuthHeaders('DELETE', `/api/v1/vault/${vaultId}/members/bob`, body, 'david', davidSigningKeyHex);
    res = await makeRequest({ method: 'DELETE', path: `/api/v1/vault/${vaultId}/members/bob`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('PUT /secrets: Readonly user (David) cannot update secrets (rejected with 403)', async function() {
    const newBlob = envelope.createSecretEnvelope(JSON.stringify({ API_KEY: '123' }), initialDek, vaultId, 1);
    const body = {
      expectedVersion: 4,
      blob: newBlob
    };
    const headers = generateAuthHeaders('PUT', `/api/v1/vault/${vaultId}/secrets`, body, 'david', davidSigningKeyHex);
    const res = await makeRequest({ method: 'PUT', path: `/api/v1/vault/${vaultId}/secrets`, headers: headers }, body);
    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('PUT /secrets: Member user (Charlie) can update secrets, incrementing vaultVersion', async function() {
    const updatedPlaintext = JSON.stringify({ DATABASE_URL: 'postgres://localhost/db', NEW_KEY: 'secret_val' });
    const newBlob = envelope.createSecretEnvelope(updatedPlaintext, initialDek, vaultId, 1);
    const body = {
      expectedVersion: 4,
      blob: newBlob
    };
    const headers = generateAuthHeaders('PUT', `/api/v1/vault/${vaultId}/secrets`, body, 'charlie', charlieSigningKeyHex);
    const res = await makeRequest({ method: 'PUT', path: `/api/v1/vault/${vaultId}/secrets`, headers: headers }, body);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.vaultVersion, 5);
    assert.strictEqual(res.body.dekVersion, 1); // dekVersion unchanged on secret update
  });

  await t.test('PUT /secrets: Version conflict returns 409 Conflict', async function() {
    const newBlob = envelope.createSecretEnvelope('{}', initialDek, vaultId, 1);
    const body = {
      expectedVersion: 4, // Stale version! Current is 5
      blob: newBlob
    };
    const headers = generateAuthHeaders('PUT', `/api/v1/vault/${vaultId}/secrets`, body, 'alice', aliceSigningKeyHex);
    const res = await makeRequest({ method: 'PUT', path: `/api/v1/vault/${vaultId}/secrets`, headers: headers }, body);

    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.error, 'conflict');
  });

  await t.test('DELETE /members: Owner cannot be revoked by anyone (rejected with 403)', async function() {
    const newDek = crypto.randomBytes(32);
    const newBlob = envelope.createSecretEnvelope('{}', newDek, vaultId, 2);
    const body = {
      expectedVersion: 5,
      newBlob: newBlob,
      newWrappedDeks: {}
    };
    const headers = generateAuthHeaders('DELETE', `/api/v1/vault/${vaultId}/members/alice`, body, 'bob', bobSigningKeyHex);
    const res = await makeRequest({ method: 'DELETE', path: `/api/v1/vault/${vaultId}/members/alice`, headers: headers }, body);

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('DELETE /members: Admin (Bob) cannot revoke another admin (rejected with 403)', async function() {
    // First promote Charlie to admin as Alice (owner)
    const charlieWrappedDek = envelope.createWrappedDekEnvelope(initialDek, charlieKeys.publicKey, vaultId, 1, 'charlie');
    const grantBody = {
      expectedVersion: 5,
      username: 'charlie',
      role: 'admin',
      wrappedDek: charlieWrappedDek,
      publicKeyFingerprint: ecdh.calculateFingerprint(charlieKeys.publicKey)
    };
    let headers = generateAuthHeaders('POST', `/api/v1/vault/${vaultId}/members`, grantBody, 'alice', aliceSigningKeyHex);
    let res = await makeRequest({ method: 'POST', path: `/api/v1/vault/${vaultId}/members`, headers: headers }, grantBody);
    assert.strictEqual(res.statusCode, 200);
    const currentVer = res.body.vaultVersion; // 6

    // Now Bob (admin) attempts to revoke Charlie (admin) -> must fail 403
    const newDek = crypto.randomBytes(32);
    const newBlob = envelope.createSecretEnvelope('{}', newDek, vaultId, 2);
    const revokeBody = {
      expectedVersion: currentVer,
      newBlob: newBlob,
      newWrappedDeks: {}
    };
    headers = generateAuthHeaders('DELETE', `/api/v1/vault/${vaultId}/members/charlie`, revokeBody, 'bob', bobSigningKeyHex);
    res = await makeRequest({ method: 'DELETE', path: `/api/v1/vault/${vaultId}/members/charlie`, headers: headers }, revokeBody);

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.error, 'forbidden');
  });

  await t.test('DELETE /members: Revocation enforces mandatory DEK rotation and increments dekVersion', async function() {
    // Alice revokes David (readonly).
    // Mandatory DEK rotation: dekVersion 1 -> 2.
    const newDek = crypto.randomBytes(32);
    const newBlob = envelope.createSecretEnvelope(JSON.stringify({ ROTATED: true }), newDek, vaultId, 2);

    // Wrap for all remaining members: alice, bob, charlie
    const newWrappedDeks = {
      alice: envelope.createWrappedDekEnvelope(newDek, aliceKeys.publicKey, vaultId, 2, 'alice'),
      bob: envelope.createWrappedDekEnvelope(newDek, bobKeys.publicKey, vaultId, 2, 'bob'),
      charlie: envelope.createWrappedDekEnvelope(newDek, charlieKeys.publicKey, vaultId, 2, 'charlie')
    };

    const body = {
      expectedVersion: 6,
      newBlob: newBlob,
      newWrappedDeks: newWrappedDeks
    };
    const headers = generateAuthHeaders('DELETE', `/api/v1/vault/${vaultId}/members/david`, body, 'alice', aliceSigningKeyHex);
    const res = await makeRequest({ method: 'DELETE', path: `/api/v1/vault/${vaultId}/members/david`, headers: headers }, body);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.vaultVersion, 7);
    assert.strictEqual(res.body.dekVersion, 2); // DEK rotated!

    // Verify David is no longer in vault members
    const checkHeaders = generateAuthHeaders('GET', `/api/v1/vault/${vaultId}/secrets`, '', 'alice', aliceSigningKeyHex);
    const checkRes = await makeRequest({ method: 'GET', path: `/api/v1/vault/${vaultId}/secrets`, headers: checkHeaders });
    assert.strictEqual(checkRes.body.wrappedDeks.david, undefined);
    assert.strictEqual(checkRes.body.dekVersion, 2);
  });
});

test('Server: Structural Invariants & Payload Size Limits', async function(t) {
  await t.test('rejects request exceeding 1 MB with 413 Payload Too Large', async function() {
    const largeBody = 'x'.repeat(1048576 + 10);
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(largeBody)
    };

    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register',
      headers: headers
    }, largeBody);

    assert.strictEqual(res.statusCode, 413);
    assert.strictEqual(res.body.error, 'payload_too_large');
  });

  await t.test('rejects malformed JSON with 400 Bad Request', async function() {
    const res = await makeRequest({
      method: 'POST',
      path: '/api/v1/auth/register',
      headers: { 'Content-Type': 'application/json' }
    }, '{ malformed json: true');

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.error, 'invalid_request');
  });

  await t.test('rejects secret blob containing plaintext keys with 400 Bad Request', async function() {
    const vaultId = 'test-plaintext-check-vault';
    const body = {
      vaultId: vaultId,
      blob: {
        algorithm: 'aes-256-gcm',
        dekVersion: 1,
        iv: 'a'.repeat(24),
        tag: 'b'.repeat(32),
        ciphertext: 'c'.repeat(32),
        aad: `${vaultId}:1`,
        plaintext: 'SUPER_SECRET_LEAK' // FORBIDDEN!
      },
      wrappedDek: envelope.createWrappedDekEnvelope(crypto.randomBytes(32), aliceKeys.publicKey, vaultId, 1, 'alice')
    };

    const headers = generateAuthHeaders('POST', '/api/v1/vault', body, 'alice', aliceSigningKeyHex);
    const res = await makeRequest({ method: 'POST', path: '/api/v1/vault', headers: headers }, body);

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.error, 'invalid_request');
  });

  await t.test('returns 404 for unsupported route', async function() {
    const headers = generateAuthHeaders('GET', '/unknown/endpoint', '', 'alice', aliceSigningKeyHex);
    const res = await makeRequest({
      method: 'GET',
      path: '/unknown/endpoint',
      headers: headers
    });

    assert.strictEqual(res.statusCode, 404);
    assert.strictEqual(res.body.error, 'not_found');
  });

  await t.test('enforces TLS boundary: refuses plaintext HTTP on non-loopback host', function() {
    assert.throws(function() {
      createServer({
        host: '192.168.1.50'
      });
    }, function(err) {
      return err.message.indexOf('Plaintext HTTP is strictly prohibited') !== -1;
    });
  });
});
