/**
 * EnvGuard Vault Server implementation.
 *
 * This file is part of Phase 3 (Vault Server & Storage).
 * Implements native Node.js HTTP/HTTPS server exposing the authenticated zero-knowledge
 * blind vault API. Provides strict input validation, ACL enforcement across all 4 roles,
 * optimistic concurrency control via monotonic version matching, request size enforcement,
 * and sanitized JSON responses.
 *
 * Security Contract:
 * - Operates entirely over ciphertext and public keys; never learns plaintext secrets or DEKs.
 * - Loopback HTTP permitted exclusively for local development; remote endpoints strictly enforce TLS.
 * - Maximum request body size capped at 1 MB (1,048,576 bytes) with streaming rejection.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { Storage, isValidVaultId, isValidUsername } from './storage.js';
import { AuthSecurityManager, authenticateRequest } from './auth.js';
import { calculateFingerprint } from '../crypto/ecdh.js';

const MAX_BODY_BYTES = 1048576; // 1 MiB

/**
 * Validate that an object has the required X25519 public key JWK structure.
 *
 * @param {object} jwk - The public key JWK to validate.
 * @returns {boolean} True if valid, false otherwise.
 */
function isValidPublicKeyJwk(jwk) {
  if (typeof jwk !== 'object' || jwk === null) {
    return false;
  }
  if (jwk.kty !== 'OKP') {
    return false;
  }
  if (jwk.crv !== 'X25519') {
    return false;
  }
  if (typeof jwk.x !== 'string' || jwk.x.length !== 43) {
    return false;
  }
  const base64urlRegex = /^[A-Za-z0-9_-]{43}$/;
  if (!base64urlRegex.test(jwk.x)) {
    return false;
  }
  // Disallow private key parameter in public JWK
  if (Object.prototype.hasOwnProperty.call(jwk, 'd')) {
    return false;
  }
  return true;
}

/**
 * Validate structural integrity of an encrypted secret blob.
 *
 * @param {object} blob - Candidate secret blob envelope.
 * @param {string} expectedVaultId - Expected vault identifier.
 * @param {number} expectedDekVersion - Expected DEK version.
 * @returns {boolean} True if structurally valid, false otherwise.
 */
function validateSecretBlobEnvelope(blob, expectedVaultId, expectedDekVersion) {
  if (typeof blob !== 'object' || blob === null) {
    return false;
  }
  if (blob.algorithm !== 'aes-256-gcm') {
    return false;
  }
  if (typeof blob.dekVersion !== 'number' || !Number.isInteger(blob.dekVersion) || blob.dekVersion < 1) {
    return false;
  }
  if (typeof expectedDekVersion === 'number' && blob.dekVersion !== expectedDekVersion) {
    return false;
  }
  if (typeof blob.iv !== 'string' || !/^[0-9a-fA-F]{24}$/.test(blob.iv)) {
    return false;
  }
  if (typeof blob.tag !== 'string' || !/^[0-9a-fA-F]{32}$/.test(blob.tag)) {
    return false;
  }
  if (typeof blob.ciphertext !== 'string' || blob.ciphertext.length === 0 || !/^[0-9a-fA-F]+$/.test(blob.ciphertext)) {
    return false;
  }
  const expectedAad = `${expectedVaultId}:${blob.dekVersion}`;
  if (blob.aad !== expectedAad) {
    return false;
  }
  // Reject any plaintext or raw key fields
  if (Object.prototype.hasOwnProperty.call(blob, 'plaintext') ||
      Object.prototype.hasOwnProperty.call(blob, 'secrets') ||
      Object.prototype.hasOwnProperty.call(blob, 'secret') ||
      Object.prototype.hasOwnProperty.call(blob, 'dek') ||
      Object.prototype.hasOwnProperty.call(blob, 'rawDek')) {
    return false;
  }
  return true;
}

/**
 * Validate structural integrity of a wrapped DEK envelope.
 *
 * @param {object} wrappedDek - Candidate wrapped DEK envelope.
 * @param {string} expectedVaultId - Expected vault identifier.
 * @param {number} expectedDekVersion - Expected DEK version.
 * @param {string} expectedUsername - Expected recipient username.
 * @returns {boolean} True if structurally valid, false otherwise.
 */
function validateWrappedDekEnvelope(wrappedDek, expectedVaultId, expectedDekVersion, expectedUsername) {
  if (typeof wrappedDek !== 'object' || wrappedDek === null) {
    return false;
  }
  if (wrappedDek.algorithm !== 'aes-256-gcm') {
    return false;
  }
  if (typeof wrappedDek.kdf !== 'object' || wrappedDek.kdf === null) {
    return false;
  }
  if (wrappedDek.kdf.algorithm !== 'hkdf-sha512' || wrappedDek.kdf.info !== 'envguard-dek-wrap-v1') {
    return false;
  }
  if (!isValidPublicKeyJwk(wrappedDek.ephemeralPublicKey)) {
    return false;
  }
  if (typeof wrappedDek.iv !== 'string' || !/^[0-9a-fA-F]{24}$/.test(wrappedDek.iv)) {
    return false;
  }
  if (typeof wrappedDek.tag !== 'string' || !/^[0-9a-fA-F]{32}$/.test(wrappedDek.tag)) {
    return false;
  }
  if (typeof wrappedDek.encryptedDek !== 'string' || !/^[0-9a-fA-F]{64}$/.test(wrappedDek.encryptedDek)) {
    return false;
  }
  const expectedAad = `${expectedVaultId}:${expectedDekVersion}:${expectedUsername}`;
  if (wrappedDek.aad !== expectedAad) {
    return false;
  }
  // Reject any plaintext or raw key fields
  if (Object.prototype.hasOwnProperty.call(wrappedDek, 'plaintext') ||
      Object.prototype.hasOwnProperty.call(wrappedDek, 'dek') ||
      Object.prototype.hasOwnProperty.call(wrappedDek, 'rawDek') ||
      Object.prototype.hasOwnProperty.call(wrappedDek, 'privateKey')) {
    return false;
  }
  return true;
}

/**
 * Check whether a host string designates a loopback network interface.
 *
 * @param {string} host - Host address or domain name.
 * @returns {boolean} True if loopback, false otherwise.
 */
export function isLoopbackHost(host) {
  if (!host) {
    return true;
  }
  const lower = host.toLowerCase();
  if (lower === '127.0.0.1' || lower === 'localhost' || lower === '::1' || lower === '[::1]') {
    return true;
  }
  return false;
}

/**
 * Read request body with streaming size enforcement.
 *
 * @param {object} req - Node.js HTTP request stream.
 * @param {number} maxBytes - Maximum allowed bytes.
 * @returns {Promise<Buffer>} The accumulated request body buffer.
 */
function readRequestBody(req, maxBytes) {
  return new Promise(function(resolve, reject) {
    const chunks = [];
    let receivedBytes = 0;
    let exceeded = false;

    req.on('data', function(chunk) {
      receivedBytes = receivedBytes + chunk.length;
      if (receivedBytes > maxBytes) {
        exceeded = true;
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', function() {
      if (exceeded) {
        const error = new Error('Payload Too Large: request body exceeds 1 MB limit');
        error.statusCode = 413;
        reject(error);
        return;
      }
      resolve(Buffer.concat(chunks));
    });

    req.on('error', function(err) {
      reject(err);
    });
  });
}

/**
 * Send a structured JSON response.
 *
 * @param {object} res - Node.js HTTP response.
 * @param {number} statusCode - HTTP status code.
 * @param {object} data - Object to serialize.
 */
function sendJsonResponse(res, statusCode, data) {
  const jsonString = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(jsonString, 'utf8'),
    'Cache-Control': 'no-store'
  });
  res.end(jsonString);
}

/**
 * Send a sanitized JSON error response.
 *
 * @param {object} res - Node.js HTTP response.
 * @param {number} statusCode - HTTP status code.
 * @param {string} errorCode - Machine-readable error code.
 * @param {string} message - Safe human-readable error description.
 */
function sendErrorResponse(res, statusCode, errorCode, message) {
  sendJsonResponse(res, statusCode, {
    error: errorCode,
    message: message
  });
}

/**
 * Parse JSON safely from a Buffer.
 *
 * @param {Buffer} buffer - Request body buffer.
 * @returns {object|null} Parsed object or null if malformed.
 */
function parseJsonBody(buffer) {
  if (!buffer || buffer.length === 0) {
    return {};
  }
  try {
    const parsed = JSON.parse(buffer.toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null) {
      return null;
    }
    return parsed;
  } catch (err) {
    return null;
  }
}

/**
 * Factory creating an EnvGuard Vault Server instance.
 *
 * @param {object} options - Server configuration options.
 * @returns {object} Controller with server instance, storage, and lifecycle methods.
 */
export function createServer(options) {
  let serverOptions = options;
  if (typeof serverOptions !== 'object' || serverOptions === null) {
    serverOptions = {};
  }

  const dataDir = serverOptions.dataDir || 'server-data';
  const enrollmentKey = serverOptions.enrollmentKey || process.env.ENVGUARD_ENROLLMENT_KEY || 'envguard-demo-enrollment-key';
  const host = serverOptions.host || '127.0.0.1';
  const tls = serverOptions.tls || null;

  // Strict TLS boundary enforcement: remote plaintext HTTP is strictly forbidden.
  if (!tls) {
    if (!isLoopbackHost(host)) {
      throw new Error('Plaintext HTTP is strictly prohibited on non-loopback interfaces. Valid TLS credentials must be provided.');
    }
  }

  const storage = new Storage(dataDir);
  const securityManager = new AuthSecurityManager();

  /**
   * Main HTTP request router.
   */
  async function requestHandler(req, res) {
    let rawBody;
    try {
      rawBody = await readRequestBody(req, MAX_BODY_BYTES);
    } catch (err) {
      if (err.statusCode === 413) {
        sendErrorResponse(res, 413, 'payload_too_large', 'Request payload exceeds 1 MB maximum permitted size');
        return;
      }
      sendErrorResponse(res, 400, 'bad_request', 'Failed to read request body');
      return;
    }

    const method = req.method.toUpperCase();
    let pathname = req.url;
    const queryIndex = req.url.indexOf('?');
    if (queryIndex !== -1) {
      pathname = req.url.substring(0, queryIndex);
    }

    // =========================================================================
    // Route 1: POST /api/v1/auth/register (Public via Enrollment Key)
    // =========================================================================
    if (method === 'POST' && pathname === '/api/v1/auth/register') {
      const body = parseJsonBody(rawBody);
      if (!body) {
        sendErrorResponse(res, 400, 'invalid_request', 'Malformed JSON payload');
        return;
      }

      const clientEnrollmentKey = body.enrollmentKey;
      if (typeof clientEnrollmentKey !== 'string' || clientEnrollmentKey.length === 0) {
        sendErrorResponse(res, 403, 'forbidden', 'Invalid enrollment key');
        return;
      }

      const clientKeyBuf = Buffer.from(clientEnrollmentKey, 'utf8');
      const serverKeyBuf = Buffer.from(enrollmentKey, 'utf8');
      let enrollmentValid = false;
      if (clientKeyBuf.length === serverKeyBuf.length) {
        enrollmentValid = crypto.timingSafeEqual(clientKeyBuf, serverKeyBuf);
      }
      if (!enrollmentValid) {
        sendErrorResponse(res, 403, 'forbidden', 'Invalid enrollment key');
        return;
      }

      const username = body.username;
      if (!isValidUsername(username)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid username format');
        return;
      }

      const publicKey = body.publicKey;
      if (!isValidPublicKeyJwk(publicKey)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid public key JWK structure');
        return;
      }

      const salt = body.salt;
      if (typeof salt !== 'string' || !/^[0-9a-fA-F]{32}$/.test(salt)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid user salt: must be 32 hexadecimal characters');
        return;
      }

      const authVerifier = body.authVerifier;
      if (typeof authVerifier !== 'string' || !/^[0-9a-fA-F]{128}$/.test(authVerifier)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid auth verifier: must be 128 hexadecimal characters');
        return;
      }

      let publicKeyFingerprint;
      try {
        publicKeyFingerprint = calculateFingerprint(publicKey);
      } catch (err) {
        sendErrorResponse(res, 400, 'invalid_request', 'Failed to derive public key fingerprint');
        return;
      }

      const userRecord = {
        username: username,
        publicKey: {
          kty: 'OKP',
          crv: 'X25519',
          x: publicKey.x
        },
        publicKeyFingerprint: publicKeyFingerprint,
        authVerifier: authVerifier,
        salt: salt,
        createdAt: new Date().toISOString(),
        status: 'active'
      };

      try {
        await storage.createUser(userRecord);
        sendJsonResponse(res, 201, {
          status: 'created',
          username: username
        });
        return;
      } catch (err) {
        if (err.code === 'ERR_USER_EXISTS') {
          sendErrorResponse(res, 409, 'conflict', 'Username already registered');
          return;
        }
        sendErrorResponse(res, 500, 'internal_error', 'Internal server error');
        return;
      }
    }

    // =========================================================================
    // Authenticated Routes: Enforce HMAC Signature & Timing-Safe Verification
    // =========================================================================
    const authResult = await authenticateRequest(req, rawBody, storage, securityManager);
    if (!authResult.authenticated) {
      const statusCode = authResult.statusCode || 401;
      const errorMessage = authResult.errorMessage || 'Unauthorized';
      sendErrorResponse(res, statusCode, 'unauthorized', errorMessage);
      return;
    }

    const authUser = authResult.user;

    // =========================================================================
    // Route 2: GET /api/v1/users/:username (Authenticated User Directory Lookup)
    // =========================================================================
    const userMatch = pathname.match(/^\/api\/v1\/users\/([^/]+)$/);
    if (method === 'GET' && userMatch) {
      const targetUsername = userMatch[1];
      if (!isValidUsername(targetUsername)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid username parameter');
        return;
      }

      const targetUser = await storage.getUser(targetUsername);
      if (!targetUser) {
        sendErrorResponse(res, 404, 'not_found', 'User not found');
        return;
      }

      sendJsonResponse(res, 200, {
        username: targetUser.username,
        publicKey: targetUser.publicKey,
        publicKeyFingerprint: targetUser.publicKeyFingerprint,
        status: targetUser.status
      });
      return;
    }

    // =========================================================================
    // Route 3: POST /api/v1/vault (Create Initial Vault)
    // =========================================================================
    if (method === 'POST' && pathname === '/api/v1/vault') {
      const body = parseJsonBody(rawBody);
      if (!body) {
        sendErrorResponse(res, 400, 'invalid_request', 'Malformed JSON payload');
        return;
      }

      const vaultId = body.vaultId;
      if (!isValidVaultId(vaultId)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid vaultId format');
        return;
      }

      const blob = body.blob;
      if (!validateSecretBlobEnvelope(blob, vaultId, 1)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid encrypted secret blob structure');
        return;
      }

      const wrappedDek = body.wrappedDek;
      if (!validateWrappedDekEnvelope(wrappedDek, vaultId, 1, authUser.username)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid wrapped DEK structure');
        return;
      }

      const initialVault = {
        vaultId: vaultId,
        vaultVersion: 1,
        dekVersion: 1,
        updatedAt: new Date().toISOString(),
        owner: authUser.username,
        members: {
          [authUser.username]: 'owner'
        },
        blob: blob,
        wrappedDeks: {
          [authUser.username]: wrappedDek
        }
      };

      try {
        await storage.createVault(vaultId, initialVault);
        sendJsonResponse(res, 201, {
          vaultId: vaultId,
          vaultVersion: 1,
          dekVersion: 1
        });
        return;
      } catch (err) {
        if (err.code === 'ERR_VAULT_EXISTS') {
          sendErrorResponse(res, 409, 'conflict', 'Vault already exists');
          return;
        }
        sendErrorResponse(res, 500, 'internal_error', 'Failed to create vault');
        return;
      }
    }

    // =========================================================================
    // Route 4: GET /api/v1/vault/:vaultId/secrets (Fetch Secrets & Wrapped DEKs)
    // =========================================================================
    const secretsMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/secrets$/);
    if (method === 'GET' && secretsMatch) {
      const vaultId = secretsMatch[1];
      if (!isValidVaultId(vaultId)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid vaultId parameter');
        return;
      }

      let vault;
      try {
        vault = await storage.getVault(vaultId);
      } catch (err) {
        sendErrorResponse(res, 500, 'internal_error', 'Failed to read vault');
        return;
      }

      if (!vault) {
        sendErrorResponse(res, 404, 'not_found', 'Vault not found');
        return;
      }

      // Authorization check: caller must be an authorized member (owner, admin, member, readonly)
      const callerRole = vault.members[authUser.username];
      if (!callerRole) {
        sendErrorResponse(res, 403, 'forbidden', 'Access denied: caller is not an authorized vault member');
        return;
      }

      sendJsonResponse(res, 200, {
        vaultVersion: vault.vaultVersion,
        dekVersion: vault.dekVersion,
        blob: vault.blob,
        wrappedDeks: vault.wrappedDeks,
        members: vault.members
      });
      return;
    }

    // =========================================================================
    // Route 5: PUT /api/v1/vault/:vaultId/secrets (Update Secrets Blob)
    // =========================================================================
    if (method === 'PUT' && secretsMatch) {
      const vaultId = secretsMatch[1];
      if (!isValidVaultId(vaultId)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid vaultId parameter');
        return;
      }

      const body = parseJsonBody(rawBody);
      if (!body) {
        sendErrorResponse(res, 400, 'invalid_request', 'Malformed JSON payload');
        return;
      }

      const expectedVersion = body.expectedVersion;
      if (typeof expectedVersion !== 'number' || !Number.isInteger(expectedVersion) || expectedVersion < 1) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid expectedVersion: must be positive integer');
        return;
      }

      const blob = body.blob;
      if (!blob) {
        sendErrorResponse(res, 400, 'invalid_request', 'Missing blob field in request body');
        return;
      }

      try {
        const updatedVault = await storage.mutateVault(vaultId, function(currentVault) {
          const callerRole = currentVault.members[authUser.username];
          if (!callerRole) {
            const err = new Error('Access denied: not an authorized member');
            err.code = 'ERR_NOT_MEMBER';
            throw err;
          }

          if (callerRole === 'readonly') {
            const err = new Error('Readonly members are not permitted to modify secrets');
            err.code = 'ERR_READONLY_DENIED';
            throw err;
          }

          if (currentVault.vaultVersion !== expectedVersion) {
            const err = new Error('Optimistic concurrency conflict: vault version mismatch');
            err.code = 'ERR_VERSION_CONFLICT';
            throw err;
          }

          if (!validateSecretBlobEnvelope(blob, vaultId, currentVault.dekVersion)) {
            const err = new Error('Invalid secret blob envelope structure or AAD mismatch');
            err.code = 'ERR_INVALID_BLOB';
            throw err;
          }

          // Secret updates modify only the blob and vaultVersion (dekVersion unchanged)
          currentVault.blob = blob;
          currentVault.vaultVersion = currentVault.vaultVersion + 1;
          currentVault.updatedAt = new Date().toISOString();

          return currentVault;
        });

        sendJsonResponse(res, 200, {
          vaultVersion: updatedVault.vaultVersion,
          dekVersion: updatedVault.dekVersion
        });
        return;
      } catch (err) {
        if (err.code === 'ERR_VAULT_NOT_FOUND') {
          sendErrorResponse(res, 404, 'not_found', 'Vault not found');
          return;
        }
        if (err.code === 'ERR_NOT_MEMBER' || err.code === 'ERR_READONLY_DENIED') {
          sendErrorResponse(res, 403, 'forbidden', err.message);
          return;
        }
        if (err.code === 'ERR_VERSION_CONFLICT') {
          sendErrorResponse(res, 409, 'conflict', err.message);
          return;
        }
        if (err.code === 'ERR_INVALID_BLOB') {
          sendErrorResponse(res, 400, 'invalid_request', err.message);
          return;
        }
        sendErrorResponse(res, 500, 'internal_error', 'Failed to update secrets');
        return;
      }
    }

    // =========================================================================
    // Route 6: POST /api/v1/vault/:vaultId/members (Grant Member Access)
    // =========================================================================
    const membersMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/members$/);
    if (method === 'POST' && membersMatch) {
      const vaultId = membersMatch[1];
      if (!isValidVaultId(vaultId)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid vaultId parameter');
        return;
      }

      const body = parseJsonBody(rawBody);
      if (!body) {
        sendErrorResponse(res, 400, 'invalid_request', 'Malformed JSON payload');
        return;
      }

      const expectedVersion = body.expectedVersion;
      if (typeof expectedVersion !== 'number' || !Number.isInteger(expectedVersion) || expectedVersion < 1) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid expectedVersion: must be positive integer');
        return;
      }

      const targetUsername = body.username;
      if (!isValidUsername(targetUsername)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid target username format');
        return;
      }

      const targetRole = body.role;
      if (targetRole !== 'admin' && targetRole !== 'member' && targetRole !== 'readonly') {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid role: must be admin, member, or readonly');
        return;
      }

      const providedFingerprint = body.publicKeyFingerprint;
      if (typeof providedFingerprint !== 'string' || providedFingerprint.length === 0) {
        sendErrorResponse(res, 400, 'invalid_request', 'Missing publicKeyFingerprint');
        return;
      }

      const targetUserRecord = await storage.getUser(targetUsername);
      if (!targetUserRecord || targetUserRecord.status !== 'active') {
        sendErrorResponse(res, 400, 'invalid_request', 'Target user does not exist or is inactive');
        return;
      }

      // Verify fingerprint matches authoritative server record
      if (targetUserRecord.publicKeyFingerprint !== providedFingerprint) {
        sendErrorResponse(res, 400, 'invalid_request', 'Provided public key fingerprint does not match target user record');
        return;
      }

      const wrappedDek = body.wrappedDek;

      try {
        const updatedVault = await storage.mutateVault(vaultId, function(currentVault) {
          const callerRole = currentVault.members[authUser.username];
          if (!callerRole) {
            const err = new Error('Access denied: not an authorized member');
            err.code = 'ERR_NOT_MEMBER';
            throw err;
          }

          if (callerRole !== 'owner' && callerRole !== 'admin') {
            const err = new Error('Access denied: only owner or admin can grant access');
            err.code = 'ERR_PERMISSION_DENIED';
            throw err;
          }

          // Admin cannot grant another admin (design invariant)
          if (callerRole === 'admin' && targetRole === 'admin') {
            const err = new Error('Admin role violation: admins cannot grant admin privileges');
            err.code = 'ERR_ADMIN_GRANT_ADMIN';
            throw err;
          }

          if (currentVault.vaultVersion !== expectedVersion) {
            const err = new Error('Optimistic concurrency conflict: vault version mismatch');
            err.code = 'ERR_VERSION_CONFLICT';
            throw err;
          }

          if (!validateWrappedDekEnvelope(wrappedDek, vaultId, currentVault.dekVersion, targetUsername)) {
            const err = new Error('Invalid wrapped DEK structure or AAD mismatch');
            err.code = 'ERR_INVALID_WRAPPED_DEK';
            throw err;
          }

          currentVault.members[targetUsername] = targetRole;
          currentVault.wrappedDeks[targetUsername] = wrappedDek;
          currentVault.vaultVersion = currentVault.vaultVersion + 1;
          currentVault.updatedAt = new Date().toISOString();

          return currentVault;
        });

        sendJsonResponse(res, 200, {
          vaultVersion: updatedVault.vaultVersion,
          dekVersion: updatedVault.dekVersion
        });
        return;
      } catch (err) {
        if (err.code === 'ERR_VAULT_NOT_FOUND') {
          sendErrorResponse(res, 404, 'not_found', 'Vault not found');
          return;
        }
        if (err.code === 'ERR_NOT_MEMBER' || err.code === 'ERR_PERMISSION_DENIED' || err.code === 'ERR_ADMIN_GRANT_ADMIN') {
          sendErrorResponse(res, 403, 'forbidden', err.message);
          return;
        }
        if (err.code === 'ERR_VERSION_CONFLICT') {
          sendErrorResponse(res, 409, 'conflict', err.message);
          return;
        }
        if (err.code === 'ERR_INVALID_WRAPPED_DEK') {
          sendErrorResponse(res, 400, 'invalid_request', err.message);
          return;
        }
        sendErrorResponse(res, 500, 'internal_error', 'Failed to grant membership');
        return;
      }
    }

    // =========================================================================
    // Route 7: DELETE /api/v1/vault/:vaultId/members/:username (Revoke Access & Rotate DEK)
    // =========================================================================
    const revokeMatch = pathname.match(/^\/api\/v1\/vault\/([^/]+)\/members\/([^/]+)$/);
    if (method === 'DELETE' && revokeMatch) {
      const vaultId = revokeMatch[1];
      const targetUsername = revokeMatch[2];

      if (!isValidVaultId(vaultId)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid vaultId parameter');
        return;
      }

      if (!isValidUsername(targetUsername)) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid target username parameter');
        return;
      }

      const body = parseJsonBody(rawBody);
      if (!body) {
        sendErrorResponse(res, 400, 'invalid_request', 'Malformed JSON payload');
        return;
      }

      const expectedVersion = body.expectedVersion;
      if (typeof expectedVersion !== 'number' || !Number.isInteger(expectedVersion) || expectedVersion < 1) {
        sendErrorResponse(res, 400, 'invalid_request', 'Invalid expectedVersion: must be positive integer');
        return;
      }

      const newBlob = body.newBlob;
      const newWrappedDeks = body.newWrappedDeks;

      try {
        const updatedVault = await storage.mutateVault(vaultId, function(currentVault) {
          const callerRole = currentVault.members[authUser.username];
          if (!callerRole) {
            const err = new Error('Access denied: not an authorized member');
            err.code = 'ERR_NOT_MEMBER';
            throw err;
          }

          if (callerRole !== 'owner' && callerRole !== 'admin') {
            const err = new Error('Access denied: only owner or admin can revoke members');
            err.code = 'ERR_PERMISSION_DENIED';
            throw err;
          }

          // Invariant: owner can NEVER be revoked
          if (targetUsername === currentVault.owner) {
            const err = new Error('Owner cannot be revoked from the vault');
            err.code = 'ERR_CANNOT_REVOKE_OWNER';
            throw err;
          }

          if (!Object.prototype.hasOwnProperty.call(currentVault.members, targetUsername)) {
            const err = new Error('Target user is not a member of this vault');
            err.code = 'ERR_TARGET_NOT_MEMBER';
            throw err;
          }

          const targetRole = currentVault.members[targetUsername];
          // Admin cannot revoke owner or another admin
          if (callerRole === 'admin') {
            if (targetRole === 'admin' || targetRole === 'owner') {
              const err = new Error('Admin role violation: admins cannot revoke another admin or owner');
              err.code = 'ERR_ADMIN_REVOKE_PRIVILEGED';
              throw err;
            }
          }

          if (currentVault.vaultVersion !== expectedVersion) {
            const err = new Error('Optimistic concurrency conflict: vault version mismatch');
            err.code = 'ERR_VERSION_CONFLICT';
            throw err;
          }

          // Revocation requires mandatory DEK rotation
          const expectedNewDekVersion = currentVault.dekVersion + 1;
          if (!validateSecretBlobEnvelope(newBlob, vaultId, expectedNewDekVersion)) {
            const err = new Error('Invalid rotated secret blob or DEK version mismatch');
            err.code = 'ERR_INVALID_ROTATED_BLOB';
            throw err;
          }

          if (typeof newWrappedDeks !== 'object' || newWrappedDeks === null) {
            const err = new Error('Invalid newWrappedDeks: must be an object');
            err.code = 'ERR_INVALID_WRAPPED_DEKS';
            throw err;
          }

          // Revoked user must NOT have a wrapped DEK in newWrappedDeks
          if (Object.prototype.hasOwnProperty.call(newWrappedDeks, targetUsername)) {
            const err = new Error('Revoked user cannot receive a wrapped DEK');
            err.code = 'ERR_REVOKED_USER_HAS_KEY';
            throw err;
          }

          // All remaining members must have valid wrapped DEKs for the new DEK generation
          const remainingMemberUsernames = Object.keys(currentVault.members).filter(function(uname) {
            return uname !== targetUsername;
          });

          for (const memberName of remainingMemberUsernames) {
            if (!Object.prototype.hasOwnProperty.call(newWrappedDeks, memberName)) {
              const err = new Error(`Missing wrapped DEK for remaining member: ${memberName}`);
              err.code = 'ERR_MISSING_MEMBER_DEK';
              throw err;
            }
            const memberWrappedDek = newWrappedDeks[memberName];
            if (!validateWrappedDekEnvelope(memberWrappedDek, vaultId, expectedNewDekVersion, memberName)) {
              const err = new Error(`Invalid wrapped DEK structure for remaining member: ${memberName}`);
              err.code = 'ERR_INVALID_MEMBER_DEK';
              throw err;
            }
          }

          // Apply state transitions
          delete currentVault.members[targetUsername];
          currentVault.blob = newBlob;
          currentVault.wrappedDeks = newWrappedDeks;
          currentVault.vaultVersion = currentVault.vaultVersion + 1;
          currentVault.dekVersion = expectedNewDekVersion;
          currentVault.updatedAt = new Date().toISOString();

          return currentVault;
        });

        sendJsonResponse(res, 200, {
          vaultVersion: updatedVault.vaultVersion,
          dekVersion: updatedVault.dekVersion
        });
        return;
      } catch (err) {
        if (err.code === 'ERR_VAULT_NOT_FOUND' || err.code === 'ERR_TARGET_NOT_MEMBER') {
          sendErrorResponse(res, 404, 'not_found', err.message);
          return;
        }
        if (err.code === 'ERR_NOT_MEMBER' || err.code === 'ERR_PERMISSION_DENIED' ||
            err.code === 'ERR_CANNOT_REVOKE_OWNER' || err.code === 'ERR_ADMIN_REVOKE_PRIVILEGED') {
          sendErrorResponse(res, 403, 'forbidden', err.message);
          return;
        }
        if (err.code === 'ERR_VERSION_CONFLICT') {
          sendErrorResponse(res, 409, 'conflict', err.message);
          return;
        }
        if (err.code === 'ERR_INVALID_ROTATED_BLOB' || err.code === 'ERR_INVALID_WRAPPED_DEKS' ||
            err.code === 'ERR_REVOKED_USER_HAS_KEY' || err.code === 'ERR_MISSING_MEMBER_DEK' ||
            err.code === 'ERR_INVALID_MEMBER_DEK') {
          sendErrorResponse(res, 400, 'invalid_request', err.message);
          return;
        }
        sendErrorResponse(res, 500, 'internal_error', 'Failed to revoke member');
        return;
      }
    }

    // Default route: Not Found
    sendErrorResponse(res, 404, 'not_found', `Cannot ${method} ${pathname}`);
  }

  let server;
  if (tls) {
    server = https.createServer(tls, requestHandler);
  } else {
    server = http.createServer(requestHandler);
  }

  return {
    server: server,
    storage: storage,
    securityManager: securityManager,

    /**
     * Start listening on specified port and host.
     *
     * @param {number} port - TCP port number.
     * @param {string} bindHost - Host address to bind.
     * @returns {Promise<object>} Server address details.
     */
    async listen(port, bindHost) {
      await storage.init();
      const listenHost = bindHost || host;
      return new Promise(function(resolve, reject) {
        server.listen(port, listenHost, function() {
          resolve(server.address());
        });
        server.on('error', reject);
      });
    },

    /**
     * Gracefully close server and cleanup security manager.
     *
     * @returns {Promise<void>}
     */
    async close() {
      securityManager.destroy();
      return new Promise(function(resolve, reject) {
        server.close(function(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve();
        });
      });
    }
  };
}
