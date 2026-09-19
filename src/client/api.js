/**
 * Vault Server Client API module.
 *
 * This file is part of Phase 4 and Phase 5.
 * Provides network transport functions for communicating with the Vault Server:
 * - Server URL resolution with prioritization and fallback.
 * - Transport security policy enforcement (TLS mandatory for non-loopback hosts).
 * - Registration endpoint execution (POST /api/v1/auth/register).
 * - Project configuration management (.envguard.json finding and atomic saving).
 * - Canonical HMAC-SHA512 request signing and authenticated dispatch.
 * - Vault creation, secret retrieval, and secret update endpoints.
 *
 * Security Contract:
 * - http:// permitted only for loopback addresses (localhost, 127.0.0.1, ::1).
 * - TLS certificate verification is always enforced; optional CA cert support for test environments.
 * - Never transmits raw API tokens, passphrases, raw DEKs, or private keys.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { URL } from 'node:url';
import * as kdf from '../crypto/kdf.js';
import { normalizeCanonicalPath } from '../server/auth.js';

/**
 * Check whether a hostname is a recognized loopback address.
 *
 * @param {string} hostname - Hostname string to check.
 * @returns {boolean} True if loopback, false otherwise.
 */
export function isLoopbackHostname(hostname) {
  if (typeof hostname !== 'string') {
    return false;
  }
  const cleanHost = hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase();
  if (cleanHost === 'localhost') {
    return true;
  }
  if (cleanHost === '127.0.0.1') {
    return true;
  }
  if (cleanHost === '::1') {
    return true;
  }
  return false;
}

/**
 * Find project configuration file (.envguard.json) from current directory upwards.
 *
 * @param {string} [startDir] - Directory to start searching from.
 * @returns {{ config: object, filePath: string }|null} Config and file path or null.
 */
export function findProjectConfig(startDir) {
  let currentDir = process.cwd();
  if (typeof startDir === 'string' && startDir.length > 0) {
    currentDir = path.resolve(startDir);
  }

  while (true) {
    const candidatePath = path.join(currentDir, '.envguard.json');
    if (fs.existsSync(candidatePath)) {
      try {
        const content = fs.readFileSync(candidatePath, 'utf8');
        const parsed = JSON.parse(content);
        return {
          config: parsed,
          filePath: candidatePath
        };
      } catch (err) {
        return null;
      }
    }
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) {
      break;
    }
    currentDir = parentDir;
  }
  return null;
}

/**
 * Find and parse project configuration file (.envguard.json) from current directory upwards.
 *
 * @param {string} [startDir] - Directory to start searching from.
 * @returns {object|null} Parsed project configuration object or null.
 */
export function loadProjectConfig(startDir) {
  const found = findProjectConfig(startDir);
  if (found) {
    return found.config;
  }
  return null;
}

/**
 * Atomically save project configuration to .envguard.json preserving existing properties.
 *
 * @param {string} filePath - Absolute path to .envguard.json.
 * @param {object} config - Configuration object to serialize.
 */
export async function saveProjectConfig(filePath, config) {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw new TypeError('Invalid filePath: must be a non-empty string');
  }
  if (typeof config !== 'object' || config === null) {
    throw new TypeError('Invalid config: must be an object');
  }

  const content = JSON.stringify(config, null, 2) + '\n';
  const randomSuffix = crypto.randomBytes(8).toString('hex');
  const tempPath = `${filePath}.${randomSuffix}.tmp`;

  let fileHandle = null;
  try {
    fileHandle = await fsp.open(tempPath, 'wx');
    await fileHandle.writeFile(content, 'utf8');
    await fileHandle.sync();
    await fileHandle.close();
    fileHandle = null;

    await fsp.rename(tempPath, filePath);
  } catch (err) {
    if (fileHandle !== null) {
      try {
        await fileHandle.close();
      } catch (closeErr) {
        // Suppress secondary error
      }
    }
    if (fs.existsSync(tempPath)) {
      try {
        await fsp.unlink(tempPath);
      } catch (unlinkErr) {
        // Suppress secondary error
      }
    }
    throw err;
  }
}

/**
 * Resolve the Vault Server URL according to design specification priority:
 * 1. CLI option (--server)
 * 2. ENVGUARD_SERVER environment variable
 * 3. serverUrl in .envguard.json
 * 4. Fallback: http://localhost:3000
 *
 * @param {string} [cliOption] - Optional CLI --server argument.
 * @param {object} [projectConfig] - Optional pre-loaded project configuration.
 * @returns {string} The resolved server URL.
 */
export function resolveServerUrl(cliOption, projectConfig) {
  if (typeof cliOption === 'string' && cliOption.length > 0) {
    return cliOption.trim();
  }

  if (typeof process.env.ENVGUARD_SERVER === 'string' && process.env.ENVGUARD_SERVER.length > 0) {
    return process.env.ENVGUARD_SERVER.trim();
  }

  let config = projectConfig;
  if (!config) {
    config = loadProjectConfig();
  }

  if (config && typeof config.serverUrl === 'string' && config.serverUrl.length > 0) {
    return config.serverUrl.trim();
  }

  return 'http://localhost:3000';
}

/**
 * Validate and sanitize a Vault Server URL against transport security policy.
 * Throws an error if transport policy is violated.
 *
 * @param {string} serverUrl - Candidate server URL string.
 * @returns {URL} Parsed and validated URL instance.
 */
export function validateServerUrl(serverUrl) {
  if (typeof serverUrl !== 'string' || serverUrl.length === 0) {
    throw new TypeError('Invalid server URL: must be a non-empty string');
  }

  let parsed;
  try {
    parsed = new URL(serverUrl);
  } catch (err) {
    throw new Error(`Invalid server URL format: ${serverUrl}`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported server protocol "${parsed.protocol}": must be http: or https:`);
  }

  if (parsed.protocol === 'http:') {
    if (!isLoopbackHostname(parsed.hostname)) {
      throw new Error('Insecure transport: http:// is only permitted for loopback addresses (localhost, 127.0.0.1, [::1]). Remote servers must use https://.');
    }
  }

  return parsed;
}

/**
 * Generate HMAC-SHA512 authentication headers for a request according to Phase 3 server protocol.
 *
 * @param {string} method - Uppercase HTTP method (GET, POST, PUT, DELETE).
 * @param {string} endpointPath - Request path including any query string.
 * @param {string|Buffer|null} rawBody - Raw serialized request body or empty.
 * @param {object} credentials - Local credentials object { username, apiToken, userSalt }.
 * @returns {object} Map of authentication headers.
 */
export function signRequest(method, endpointPath, rawBody, credentials) {
  if (typeof method !== 'string' || method.length === 0) {
    throw new TypeError('Invalid method: must be a non-empty string');
  }
  if (typeof endpointPath !== 'string' || endpointPath.length === 0) {
    throw new TypeError('Invalid endpointPath: must be a non-empty string');
  }
  if (typeof credentials !== 'object' || credentials === null) {
    throw new TypeError('Invalid credentials: must be an object');
  }
  if (typeof credentials.username !== 'string' || credentials.username.length === 0) {
    throw new TypeError('Invalid credentials: missing username');
  }
  if (typeof credentials.apiToken !== 'string' || credentials.apiToken.length !== 64) {
    throw new TypeError('Invalid credentials: apiToken must be a 64-hex string');
  }
  if (typeof credentials.userSalt !== 'string' || credentials.userSalt.length !== 32) {
    throw new TypeError('Invalid credentials: userSalt must be a 32-hex string');
  }

  const tokenBuffer = Buffer.from(credentials.apiToken, 'hex');
  const saltBuffer = Buffer.from(credentials.userSalt, 'hex');

  let kSign = null;
  try {
    kSign = kdf.hkdfSha512(tokenBuffer, saltBuffer, 'envguard-client-signing-v1', 64);
  } finally {
    tokenBuffer.fill(0);
    saltBuffer.fill(0);
  }

  const timestamp = new Date().toISOString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const canonicalPath = normalizeCanonicalPath(endpointPath);

  let bodyBuffer = Buffer.alloc(0);
  if (Buffer.isBuffer(rawBody)) {
    bodyBuffer = rawBody;
  } else if (typeof rawBody === 'string') {
    bodyBuffer = Buffer.from(rawBody, 'utf8');
  }

  const bodyHash = crypto.createHash('sha512').update(bodyBuffer).digest('hex');

  const canonicalString = method.toUpperCase() + '\n' +
                          canonicalPath + '\n' +
                          timestamp + '\n' +
                          nonce + '\n' +
                          bodyHash;

  let signature;
  try {
    signature = crypto.createHmac('sha512', kSign).update(canonicalString).digest('hex');
  } finally {
    kSign.fill(0);
  }

  return {
    'X-EnvGuard-User': credentials.username,
    'X-EnvGuard-Timestamp': timestamp,
    'X-EnvGuard-Nonce': nonce,
    'X-EnvGuard-Signature': signature
  };
}

/**
 * Send an authenticated request to the Vault Server.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} method - HTTP method ('GET', 'POST', 'PUT', etc.).
 * @param {string} endpointPath - Endpoint path (e.g. '/api/v1/vault').
 * @param {object|null} bodyData - JSON payload or null.
 * @param {object} credentials - Client credentials object { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options ({ caCertPath, caCertContent, timeoutMs }).
 * @returns {Promise<object>} Parsed JSON response body on success.
 */
export async function sendAuthenticatedRequest(serverUrl, method, endpointPath, bodyData, credentials, options) {
  const parsedUrl = validateServerUrl(serverUrl);

  let bodyString = '';
  if (bodyData !== null && typeof bodyData !== 'undefined') {
    bodyString = JSON.stringify(bodyData);
  }

  const authHeaders = signRequest(method, endpointPath, bodyString, credentials);

  const requestHeaders = Object.assign({}, authHeaders, {
    'Accept': 'application/json'
  });

  if (bodyString.length > 0) {
    requestHeaders['Content-Type'] = 'application/json';
    requestHeaders['Content-Length'] = Buffer.byteLength(bodyString, 'utf8');
  }

  const isHttps = parsedUrl.protocol === 'https:';
  let transport = http;
  if (isHttps) {
    transport = https;
  }

  let port = parsedUrl.port;
  if (!port) {
    if (isHttps) {
      port = 443;
    } else {
      port = 80;
    }
  }

  const requestOptions = {
    hostname: parsedUrl.hostname,
    port: port,
    path: endpointPath,
    method: method.toUpperCase(),
    headers: requestHeaders
  };

  let caCertPath = null;
  if (options && typeof options.caCertPath === 'string') {
    caCertPath = options.caCertPath;
  } else if (typeof process.env.ENVGUARD_CA_CERT === 'string') {
    caCertPath = process.env.ENVGUARD_CA_CERT;
  }

  if (isHttps) {
    if (caCertPath && fs.existsSync(caCertPath)) {
      const caContent = fs.readFileSync(caCertPath, 'utf8');
      requestOptions.ca = [caContent];
    } else if (options && options.caCertContent) {
      requestOptions.ca = [options.caCertContent];
    }
  }

  let timeoutMs = 10000;
  if (options && typeof options.timeoutMs === 'number' && options.timeoutMs > 0) {
    timeoutMs = options.timeoutMs;
  }

  return new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      const chunks = [];

      res.on('data', (chunk) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        const bodyBuffer = Buffer.concat(chunks);
        const bodyText = bodyBuffer.toString('utf8');

        let parsedBody = null;
        if (bodyText.length > 0) {
          try {
            parsedBody = JSON.parse(bodyText);
          } catch (jsonErr) {
            // Non-JSON response
          }
        }

        const statusCode = res.statusCode;

        if (statusCode >= 200 && statusCode < 300) {
          if (parsedBody) {
            resolve(parsedBody);
            return;
          }
          resolve({});
          return;
        }

        let errorMessage = `Server returned HTTP ${statusCode}`;
        if (parsedBody && typeof parsedBody.message === 'string') {
          errorMessage = parsedBody.message;
        }

        const error = new Error(errorMessage);
        error.statusCode = statusCode;
        error.responseBody = parsedBody;

        reject(error);
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms connecting to Vault Server`));
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (bodyString.length > 0) {
      req.write(bodyString);
    }
    req.end();
  });
}

/**
 * Submit user registration request to the Vault Server.
 *
 * @param {string} serverUrl - Base Vault Server URL.
 * @param {object} registrationPayload - Payload containing username, publicKey, salt, authVerifier, enrollmentKey.
 * @param {object} [options] - Optional transport options ({ caCertPath, caCertContent, timeoutMs }).
 * @returns {Promise<object>} Server response payload on success.
 */
export async function registerUser(serverUrl, registrationPayload, options) {
  const parsedUrl = validateServerUrl(serverUrl);

  if (typeof registrationPayload !== 'object' || registrationPayload === null) {
    throw new TypeError('Invalid registration payload: must be a non-null object');
  }

  // Security check: ensure raw API token or private key is NEVER in payload
  if (Object.prototype.hasOwnProperty.call(registrationPayload, 'apiToken') ||
      Object.prototype.hasOwnProperty.call(registrationPayload, 'rawToken') ||
      Object.prototype.hasOwnProperty.call(registrationPayload, 'passphrase') ||
      Object.prototype.hasOwnProperty.call(registrationPayload, 'privateKey') ||
      Object.prototype.hasOwnProperty.call(registrationPayload, 'd')) {
    throw new Error('Security violation: raw secrets detected in registration payload');
  }

  const payloadString = JSON.stringify(registrationPayload);
  const isHttps = parsedUrl.protocol === 'https:';
  let transport = http;
  if (isHttps) {
    transport = https;
  }

  const requestHeaders = {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payloadString, 'utf8'),
    'Accept': 'application/json'
  };

  let port = parsedUrl.port;
  if (!port) {
    if (isHttps) {
      port = 443;
    } else {
      port = 80;
    }
  }

  const requestOptions = {
    hostname: parsedUrl.hostname,
    port: port,
    path: '/api/v1/auth/register',
    method: 'POST',
    headers: requestHeaders
  };

  let caCertPath = null;
  if (options && typeof options.caCertPath === 'string') {
    caCertPath = options.caCertPath;
  } else if (typeof process.env.ENVGUARD_CA_CERT === 'string') {
    caCertPath = process.env.ENVGUARD_CA_CERT;
  }

  if (isHttps) {
    if (caCertPath && fs.existsSync(caCertPath)) {
      const caContent = fs.readFileSync(caCertPath, 'utf8');
      requestOptions.ca = [caContent];
    } else if (options && options.caCertContent) {
      requestOptions.ca = [options.caCertContent];
    }
  }

  let timeoutMs = 10000;
  if (options && typeof options.timeoutMs === 'number' && options.timeoutMs > 0) {
    timeoutMs = options.timeoutMs;
  }

  return new Promise((resolve, reject) => {
    const req = transport.request(requestOptions, (res) => {
      const chunks = [];

      res.on('data', (chunk) => {
        chunks.push(chunk);
      });

      res.on('end', () => {
        const bodyBuffer = Buffer.concat(chunks);
        const bodyText = bodyBuffer.toString('utf8');

        let parsedBody = null;
        if (bodyText.length > 0) {
          try {
            parsedBody = JSON.parse(bodyText);
          } catch (jsonErr) {
            // Non-JSON response
          }
        }

        const statusCode = res.statusCode;

        if (statusCode === 201) {
          if (parsedBody && parsedBody.status === 'created') {
            resolve(parsedBody);
            return;
          }
          resolve({ status: 'created', username: registrationPayload.username });
          return;
        }

        let errorMessage = `Server returned HTTP ${statusCode}`;
        if (parsedBody && typeof parsedBody.message === 'string') {
          errorMessage = parsedBody.message;
        }

        if (statusCode === 400) {
          reject(new Error(`Registration failed (invalid request): ${errorMessage}`));
          return;
        }
        if (statusCode === 403) {
          reject(new Error(`Registration failed (forbidden): ${errorMessage}`));
          return;
        }
        if (statusCode === 409) {
          reject(new Error(`Registration failed (conflict): ${errorMessage}`));
          return;
        }
        if (statusCode === 413) {
          reject(new Error(`Registration failed (payload too large): ${errorMessage}`));
          return;
        }
        if (statusCode >= 500) {
          reject(new Error(`Registration failed (server error): ${errorMessage}`));
          return;
        }

        reject(new Error(`Registration failed with status ${statusCode}: ${errorMessage}`));
      });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${timeoutMs}ms connecting to Vault Server`));
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.write(payloadString);
    req.end();
  });
}

/**
 * Create a new vault on the Vault Server.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {object} vaultPayload - { vaultId, blob, wrappedDek }.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} Created vault metadata { vaultId, vaultVersion: 1, dekVersion: 1 }.
 */
export async function createVault(serverUrl, vaultPayload, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'POST', '/api/v1/vault', vaultPayload, credentials, options);
}

/**
 * Fetch encrypted vault secrets and wrapped DEKs from the Vault Server.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} vaultId - Vault identifier.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} Vault state { vaultVersion, dekVersion, blob, wrappedDeks }.
 */
export async function getVaultSecrets(serverUrl, vaultId, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'GET', `/api/v1/vault/${vaultId}/secrets`, null, credentials, options);
}

/**
 * Update the encrypted secret blob in an existing vault.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} vaultId - Vault identifier.
 * @param {object} updatePayload - { expectedVersion, blob }.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} Updated vault metadata { vaultVersion, dekVersion }.
 */
export async function updateVaultSecrets(serverUrl, vaultId, updatePayload, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'PUT', `/api/v1/vault/${vaultId}/secrets`, updatePayload, credentials, options);
}

/**
 * Fetch a registered user's public identity and fingerprint from the Vault Server.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} targetUsername - Username of user to lookup.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} User identity { username, publicKey, publicKeyFingerprint, status }.
 */
export async function getUser(serverUrl, targetUsername, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'GET', `/api/v1/users/${targetUsername}`, null, credentials, options);
}

/**
 * Grant vault access to a user.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} vaultId - Vault identifier.
 * @param {object} grantPayload - { expectedVersion, username, role, wrappedDek, publicKeyFingerprint }.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} Updated vault metadata { vaultVersion, dekVersion }.
 */
export async function grantVaultMember(serverUrl, vaultId, grantPayload, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'POST', `/api/v1/vault/${vaultId}/members`, grantPayload, credentials, options);
}

/**
 * Revoke vault access from a user and commit rotated vault state.
 *
 * @param {string} serverUrl - Vault Server base URL.
 * @param {string} vaultId - Vault identifier.
 * @param {string} targetUsername - Username of member to revoke.
 * @param {object} revokePayload - { expectedVersion, newBlob, newWrappedDeks }.
 * @param {object} credentials - Client credentials { username, apiToken, userSalt }.
 * @param {object} [options] - Optional transport options.
 * @returns {Promise<object>} Updated vault metadata { vaultVersion, dekVersion }.
 */
export async function revokeVaultMember(serverUrl, vaultId, targetUsername, revokePayload, credentials, options) {
  return sendAuthenticatedRequest(serverUrl, 'DELETE', `/api/v1/vault/${vaultId}/members/${targetUsername}`, revokePayload, credentials, options);
}

