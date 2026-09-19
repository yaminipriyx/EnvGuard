/**
 * Vault Server Client API module.
 *
 * This file is part of Phase 4 (Client Identity & Registration).
 * Provides network transport functions for communicating with the Vault Server:
 * - Server URL resolution with prioritization and fallback.
 * - Transport security policy enforcement (TLS mandatory for non-loopback hosts).
 * - Registration endpoint execution (POST /api/v1/auth/register).
 *
 * Security Contract:
 * - http:// permitted only for loopback addresses (localhost, 127.0.0.1, ::1).
 * - TLS certificate verification is always enforced; optional CA cert support for test environments.
 * - Never transmits raw API tokens, passphrases, or private keys.
 * - Zero ternary operators, zero optional chaining, zero nullish coalescing.
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { URL } from 'node:url';

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
 * Find and parse project configuration file (.envguard.json) from current directory upwards.
 *
 * @param {string} [startDir] - Directory to start searching from.
 * @returns {object|null} Parsed project configuration object or null.
 */
export function loadProjectConfig(startDir) {
  let currentDir = process.cwd();
  if (typeof startDir === 'string' && startDir.length > 0) {
    currentDir = path.resolve(startDir);
  }

  while (true) {
    const candidatePath = path.join(currentDir, '.envguard.json');
    if (fs.existsSync(candidatePath)) {
      try {
        const content = fs.readFileSync(candidatePath, 'utf8');
        return JSON.parse(content);
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
      throw new Error(`Insecure transport: http:// is only permitted for loopback addresses (localhost, 127.0.0.1, [::1]). Remote servers must use https://.`);
    }
  }

  return parsed;
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
