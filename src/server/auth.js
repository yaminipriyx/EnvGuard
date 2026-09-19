/**
 * Request authentication and replay protection module.
 *
 * This file is part of Phase 3 (Vault Server & Storage).
 * Implements canonical request signing verification using HMAC-SHA512,
 * timestamp freshness window enforcement, in-memory replay attack prevention
 * via committed single-use nonces, IP-based authentication failure rate limiting,
 * and timing-safe handling of nonexistent or inactive users.
 *
 * Security Contract:
 * - Reconstructs CANONICAL_STRING from HTTP method, canonical path, timestamp, nonce, and body hash.
 * - Enforces 300-second timestamp freshness window.
 * - Nonce cache key ${username}:${nonce} is committed ONLY after HMAC verification succeeds.
 * - Dummy verification path prevents username enumeration timing side channels.
 * - No secrets, private keys, DEKs, or raw API tokens are handled in this module.
 */

import crypto from 'node:crypto';
import path from 'node:path';

// Static 64-byte dummy verifier buffer used to prevent username enumeration timing differences.
const DUMMY_VERIFIER_BUFFER = crypto.createHash('sha512').update('envguard-timing-safe-dummy-verifier').digest();

/**
 * Normalizes request URL to a canonical path.
 * Strips duplicate slashes and dot segments.
 *
 * @param {string} rawUrl - The raw request URL string.
 * @returns {string} The canonical pathname.
 */
export function normalizeCanonicalPath(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
    return '/';
  }

  let pathname = rawUrl;
  const queryIndex = rawUrl.indexOf('?');
  if (queryIndex !== -1) {
    pathname = rawUrl.substring(0, queryIndex);
  }

  const normalized = path.posix.normalize(pathname);
  if (!normalized.startsWith('/')) {
    return '/' + normalized;
  }
  return normalized;
}

/**
 * Compute SHA-512 hex digest of request body buffer.
 *
 * @param {Buffer|null} bodyBuffer - Raw request body buffer.
 * @returns {string} 128-character hex digest of body.
 */
export function computeBodyHash(bodyBuffer) {
  let bufferToHash;
  if (Buffer.isBuffer(bodyBuffer)) {
    bufferToHash = bodyBuffer;
  } else if (typeof bodyBuffer === 'string') {
    bufferToHash = Buffer.from(bodyBuffer, 'utf8');
  } else {
    bufferToHash = Buffer.alloc(0);
  }
  return crypto.createHash('sha512').update(bufferToHash).digest('hex');
}

/**
 * Replay protection and rate limiting manager.
 */
export class AuthSecurityManager {
  constructor() {
    this.nonceCache = new Map();
    this.ipRateLimits = new Map();
    this.cleanupIntervalMs = 60000; // 1 minute
    this.nonceTtlMs = 600000; // 10 minutes (600 seconds)
    this.lockoutDurationMs = 900000; // 15 minutes (900 seconds)
    this.maxFailedAttempts = 10;

    // Periodic sweep to prevent unbounded memory growth
    this.sweepTimer = setInterval(() => {
      this.cleanupExpired();
    }, this.cleanupIntervalMs);

    if (this.sweepTimer.unref) {
      this.sweepTimer.unref();
    }
  }

  /**
   * Stop background timers.
   */
  destroy() {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
  }

  /**
   * Remove expired nonces and stale rate limit records.
   */
  cleanupExpired() {
    const now = Date.now();
    for (const entry of this.nonceCache.entries()) {
      const key = entry[0];
      const expiresAt = entry[1];
      if (now > expiresAt) {
        this.nonceCache.delete(key);
      }
    }

    for (const entry of this.ipRateLimits.entries()) {
      const ip = entry[0];
      const record = entry[1];
      if (record.lockoutUntil > 0) {
        if (now > record.lockoutUntil) {
          this.ipRateLimits.delete(ip);
        }
      } else if (now - record.lastFailureTime > this.lockoutDurationMs) {
        this.ipRateLimits.delete(ip);
      }
    }
  }

  /**
   * Check whether an IP address is currently locked out.
   *
   * @param {string} ip - Client IP address.
   * @returns {boolean} True if locked out, false otherwise.
   */
  isIpLockedOut(ip) {
    if (!ip) {
      return false;
    }
    const record = this.ipRateLimits.get(ip);
    if (!record) {
      return false;
    }
    const now = Date.now();
    if (record.lockoutUntil > 0) {
      if (now < record.lockoutUntil) {
        return true;
      }
      this.ipRateLimits.delete(ip);
      return false;
    }
    return false;
  }

  /**
   * Record a failed authentication attempt for an IP.
   *
   * @param {string} ip - Client IP address.
   */
  recordAuthFailure(ip) {
    if (!ip) {
      return;
    }
    const now = Date.now();
    let record = this.ipRateLimits.get(ip);
    if (!record) {
      record = {
        failedCount: 1,
        lastFailureTime: now,
        lockoutUntil: 0
      };
      this.ipRateLimits.set(ip, record);
      return;
    }

    record.failedCount = record.failedCount + 1;
    record.lastFailureTime = now;

    if (record.failedCount >= this.maxFailedAttempts) {
      record.lockoutUntil = now + this.lockoutDurationMs;
    }
  }

  /**
   * Record a successful authentication attempt for an IP.
   *
   * @param {string} ip - Client IP address.
   */
  recordAuthSuccess(ip) {
    if (!ip) {
      return;
    }
    this.ipRateLimits.delete(ip);
  }

  /**
   * Check if a nonce has already been consumed.
   *
   * @param {string} username - Client username.
   * @param {string} nonce - Nonce hex string.
   * @returns {boolean} True if nonce was already consumed (replay), false otherwise.
   */
  isNonceReplayed(username, nonce) {
    const key = `${username}:${nonce}`;
    if (this.nonceCache.has(key)) {
      const expiresAt = this.nonceCache.get(key);
      if (Date.now() < expiresAt) {
        return true;
      }
      this.nonceCache.delete(key);
      return false;
    }
    return false;
  }

  /**
   * Commit a nonce to the replay cache after successful signature verification.
   *
   * @param {string} username - Client username.
   * @param {string} nonce - Nonce hex string.
   */
  commitNonce(username, nonce) {
    const key = `${username}:${nonce}`;
    const expiresAt = Date.now() + this.nonceTtlMs;
    this.nonceCache.set(key, expiresAt);
  }
}

/**
 * Validate and verify incoming request authentication.
 *
 * @param {object} req - Node.js HTTP request.
 * @param {Buffer} rawBody - Raw request body buffer.
 * @param {object} storage - Storage instance.
 * @param {AuthSecurityManager} securityManager - Security manager instance.
 * @returns {Promise<{ authenticated: boolean, user: object, statusCode: number, errorMessage: string }>}
 */
export async function authenticateRequest(req, rawBody, storage, securityManager) {
  const clientIp = req.socket.remoteAddress || 'unknown';

  // Check IP rate limiting
  if (securityManager.isIpLockedOut(clientIp)) {
    return {
      authenticated: false,
      statusCode: 429,
      errorMessage: 'Too many failed authentication attempts. Please try again later.'
    };
  }

  // Reject query parameters on authenticated routes (strict design invariant)
  if (req.url && req.url.indexOf('?') !== -1) {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Query parameters are strictly forbidden on authenticated routes'
    };
  }

  const rawUser = req.headers['x-envguard-user'];
  const rawTimestamp = req.headers['x-envguard-timestamp'];
  const rawNonce = req.headers['x-envguard-nonce'];
  const rawSignature = req.headers['x-envguard-signature'];

  // (1) Header Validation: presence, type, length (<= 256 bytes)
  if (typeof rawUser !== 'string' || typeof rawTimestamp !== 'string' ||
      typeof rawNonce !== 'string' || typeof rawSignature !== 'string') {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Missing required authentication headers'
    };
  }

  if (Buffer.byteLength(rawUser, 'utf8') > 256 ||
      Buffer.byteLength(rawTimestamp, 'utf8') > 256 ||
      Buffer.byteLength(rawNonce, 'utf8') > 256 ||
      Buffer.byteLength(rawSignature, 'utf8') > 256) {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Authentication headers exceed maximum permitted size of 256 bytes'
    };
  }

  // Validate nonce format: 16 bytes = 32 hex characters
  const nonceRegex = /^[0-9a-fA-F]{32}$/;
  if (!nonceRegex.test(rawNonce)) {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Invalid nonce format: must be 32 hexadecimal characters'
    };
  }

  // Validate signature format: 64 bytes = 128 hex characters
  const sigRegex = /^[0-9a-fA-F]{128}$/;
  if (!sigRegex.test(rawSignature)) {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Invalid signature format: must be 128 hexadecimal characters'
    };
  }

  // (2) Timestamp Freshness Window: delta <= 300 seconds
  const requestTime = Date.parse(rawTimestamp);
  if (Number.isNaN(requestTime)) {
    return {
      authenticated: false,
      statusCode: 400,
      errorMessage: 'Invalid timestamp format: must be valid ISO 8601 string'
    };
  }

  const now = Date.now();
  const deltaSeconds = Math.abs(now - requestTime) / 1000;
  if (deltaSeconds > 300) {
    return {
      authenticated: false,
      statusCode: 401,
      errorMessage: 'Request timestamp is outside the allowed 300-second freshness window'
    };
  }

  // (3) Construct CANONICAL_STRING
  const canonicalMethod = req.method.toUpperCase();
  const canonicalPath = normalizeCanonicalPath(req.url);
  const bodyHash = computeBodyHash(rawBody);

  const canonicalString = canonicalMethod + '\n' +
                          canonicalPath + '\n' +
                          rawTimestamp + '\n' +
                          rawNonce + '\n' +
                          bodyHash;

  // (4) User Lookup & Timing-Safe Verification Path
  const user = await storage.getUser(rawUser);

  let verifierBuffer;
  let isDummy = false;

  if (user && user.status === 'active' && typeof user.authVerifier === 'string' && user.authVerifier.length === 128) {
    try {
      verifierBuffer = Buffer.from(user.authVerifier, 'hex');
    } catch (err) {
      verifierBuffer = DUMMY_VERIFIER_BUFFER;
      isDummy = true;
    }
  } else {
    verifierBuffer = DUMMY_VERIFIER_BUFFER;
    isDummy = true;
  }

  const computedSignatureHex = crypto.createHmac('sha512', verifierBuffer).update(canonicalString).digest('hex');
  const computedBuffer = Buffer.from(computedSignatureHex, 'hex');
  const providedBuffer = Buffer.from(rawSignature, 'hex');

  let signaturesMatch = false;
  if (computedBuffer.length === providedBuffer.length) {
    signaturesMatch = crypto.timingSafeEqual(computedBuffer, providedBuffer);
  }

  if (isDummy || !signaturesMatch) {
    securityManager.recordAuthFailure(clientIp);
    return {
      authenticated: false,
      statusCode: 401,
      errorMessage: 'Authentication failed: invalid credentials or signature'
    };
  }

  // (5) Nonce Cache Check (Committed ONLY after signature is verified)
  if (securityManager.isNonceReplayed(rawUser, rawNonce)) {
    securityManager.recordAuthFailure(clientIp);
    return {
      authenticated: false,
      statusCode: 401,
      errorMessage: 'Replay attack detected: nonce has already been used'
    };
  }

  // Commit valid nonce to cache
  securityManager.commitNonce(rawUser, rawNonce);
  securityManager.recordAuthSuccess(clientIp);

  return {
    authenticated: true,
    user: user
  };
}
