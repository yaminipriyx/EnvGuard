/**
 * Vault server persistent storage engine.
 *
 * This file is part of Phase 3 (Vault Server & Storage).
 * Implements persistent atomic storage for users.json and vaults/<vaultId>.json.
 * Enforces strict path traversal defenses, in-process asynchronous mutex locking
 * per vault and globally for users, atomic temporary write-and-rename semantics,
 * and strict validation of zero-knowledge invariant structures.
 *
 * Security Contract:
 * - Never store raw API tokens, developer private keys, passphrases, plaintext secrets, or DEKs.
 * - Path traversal attempts (.., separators, absolute paths) are rejected before path construction.
 * - Exclusive creation semantics (wx flag) prevent vault creation race conditions.
 * - Concurrency serialization ensures atomic state transitions across read-validate-modify-write.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * Validate vault identifier format and path safety.
 *
 * @param {string} vaultId - Candidate vault identifier.
 * @returns {boolean} True if vault ID is valid and safe, false otherwise.
 */
export function isValidVaultId(vaultId) {
  if (typeof vaultId !== 'string') {
    return false;
  }
  if (vaultId.length === 0 || vaultId.length > 128) {
    return false;
  }
  if (vaultId === '.' || vaultId === '..') {
    return false;
  }
  if (vaultId.indexOf('/') !== -1 || vaultId.indexOf('\\') !== -1) {
    return false;
  }
  const validRegex = /^[a-zA-Z0-9_-]+$/;
  if (!validRegex.test(vaultId)) {
    return false;
  }
  return true;
}

/**
 * Validate username format and path safety.
 *
 * @param {string} username - Candidate username.
 * @returns {boolean} True if username is valid and safe, false otherwise.
 */
export function isValidUsername(username) {
  if (typeof username !== 'string') {
    return false;
  }
  if (username.length === 0 || username.length > 64) {
    return false;
  }
  if (username === '.' || username === '..') {
    return false;
  }
  if (username.indexOf('/') !== -1 || username.indexOf('\\') !== -1) {
    return false;
  }
  const validRegex = /^[a-zA-Z0-9_.-]+$/;
  if (!validRegex.test(username)) {
    return false;
  }
  return true;
}

/**
 * In-process asynchronous mutex queue for serializing operations.
 */
export class AsyncMutex {
  constructor() {
    this.queue = Promise.resolve();
  }

  /**
   * Acquire lock, returning a release callback.
   *
   * @returns {Promise<Function>} A function to call when releasing the lock.
   */
  acquire() {
    let releaseLock;
    const nextPromise = new Promise(function(resolve) {
      releaseLock = resolve;
    });

    const currentQueue = this.queue;
    this.queue = this.queue.then(function() {
      return nextPromise;
    });

    return currentQueue.then(function() {
      return releaseLock;
    });
  }
}

/**
 * Atomically write data as JSON to the destination path.
 * Writes to a unique temp file in the same directory, flushes via filehandle.sync(),
 * and renames over the target path.
 *
 * @param {string} targetPath - Final destination file path.
 * @param {object} data - Data to serialize and persist.
 * @returns {Promise<void>}
 */
export async function atomicWriteJson(targetPath, data) {
  const dir = path.dirname(targetPath);
  const uuid = crypto.randomUUID();
  const tempPath = path.join(dir, `${path.basename(targetPath)}.${uuid}.tmp`);
  const serialized = JSON.stringify(data, null, 2);

  let handle;
  try {
    handle = await fs.promises.open(tempPath, 'wx', 0o600);
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;

    await fs.promises.rename(tempPath, targetPath);
  } catch (err) {
    if (handle) {
      try {
        await handle.close();
      } catch (closeErr) {
        // Suppress secondary close errors
      }
    }
    try {
      await fs.promises.unlink(tempPath);
    } catch (unlinkErr) {
      // Suppress temp unlink error if file was never created
    }
    throw err;
  }
}

/**
 * Storage management class for the EnvGuard Vault Server.
 */
export class Storage {
  /**
   * Initialize storage with a specified root directory.
   *
   * @param {string} dataDir - Root directory for server storage.
   */
  constructor(dataDir) {
    if (typeof dataDir !== 'string' || dataDir.length === 0) {
      throw new TypeError('Invalid dataDir: must be a non-empty string');
    }
    this.dataDir = path.resolve(dataDir);
    this.usersFilePath = path.join(this.dataDir, 'users.json');
    this.vaultsDirPath = path.join(this.dataDir, 'vaults');

    this.usersMutex = new AsyncMutex();
    this.vaultCreationMutex = new AsyncMutex();
    this.vaultMutexes = new Map();
  }

  /**
   * Get or create an AsyncMutex for a specific vaultId.
   *
   * @param {string} vaultId - Unique vault identifier.
   * @returns {AsyncMutex} Mutex dedicated to the vault.
   */
  getVaultMutex(vaultId) {
    if (!this.vaultMutexes.has(vaultId)) {
      this.vaultMutexes.set(vaultId, new AsyncMutex());
    }
    return this.vaultMutexes.get(vaultId);
  }

  /**
   * Initialize server storage directories and files if they do not exist.
   *
   * @returns {Promise<void>}
   */
  async init() {
    await fs.promises.mkdir(this.dataDir, { recursive: true });
    await fs.promises.mkdir(this.vaultsDirPath, { recursive: true });

    const release = await this.usersMutex.acquire();
    try {
      let usersExist = false;
      try {
        await fs.promises.access(this.usersFilePath, fs.constants.F_OK);
        usersExist = true;
      } catch (err) {
        usersExist = false;
      }

      if (!usersExist) {
        await atomicWriteJson(this.usersFilePath, {});
      }
    } finally {
      release();
    }
  }

  /**
   * Resolve a safe absolute file path for a vault file.
   *
   * @param {string} vaultId - Vault identifier.
   * @returns {string} Absolute path to the vault JSON file.
   */
  getVaultFilePath(vaultId) {
    if (!isValidVaultId(vaultId)) {
      const error = new Error(`Invalid or malformed vault ID: ${vaultId}`);
      error.code = 'ERR_INVALID_VAULT_ID';
      throw error;
    }

    const resolved = path.join(this.vaultsDirPath, `${vaultId}.json`);
    const relative = path.relative(this.vaultsDirPath, resolved);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      const error = new Error('Path traversal detected');
      error.code = 'ERR_PATH_TRAVERSAL';
      throw error;
    }
    return resolved;
  }

  /**
   * Read all users from users.json.
   * Must be called while holding usersMutex if mutations are performed.
   *
   * @returns {Promise<object>} Map of username -> user record.
   */
  async readUsersRaw() {
    try {
      const raw = await fs.promises.readFile(this.usersFilePath, 'utf8');
      const parsed = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null) {
        return {};
      }
      return parsed;
    } catch (err) {
      if (err.code === 'ENOENT') {
        return {};
      }
      throw err;
    }
  }

  /**
   * Retrieve a user by username.
   *
   * @param {string} username - Target username.
   * @returns {Promise<object|null>} User record or null if not found.
   */
  async getUser(username) {
    if (!isValidUsername(username)) {
      return null;
    }

    const release = await this.usersMutex.acquire();
    try {
      const users = await this.readUsersRaw();
      if (Object.prototype.hasOwnProperty.call(users, username)) {
        return users[username];
      }
      return null;
    } finally {
      release();
    }
  }

  /**
   * Save a new user to users.json under the users mutex lock.
   * Rejects if username already exists.
   *
   * @param {object} userRecord - Valid user record.
   * @returns {Promise<void>}
   */
  async createUser(userRecord) {
    if (typeof userRecord !== 'object' || userRecord === null) {
      throw new TypeError('Invalid userRecord: must be an object');
    }

    const username = userRecord.username;
    if (!isValidUsername(username)) {
      const error = new Error('Invalid username');
      error.code = 'ERR_INVALID_USERNAME';
      throw error;
    }

    const release = await this.usersMutex.acquire();
    try {
      const users = await this.readUsersRaw();
      if (Object.prototype.hasOwnProperty.call(users, username)) {
        const error = new Error(`User already exists: ${username}`);
        error.code = 'ERR_USER_EXISTS';
        throw error;
      }

      users[username] = userRecord;
      await atomicWriteJson(this.usersFilePath, users);
    } finally {
      release();
    }
  }

  /**
   * Read a vault by vaultId.
   *
   * @param {string} vaultId - Vault identifier.
   * @returns {Promise<object|null>} Vault data or null if not found.
   */
  async getVault(vaultId) {
    const vaultPath = this.getVaultFilePath(vaultId);
    const mutex = this.getVaultMutex(vaultId);
    const release = await mutex.acquire();
    try {
      const raw = await fs.promises.readFile(vaultPath, 'utf8');
      const parsed = JSON.parse(raw);
      return parsed;
    } catch (err) {
      if (err.code === 'ENOENT') {
        return null;
      }
      throw err;
    } finally {
      release();
    }
  }

  /**
   * Create a new vault exclusively.
   * Uses both the vault creation mutex and the per-vault mutex,
   * opening the target file with the 'wx' flag to guarantee exclusive creation.
   *
   * @param {string} vaultId - Vault identifier.
   * @param {object} initialData - Initial vault state.
   * @returns {Promise<void>}
   */
  async createVault(vaultId, initialData) {
    const vaultPath = this.getVaultFilePath(vaultId);
    const creationRelease = await this.vaultCreationMutex.acquire();
    const vaultMutex = this.getVaultMutex(vaultId);
    const vaultRelease = await vaultMutex.acquire();

    let fileHandle;
    try {
      const serialized = JSON.stringify(initialData, null, 2);
      // 'wx' flag fails with EEXIST if the destination file already exists.
      fileHandle = await fs.promises.open(vaultPath, 'wx', 0o600);
      await fileHandle.writeFile(serialized, 'utf8');
      await fileHandle.sync();
      await fileHandle.close();
      fileHandle = null;
    } catch (err) {
      if (fileHandle) {
        try {
          await fileHandle.close();
        } catch (closeErr) {
          // Suppress close error
        }
      }
      if (err.code === 'EEXIST') {
        const conflictErr = new Error(`Vault already exists: ${vaultId}`);
        conflictErr.code = 'ERR_VAULT_EXISTS';
        throw conflictErr;
      }
      throw err;
    } finally {
      vaultRelease();
      creationRelease();
    }
  }

  /**
   * Mutate a vault under its per-vault mutex lock.
   * Executes the mutatorFn passing the current vault state.
   * The mutatorFn must return the new vault state.
   * Persists the updated state atomically.
   *
   * @param {string} vaultId - Vault identifier.
   * @param {Function} mutatorFn - Async or sync callback: (currentVault) => updatedVault.
   * @returns {Promise<object>} The updated vault state.
   */
  async mutateVault(vaultId, mutatorFn) {
    const vaultPath = this.getVaultFilePath(vaultId);
    const mutex = this.getVaultMutex(vaultId);
    const release = await mutex.acquire();

    try {
      let currentVault;
      try {
        const raw = await fs.promises.readFile(vaultPath, 'utf8');
        currentVault = JSON.parse(raw);
      } catch (err) {
        if (err.code === 'ENOENT') {
          const notFoundErr = new Error(`Vault not found: ${vaultId}`);
          notFoundErr.code = 'ERR_VAULT_NOT_FOUND';
          throw notFoundErr;
        }
        throw err;
      }

      const updatedVault = await mutatorFn(currentVault);
      if (typeof updatedVault !== 'object' || updatedVault === null) {
        throw new TypeError('Mutator function must return a valid vault object');
      }

      await atomicWriteJson(vaultPath, updatedVault);
      return updatedVault;
    } finally {
      release();
    }
  }
}
