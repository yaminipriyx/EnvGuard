# EnvGuard Architectural Design & Threat Model (Phase 0)

## 1. System Overview

EnvGuard is a zero-knowledge command-line interface (CLI) and centralized vault system designed to eliminate plaintext `.env` files from developer workstations, source control repositories, and shared storage environments.

Traditional secret management often relies on local `.env` files that risk accidental commits to version control, leakage via unencrypted backups, or unauthorized access by malicious local processes. EnvGuard addresses these vulnerabilities by storing encrypted environment secrets on a centralized Vault Server and decrypting them strictly in volatile memory at runtime.

### 1.1 Core Components

1. **EnvGuard CLI (`envguard`)**:
   - A Node.js CLI client executed locally by developers (requires Node.js 18.0.0+).
   - Manages developer cryptographic identities using native X25519 asymmetric keys represented as JSON Web Keys (JWK).
   - Generates and stores raw API authentication tokens locally in `~/.envguard/credentials.json`.
   - Authenticates requests to the Vault Server using HMAC-SHA512 request signing with keys derived via `crypto.hkdfSync`.
   - Encrypts and decrypts secret payloads locally in volatile memory using AES-256-GCM with explicit Additional Authenticated Data (AAD).
   - Injects decrypted secrets directly into child process environments via `child_process.spawn` without touching disk storage.
   - Enforces recipient public-key fingerprint verification and Trust-On-First-Use (TOFU) key pinning to prevent server-side public-key substitution.

2. **EnvGuard Vault Server**:
   - A centralized HTTP service built with Node.js built-in HTTPS/HTTP primitives.
   - Operates behind TLS (HTTPS strictly enforced for non-loopback traffic).
   - Acts as an authenticated, blind storage orchestrator.
   - Stores global user authentication verifiers in `users.json` and atomic per-environment vault states in `vaults/<vaultId>.json`.
   - Enforces optimistic concurrency control on all mutable vault transactions (`set`, `grant`, `revoke`) using a monotonic `vaultVersion` counter protected by an in-process asynchronous mutex.
   - Tracks DEK generations separately via `dekVersion`, incrementing it only when actual DEK rotation occurs (`revoke`).
   - Stores only derived authentication verifiers (`authVerifier`), never raw user API tokens.
   - **Oblivious Storage Guarantee**: Operates entirely over ciphertext and public keys. Under the stated cryptographic assumptions, compromise of the Vault Server's stored data does not provide the private keys or unwrapped DEKs required to decrypt existing secret payloads.

### 1.2 High-Level CLI Workflows

- **`envguard init`**:
  Initializes developer identity. Enforces a minimum 12-character master passphrase. In volatile memory, derives a 256-bit key encryption key (KEK) via PBKDF2-HMAC-SHA256, generates an asymmetric X25519 keypair in JWK format, and generates a raw 32-byte API token $T$ with a 16-byte user salt. Derives $K_{sign}$ via `crypto.hkdfSync`. Registers with the server using an enrollment bootstrap key (`--enrollment-key`), sending only the public key, salt, and $K_{sign}$ (`authVerifier`). Upon server registration confirmation, writes `~/.envguard/key.enc` and `~/.envguard/credentials.json` (memory-first, atomic write pattern).

- **`envguard set [KEY[=VALUE]] [--stdin] [--env <name>]`**:
  Sets or updates secrets for a specific project environment:
  - **Input Modes**:
    - `envguard set KEY`: Secure interactive prompt with hidden terminal input (no echo), preventing shell history leakage.
    - `envguard set --stdin`: Reads key-value pairs from standard input (pipe or heredoc).
    - `envguard set KEY=VALUE`: Inline argument form supported for automation; displays a security warning regarding shell history and process table exposure.
  - **Variable Validation**: Variable names are validated against `^[A-Za-z_][A-Za-z0-9_]*$`.
  - **Initial `set` (Vault does not exist)**: Authenticated caller becomes the vault owner. Generates a unique `vaultId` formatted as `<project>-<environment>-<random16Hex>`. Generates initial random 256-bit DEK, canonicalizes secrets into a JSON map, encrypts the payload using AES-256-GCM with AAD `${vaultId}:1`, wraps the DEK for the owner with AAD `${vaultId}:1:${ownerUsername}`, and atomically creates the vault state on the server with `vaultVersion = 1` and `dekVersion = 1`.
  - **Subsequent `set` (Vault exists)**: Caller must have `owner`, `admin`, or `member` role. CLI fetches vault state, unwraps existing DEK (verifying AES-GCM via `decipher.final()`), decrypts existing secrets in memory, merges updates, and re-encrypts the complete payload using the **existing DEK** with AAD `${vaultId}:${currentDekVersion}`. The DEK is **not** rotated (`dekVersion` unchanged). Submits update to `PUT /api/v1/vault/:vaultId/secrets` with `expectedVersion` matching `vaultVersion`. Server increments `vaultVersion`.

- **`envguard run [--env <name>] -- <command>`**:
  Executes a command with secrets injected into runtime memory. Resolves the target environment vault, authenticates with the server, fetches the encrypted secret blob and user's wrapped DEK, prompts for master passphrase, decrypts private key in memory (verifying key integrity), unwraps DEK using X25519 ECDH + HKDF-SHA512 + AES-256-GCM (verifying AAD and `decipher.final()`), decrypts secrets blob (verifying AAD and `decipher.final()`), parses JSON secret map, and spawns `<command>` with injected environment variables (`shell: false`). Safely resolves `.cmd`/`.bat` extensions on Windows.

- **`envguard grant <username> [--role <role>] [--fingerprint <fp>] [--env <name>]`**:
  Grants environment access to a teammate:
  - Authorization: `owner` can grant `admin`, `member`, `readonly`. `admin` can grant `member`, `readonly` only (**admin cannot grant another admin**).
  - Public-Key Verification: Fetches target user's public key. Displays fingerprint (`SHA256:...`) for interactive confirmation or verifies against `--fingerprint <fp>`. Verifies against locally pinned keys in `~/.envguard/known_keys.json` (TOFU). If a pinned key changed, aborts immediately.
  - Unwraps current DEK, wraps it for the target user using their verified public key and AAD `${vaultId}:${currentDekVersion}:${targetUsername}`, and submits `POST /api/v1/vault/:vaultId/members` with `expectedVersion`. Server increments `vaultVersion`; `dekVersion` remains unchanged.

- **`envguard revoke <username> [--env <name>]`**:
  Revokes environment access from a teammate:
  - Authorization: `owner` can revoke any non-owner (`admin`, `member`, `readonly`). `admin` can revoke `member` or `readonly` only (cannot revoke `owner` or another `admin`).
  - Mandatory DEK Rotation: Unwraps current DEK, decrypts current secrets, generates fresh DEK ($DEK_{new}$), re-encrypts secrets with AAD `${vaultId}:${newDekVersion}`, re-wraps $DEK_{new}$ for remaining authorized members using their pinned public keys, and submits `DELETE /api/v1/vault/:vaultId/members/:username` with `expectedVersion`. Server increments `vaultVersion` and increments `dekVersion`.

---

## 2. Threat Model

The security boundaries and adversarial capabilities for EnvGuard are formalized below.

### 2.1 Threat Actors and Scenarios

#### Scenario A: Malicious or Compromised Vault Server
- **Adversary Capability**: Full root access to the Vault Server host, OS memory, and filesystem (`users.json`, `vaults/<vaultId>.json`). Can inspect stored files, read HTTP requests, alter responses, or attempt unauthorized decryption.
- **Server Visibility**:
  - Encrypted secret blobs (ciphertext, IV, tag, AAD).
  - Wrapped DEKs (ephemeral public keys, IV, tag, encrypted DEK, AAD).
  - User public keys and usernames.
  - Request metadata (IP addresses, timestamps).
  - Stored authentication verifiers (`authVerifier`, derived signing key $K_{sign}$).
- **Security Boundaries and Guarantees**:
  - **Secret Confidentiality**: Compromise of stored server data does not provide developer private keys, unwrapped DEKs, master passphrases, or plaintext secrets. Existing ciphertexts cannot be decrypted by the server.
  - **Authentication vs. Confidentiality**: Storing derived signing verifiers ($K_{sign}$) means server compromise may allow an adversary to forge HMAC signatures and impersonate users at the API layer. However, server compromise alone does **not** provide private keys required to unwrap DEKs.
  - **Active Public-Key Substitution**: A compromised server attempting to substitute an attacker's public key during `grant` or `revoke` is thwarted by client-side recipient fingerprint verification, manual confirmation prompts, `--fingerprint` enforcement, and TOFU key pinning (`known_keys.json`). **The client is protected against an actively malicious server substituting public keys if and only if the recipient public key has been verified or pinned.**

#### Scenario B: Disk Compromise of Developer Workstation
- **Adversary Capability**: Read access to `~/.envguard/key.enc`.
- **Protection**: Long-term X25519 private key is encrypted with PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt) and AES-256-GCM (12-byte IV, 16-byte tag). Passphrase minimum length is 12 characters. Without the passphrase, offline brute force is heavily rate-limited by PBKDF2 computational cost. Tampering fails AES-GCM authentication immediately.

#### Scenario C: Network Attacker / Passive Sniffer
- **Adversary Capability**: Intercepts or records network traffic between CLI and server.
- **Protection**:
  - **Transport Layer**: TLS (HTTPS) provides transport encryption and server authentication. (`https://` is mandatory for non-loopback endpoints).
  - **Application Layer**: HMAC-SHA512 request signing authenticates the user, ensures payload integrity, and prevents replay attacks via timestamps (5-minute window) and single-use nonces.
  - **Payload Confidentiality**: Plaintext secrets and private keys are never transmitted over the network.

#### Scenario D: Revoked Teammate
- **Adversary Capability**: Possesses their own private key, past unwrapped DEKs, and previously fetched secrets.
- **Protection**: Revocation triggers mandatory DEK rotation ($DEK_{new}$), re-encryption of secrets with incremented `dekVersion`, and re-wrapping exclusively for remaining authorized members. The revoked user cannot unwrap $DEK_{new}$ because no wrapped copy exists for their key.
- **Explicit Limitation**: Revocation cannot retroactively erase secrets that the user already retrieved or copied prior to revocation. External credentials must be rotated operationally.

#### Scenario E: Unauthorized User and Environment Cross-Access
- **Protection**: Each environment (`development`, `staging`, `production`) uses an independent `vaultId` with an independent DEK lifecycle. Server ACL enforcers reject requests without required roles. Cryptographically, DEKs are wrapped only for authorized public keys. Access to `development` grants zero cryptographic ability to decrypt `production`.

#### Scenario F: Local Attacker / OS Process Inspection
- **Adversary Capability**: A local user or process with operating system permissions to inspect running processes, memory, or environment tables.
- **Security Reality**: When `envguard run` spawns a child process:
  - The child process receives secrets via `process.env`.
  - Descendant processes inherit these environment variables.
  - While the process runs, OS debugging APIs or Linux `/proc/<pid>/environ` may expose environment variables to permitted local users or `root`/`SYSTEM`.
- **Explicit Guarantee**: EnvGuard eliminates intentional plaintext persistence to disk (`.env` files); it does **not** protect secrets from a local attacker possessing operating-system privileges to inspect running processes or memory.

#### Scenario G: Rollback Limitation within Same DEK Generation
- **Limitation**: AAD binds the secret blob to `vaultId` and `dekVersion`. However, AAD binding does **not** completely prevent an active server attacker from rolling back a vault to an earlier valid state within the same `dekVersion` (e.g. reverting a secret update back to version 2 from version 3). Completely eliminating rollback attacks requires client-side state tracking or a trusted monotonic counter.

---

## 3. Cryptographic Responsibilities

EnvGuard relies exclusively on Node.js native `crypto` module primitives (Node.js 18.0.0+ required).

| Primitive | Purpose | Input | Output | Where It Is Used & Invariants |
| :--- | :--- | :--- | :--- | :--- |
| **AES-256-GCM** | Authenticated symmetric encryption of secrets, wrapped DEKs, and local private keys | - 256-bit Key (`key`)<br>- 96-bit IV (`iv`)<br>- Plaintext Buffer<br>- Canonical AAD Buffer | - Ciphertext Buffer<br>- 128-bit Auth Tag (`tag`) | 1. Encrypting secret payload with DEK (AAD: `${vaultId}:${dekVersion}`).<br>2. Wrapping DEK with derived KEK (AAD: `${vaultId}:${dekVersion}:${recipientUsername}`).<br>3. Encrypting private key in `~/.envguard/key.enc`.<br><br>**Security Invariant**: AES-256-GCM authentication must successfully complete via `decipher.final()` before decrypted plaintext is trusted, parsed, processed, exposed, or returned. Plaintext from `decipher.update()` must never be used prior to `decipher.final()`. |
| **X25519 / ECDH** | Asymmetric key agreement producing shared secret | - Sender Private `KeyObject`<br>- Recipient Public `KeyObject` | - 32-byte raw shared secret (`sharedSecret`) | 1. DEK wrapping (ephemeral private + recipient public).<br>2. DEK unwrapping (recipient private + ephemeral public).<br><br>**Validation**: Rejects all-zero shared secrets (`Buffer.alloc(32, 0)`). |
| **HKDF-SHA512** | Key derivation with strict domain separation | - Digest: `"sha512"`<br>- IKM: 32-byte shared secret or API token<br>- Salt: Empty buffer or 16-byte user salt<br>- Info: Domain string<br>- Keylen: 32 or 64 bytes | - Derived Key Buffer | Implemented strictly via: `Buffer.from(crypto.hkdfSync(digest, ikm, salt, info, keylen))`.<br><br>1. `envguard-dek-wrap-v1` (32 bytes, salt: `Buffer.alloc(0)`).<br>2. `envguard-client-signing-v1` (64 bytes, salt: 16-byte random user salt). |
| **PBKDF2-HMAC-SHA256** | Password-based KEK derivation | - Passphrase (min 12 chars)<br>- Salt (16-byte random buffer)<br>- Iterations: 600,000<br>- Key length: 32 bytes<br>- Digest: `"sha256"` | - 32-byte KEK Buffer | Protecting `~/.envguard/key.enc` at rest. |
| **HMAC-SHA512** | Request authentication and payload integrity | - Signing Key ($K_{sign}$, 64 bytes)<br>- Canonical request string | - 64-byte HMAC signature (hex-encoded) | Authenticating client HTTP requests. Verified via `crypto.timingSafeEqual` after length validation. |

### 3.1 Node.js X25519 Key Representation

To ensure strict interoperability with Node.js `KeyObject` APIs, X25519 keys are formatted as JSON Web Keys (JWK):

- **Public Key JWK**:
  ```json
  {
    "kty": "OKP",
    "crv": "X25519",
    "x": "<base64url-encoded-32-byte-public-key>"
  }
  ```
- **Private Key JWK** (unwrapped in memory):
  ```json
  {
    "kty": "OKP",
    "crv": "X25519",
    "x": "<base64url-encoded-32-byte-public-key>",
    "d": "<base64url-encoded-32-byte-private-key>"
  }
  ```
- **Conversion to KeyObject**:
  - `crypto.createPublicKey({ key: jwkObject, format: 'jwk' })`
  - `crypto.createPrivateKey({ key: jwkObject, format: 'jwk' })`
- **Private Key Integrity Check**:
  Upon decrypting `~/.envguard/key.enc`, the CLI derives the public key from the private key and verifies it matches the stored `publicKey` before proceeding.

---

## 4. Exact Data Formats

### 4.1 Local Encrypted Key File (`~/.envguard/key.enc`)

Location: `~/.envguard/key.enc` (POSIX mode `0600`; on Windows, protected by user ACL).

```json
{
  "version": 1,
  "createdAt": "2026-09-19T10:00:00.000Z",
  "publicKey": {
    "kty": "OKP",
    "crv": "X25519",
    "x": "3p9XoqpxbmgqwSqtWzg5VSDppE1plEL8y0zO2bZ_V0U"
  },
  "publicKeyHex": "de9f57a2aa716e682ac12aad5b38395520e9a44d699442fccb4cced9b67f5745",
  "kdf": {
    "algorithm": "pbkdf2",
    "digest": "sha256",
    "iterations": 600000,
    "salt": "a1b2c3d4e5f60718293a4b5c6d7e8f90"
  },
  "cipher": {
    "algorithm": "aes-256-gcm",
    "iv": "0102030405060708090a0b0c",
    "tag": "1112131415161718191a1b1c1d1e1f20",
    "ciphertext": "a9b8c7d6..."
  }
}
```

### 4.2 Local Client Credentials (`~/.envguard/credentials.json`)

Location: `~/.envguard/credentials.json` (POSIX mode `0600`).

```json
{
  "version": 1,
  "username": "alice",
  "apiToken": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "userSalt": "f0e1d2c3b4a5968778695a4b3c2d1e0f"
}
```

### 4.3 Local Known Keys Cache (`~/.envguard/known_keys.json`)

Stores pinned recipient public-key fingerprints for Trust-On-First-Use (TOFU) validation.

```json
{
  "version": 1,
  "pinnedKeys": {
    "bob": {
      "fingerprint": "SHA256:7b5d92a1c4e8f0b3e6d9a2c5b8e1f4a7d0c3e6b9a2c5d8e1f4a7b0c3e6d9a2c5",
      "publicKeyHex": "3f9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f",
      "pinnedAt": "2026-09-19T11:00:00.000Z"
    }
  }
}
```

### 4.4 Encrypted Secrets Blob

```json
{
  "algorithm": "aes-256-gcm",
  "dekVersion": 1,
  "iv": "0a1b2c3d4e5f6a7b8c9d0e1f",
  "tag": "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
  "ciphertext": "8f9e0a1b2c3d4e5f...",
  "aad": "my-app-development-a7f3c92b8e14d056:1"
}
```

*Canonical Plaintext Format*: Serialized UTF-8 JSON object of validated variable strings:
`{"API_KEY":"secret123","DATABASE_URL":"postgres://..."}`.

### 4.5 Wrapped DEK Object

```json
{
  "algorithm": "aes-256-gcm",
  "kdf": {
    "algorithm": "hkdf-sha512",
    "info": "envguard-dek-wrap-v1"
  },
  "ephemeralPublicKey": {
    "kty": "OKP",
    "crv": "X25519",
    "x": "4q-XoqqxbmgqwSqtWzg5VSDppE1plEL8y0zO2bZ_V0U"
  },
  "ephemeralPublicKeyHex": "e2af97a2aa716e682ac12aad5b38395520e9a44d699442fccb4cced9b67f5745",
  "iv": "1a2b3c4d5e6f7a8b9c0d1e2f",
  "tag": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
  "encryptedDek": "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
  "aad": "my-app-development-a7f3c92b8e14d056:1:alice"
}
```

### 4.6 Server Storage Formats

#### 1. Global Users Store (`users.json`)
```json
{
  "alice": {
    "username": "alice",
    "publicKey": {
      "kty": "OKP",
      "crv": "X25519",
      "x": "3p9XoqpxbmgqwSqtWzg5VSDppE1plEL8y0zO2bZ_V0U"
    },
    "publicKeyHex": "de9f57a2aa716e682ac12aad5b38395520e9a44d699442fccb4cced9b67f5745",
    "publicKeyFingerprint": "SHA256:7b5d92a1c4e8f0b3e6d9a2c5b8e1f4a7d0c3e6b9a2c5d8e1f4a7b0c3e6d9a2c5",
    "authVerifier": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
    "salt": "f0e1d2c3b4a5968778695a4b3c2d1e0f",
    "createdAt": "2026-09-19T10:00:00.000Z",
    "status": "active"
  }
}
```

#### 2. Atomic Per-Vault State (`vaults/<vaultId>.json`)
Path: `vaults/my-app-development-a7f3c92b8e14d056.json`.
```json
{
  "vaultId": "my-app-development-a7f3c92b8e14d056",
  "vaultVersion": 1,
  "dekVersion": 1,
  "updatedAt": "2026-09-19T10:00:00.000Z",
  "owner": "alice",
  "members": {
    "alice": "owner",
    "bob": "member"
  },
  "blob": {
    "algorithm": "aes-256-gcm",
    "dekVersion": 1,
    "iv": "0a1b2c3d4e5f6a7b8c9d0e1f",
    "tag": "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
    "ciphertext": "8f9e0a1b2c3d4e5f...",
    "aad": "my-app-development-a7f3c92b8e14d056:1"
  },
  "wrappedDeks": {
    "alice": {
      "algorithm": "aes-256-gcm",
      "kdf": { "algorithm": "hkdf-sha512", "info": "envguard-dek-wrap-v1" },
      "ephemeralPublicKey": { "kty": "OKP", "crv": "X25519", "x": "4q-XoqqxbmgqwSqtWzg5VSDppE1plEL8y0zO2bZ_V0U" },
      "ephemeralPublicKeyHex": "e2af97a2aa716e682ac12aad5b38395520e9a44d699442fccb4cced9b67f5745",
      "iv": "1a2b3c4d5e6f7a8b9c0d1e2f",
      "tag": "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
      "encryptedDek": "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
      "aad": "my-app-development-a7f3c92b8e14d056:1:alice"
    }
  }
}
```

---

## 5. Server Authentication & Request Protocol

### 5.1 Client-Driven Token Issuance Architecture

1. **Client Key Generation**: During `envguard init`, the client generates in memory:
   - 32-byte cryptographically secure random API token $T$.
   - 16-byte random user salt.
2. **Client Derivation**:
   $$K_{sign} = \text{Buffer.from(crypto.hkdfSync('sha512', T, userSalt, 'envguard-client-signing-v1', 64))}$$
3. **Registration Request**:
   Client submits `POST /api/v1/auth/register` with:
   `{ "username": "alice", "publicKey": {...}, "salt": "...", "authVerifier": "<hex-encoded K_sign>", "enrollmentKey": "..." }`.
4. **Server Storage**: Server stores `authVerifier` ($K_{sign}$), `salt`, and `publicKey` in `users.json`. **The server never receives or stores the raw API token $T$.**
5. **Local Persistence**: Client writes $T$ and `userSalt` to `~/.envguard/credentials.json`.

### 5.2 Canonical Request String & Signing

- **Query Parameters**: Query parameters are **strictly forbidden** on authenticated routes. Requests with query strings are rejected with HTTP 400 Bad Request.
- **Canonical String Format**:
  ```text
  CANONICAL_STRING = HTTP_METHOD + "\n" +
                     CANONICAL_PATH + "\n" +
                     TIMESTAMP + "\n" +
                     NONCE + "\n" +
                     BODY_HASH
  ```
- **Components**:
  - `HTTP_METHOD`: Uppercase string (`GET`, `PUT`, `POST`, `DELETE`).
  - `CANONICAL_PATH`: Normalized pathname (e.g. `/api/v1/vault/my-app-dev-a7f3/secrets`).
  - `TIMESTAMP`: ISO 8601 UTC string (e.g. `2026-09-19T10:00:00.000Z`).
  - `NONCE`: 16-byte cryptographically random hex string.
  - `BODY_HASH`: SHA-512 hex digest of raw request body (for empty bodies, SHA-512 of `""`).
- **Signature**:
  $$\text{SIGNATURE} = \text{crypto.createHmac('sha512', } K_{sign}\text{).update(CANONICAL\_STRING).digest('hex')}$$

### 5.3 Server-Side Request Verification Pipeline

When a request arrives, the server executes these explicit verification steps in order:

```text
[Incoming HTTP Request]
         |
         v
(1) Header Validation: Check X-EnvGuard-User, Timestamp, Nonce, Signature
    - Reject if missing or headers exceed 256 bytes -> 400 Bad Request
         |
         v
(2) Timestamp Freshness Window:
    - Compute delta = |server.now - request.timestamp|
    - Reject if delta > 300 seconds -> 401 Unauthorized
         |
         v
(3) User Lookup & Timing-Safe Verification Path:
    - Lookup username in users.json.
    - If user not found or inactive:
      Substitute dummyVerifier and compute dummy signature to prevent user enumeration.
      Reject -> 401 Unauthorized
         |
         v
(4) HMAC Signature Verification:
    - Recompute BODY_HASH = SHA512(rawRequestBody).
    - Construct server CANONICAL_STRING.
    - Compute expectedSignature = HMAC-SHA512(storedVerifier, CANONICAL_STRING).
    - If signatureBuffer.length !== expectedBuffer.length || !timingSafeEqual(sig, expected):
      Reject -> 401 Unauthorized
         |
         v
(5) Nonce Cache Check (Committed ONLY after valid signature):
    - Key = `${username}:${nonce}`.
    - If key in nonceCache: Reject -> 401 Unauthorized (Replay Attack)
    - Else: nonceCache.set(key, expiresAt = server.now + 600s)
         |
         v
(6) Route Authorization & Mutex Handling -> Proceed
```

*Replay Limitation Notice*: The in-memory nonce cache is cleared on server restart. Replay protection for requests within the 5-minute window is not preserved across a server reboot unless backed by persistent replay state.

---

## 6. TLS & Network Architecture

### 6.1 Unified Network Architecture

1. **Production Deployment**:
   - The Vault Server runs natively with TLS using `https.createServer` (or alternatively runs behind a dedicated TLS-terminating reverse proxy such as Nginx or AWS ALB).
   - In both cases, the external interface accessed by the CLI client is strictly HTTPS.
2. **Local Demo / Development Deployment**:
   - The server provides a self-signed TLS certificate for testing.
   - The CLI client supports configuring trust for the demo CA via the `ENVGUARD_CA_CERT` environment variable or `--ca-cert <path>` CLI flag (or standard `NODE_EXTRA_CA_CERTS`).
3. **Client URL Enforcement Policy**:
   - `https://` is **strictly required** for all non-loopback server URLs.
   - `http://` is permitted **only** for explicitly identified loopback endpoints (`http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`).
   - The CLI client will actively abort with an error if a non-loopback `http://` URL is configured or passed.

---

## 7. Project Model & Vault Identification

### 7.1 Schema for `.envguard.json`

Located at repository root, committed to version control. To prevent namespace squatting, vault IDs include a 16-character random hex component.

```json
{
  "version": 1,
  "project": "my-app",
  "serverUrl": "https://vault.internal:8443",
  "environments": {
    "development": "my-app-development-a7f3c92b8e14d056",
    "staging": "my-app-staging-b8e4d01c9f25e167",
    "production": "my-app-production-c9f5e12da036f278"
  }
}
```

### 7.2 Resolution Priority

1. **Active Environment**: `--env <name>` flag $\rightarrow$ `ENVGUARD_ENV` env var $\rightarrow$ default `"development"`.
2. **Server URL**: `--server <url>` flag $\rightarrow$ `ENVGUARD_SERVER` env var $\rightarrow$ `serverUrl` in `.envguard.json` $\rightarrow$ fallback `http://localhost:3000`.

---

## 8. DEK Lifecycle, Authorization, and Concurrency Control

### 8.1 Distinct Counters: `vaultVersion` vs `dekVersion`

- **`vaultVersion`**: Monotonically increasing state version for optimistic concurrency control. Increments on **every successful vault mutation** (`set`, `grant`, `revoke`).
- **`dekVersion`**: Identifies the generation of the active Data Encryption Key. Increments **only when the DEK changes**:
  - Initial creation: `dekVersion = 1`.
  - Normal `set`: `dekVersion` remains unchanged.
  - `grant`: `dekVersion` remains unchanged.
  - `revoke`: $DEK_{new}$ is generated; `dekVersion` increments (`dekVersion + 1`).

### 8.2 ACL Roles and Authorization Matrix

| Role | Read Secrets (`run`) | Update Secrets (`set`) | Grant Access (`grant`) | Revoke Access (`revoke`) | Constraints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`owner`** | Yes | Yes | Can grant `admin`, `member`, `readonly` | Can revoke `admin`, `member`, `readonly` | Vault creator. Cannot be revoked by any member. |
| **`admin`** | Yes | Yes | Can grant `member`, `readonly` only | Can revoke `member`, `readonly` only | **Cannot grant `admin`**. Cannot revoke `owner` or another `admin`. |
| **`member`** | Yes | Yes | No | No | Standard developer. Cannot grant or revoke. |
| **`readonly`** | Yes | No | No | No | Automated runners. **Enforced logically by server authorization** (has DEK, but server rejects mutation API calls). |

### 8.3 Server-Side Concurrency & In-Process Mutex

To prevent lost updates and race conditions during concurrent mutations:
1. **Per-Vault Asynchronous Mutex**: The server maintains an in-memory lock keyed by `vaultId`. All mutation operations (`PUT /secrets`, `POST /members`, `DELETE /members`) must acquire `lock(vaultId)` before executing:
   - Read current state from `vaults/<vaultId>.json`.
   - Validate `request.expectedVersion === currentVault.vaultVersion`.
   - If mismatched, release lock and return `HTTP 409 Conflict`.
   - Apply mutation. Increment `vaultVersion = currentVault.vaultVersion + 1`.
   - Write updated state to a unique temporary file: `vaults/<vaultId>.<uuid>.tmp`.
   - Flush and sync to storage via `filehandle.sync()`. Close file.
   - Atomically replace via `fs.promises.rename('vaults/<vaultId>.<uuid>.tmp', 'vaults/<vaultId>.json')`.
   - Release `lock(vaultId)`.
2. **Exclusive Vault Creation**: Vault creation acquires a global creation lock, verifies that `vaults/<vaultId>.json` does not exist, and atomically writes the initial file.
3. **Multi-Process Scope**: In-process mutexes protect a single Node.js process. Clustered deployments require distributed locking (e.g. Redis Redlock or database transactions).

### 8.4 Dedicated API Mutation Endpoints

The server exposes dedicated endpoints with independent schemas and authorization validators:

| Method & Route | Required Role | Request Body Schema | Effect & Invariants |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/vault/:vaultId/secrets` | `owner`, `admin`, `member`, `readonly` | None | Returns `{ vaultVersion, dekVersion, blob, wrappedDeks }`. |
| `PUT /api/v1/vault/:vaultId/secrets` | `owner`, `admin`, `member` | `{ "expectedVersion": N, "blob": EncryptedSecretsBlob }` | Updates secret blob only. `members` and `wrappedDeks` cannot be altered. Increments `vaultVersion`. `dekVersion` unchanged. |
| `POST /api/v1/vault/:vaultId/members` | `owner`, `admin` | `{ "expectedVersion": N, "username": "bob", "role": "member", "wrappedDek": WrappedDek, "publicKeyFingerprint": "SHA256:..." }` | Adds member. Owner can grant admin/member/readonly; Admin can grant member/readonly only. Validates fingerprint against `users.json`. Increments `vaultVersion`. `dekVersion` unchanged. |
| `DELETE /api/v1/vault/:vaultId/members/:username` | `owner`, `admin` | `{ "expectedVersion": N, "newBlob": EncryptedSecretsBlob, "newWrappedDeks": { ... } }` | Revokes member. Admin cannot revoke owner/admin. Requires DEK rotation (`newBlob.dekVersion === currentDekVersion + 1`). Re-wraps solely for remaining members. Increments both `vaultVersion` and `dekVersion`. |

---

## 9. Trust Boundaries

### 9.1 Architectural Boundary Diagram

```text
+-------------------------------------------------------------------------+
| DEVELOPER WORKSTATION                                                   |
|                                                                         |
|  [ Developer Passphrase (min 12 chars) ]                                |
|           | (Entered via hidden TTY prompt)                             |
|           v                                                             |
|  +-------------------------------------------------------------------+  |
|  | VOLATILE RAM BOUNDARY (EnvGuard CLI Process)                      |  |
|  |  - Passphrase Buffer (zeroized via buffer.fill(0) after KDF)     |  |
|  |  - Unwrapped X25519 Private Key JWK (derived public key verified)|  |
|  |  - ECDH Shared Secrets (zero-check enforced, zeroized after use)  |  |
|  |  - Plaintext DEK Buffer (zeroized after cipher init)              |  |
|  |  - Decrypted Secrets Map (trusted ONLY after decipher.final())    |  |
|  |               |                                                   |  |
|  |               | Direct memory injection via spawn(shell: false)   |  |
|  |               v                                                   |  |
|  |  +-------------------------------------------------------------+  |  |
|  |  | Child Process (e.g., node app.js)                           |  |  |
|  |  |  - process.env receives injected variables                  |  |  |
|  |  +-------------------------------------------------------------+  |  |
|  +-------------------------------------------------------------------+  |
|           |                                                             |
|           v                                                             |
|  +-------------------------------------------------------------------+  |
|  | PERSISTENT DISK STORAGE                                           |  |
|  |  - ~/.envguard/key.enc (PBKDF2 + AES-GCM encrypted key bundle)    |  |
|  |  - ~/.envguard/credentials.json (Raw API token & salt, mode 0600) |  |
|  |  - ~/.envguard/known_keys.json (TOFU pinned public-key hashes)    |  |
|  |  - .envguard.json (Project vault IDs & server URL - public)       |  |
|  |  * NO INTENTIONAL PLAINTEXT SECRET WRITES BY APPLICATION          |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
                                    |
                                    | HTTPS TLS Transport (Mandatory for non-loopback)
                                    | + HMAC-SHA512 Request Authentication (No query params)
                                    v
+-------------------------------------------------------------------------+
| VAULT SERVER BOUNDARY                                                   |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Server Process (Node.js HTTPS Server)                             |  |
|  |  - Request HMAC & Timing-Safe User Validator                      |  |
|  |  - Nonce Cache Replay Guard (committed after signature check)     |  |
|  |  - In-Process Async Mutex per vaultId                             |  |
|  |  - Optimistic Concurrency Guard (vaultVersion match check)        |  |
|  |  - Route-Specific Authorization Enforcers                         |  |
|  +-------------------------------------------------------------------+  |
|           |                                                             |
|           v                                                             |
|  +-------------------------------------------------------------------+  |
|  | Server Storage (Blind Storage Filesystem)                         |  |
|  |  - users.json (Public keys, derived authVerifiers, salts)         |  |
|  |  - vaults/<vaultId>.json (Atomic state: blob, wrappedDeks, ACL,   |  |
|  |    vaultVersion, dekVersion)                                      |  |
|  |  * RAW API TOKENS NEVER STORED HERE                               |  |
|  |  * CANNOT READ OR DECRYPT STORED SECRETS                          |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
```

### 9.2 Boundary Classification Matrix

| Boundary Zone | Allowed in this Zone | Forbidden in this Zone |
| :--- | :--- | :--- |
| **Workstation RAM** | - Plaintext secrets<br>- Decrypted private keys<br>- Unwrapped DEKs<br>- Derived keys ($K_{wrap}$, $K_{sign}$)<br>- Child process environment variables | - Logging secrets to console or error streams<br>- Using decrypted plaintext before `decipher.final()` succeeds<br>- Retaining unzeroized sensitive buffers |
| **Workstation Disk** | - `~/.envguard/key.enc` (encrypted private key)<br>- `~/.envguard/credentials.json` (API token, mode `0600`)<br>- `~/.envguard/known_keys.json` (pinned keys)<br>- `.envguard.json` (project metadata) | - Plaintext `.env` files<br>- Unencrypted private keys<br>- Persistent application secret caches or debug dumps |
| **Network in Transit** | - Encrypted secrets blobs (ciphertext)<br>- Wrapped DEKs<br>- Public keys<br>- HMAC request signatures & nonces | - Plaintext secrets<br>- Unwrapped DEKs<br>- Private keys<br>- Master passphrases<br>- Non-TLS transmission to remote hosts |
| **Vault Server Host** | - Encrypted blobs<br>- Wrapped DEKs<br>- Public keys<br>- Derived signing verifiers ($K_{sign}$)<br>- Usernames and project metadata<br>- Request nonces & timestamps | - Plaintext secrets<br>- Unwrapped DEKs<br>- Developer private keys<br>- Raw API tokens<br>- Master passphrases |

---

## 10. Security Invariants

All future implementation phases must strictly adhere to the following non-negotiable security invariants:

1. **Plaintext Storage Invariant**: The application never intentionally writes plaintext secrets to persistent storage, temporary files, caches, logs, or other externally persistent locations. Operating-system memory paging/swapping is outside the application's direct control.
2. **Oblivious Storage Guarantee**: Under the stated cryptographic assumptions, compromise of the Vault Server's stored data does not provide developer private keys, unwrapped DEKs, master passphrases, or plaintext secrets. Server compromise may enable API-layer user impersonation via stored HMAC verifiers, but stored server data alone does not provide the cryptographic material required to decrypt existing vault secrets.
3. **Public-Key Verification Invariant**: The client is protected against an actively malicious server substituting public keys if and only if recipient public keys are verified via fingerprint display, interactive confirmation, `--fingerprint` CLI flags, and local TOFU key pinning (`known_keys.json`).
4. **No Raw API Tokens on Server**: The Vault Server must never receive or store raw user API tokens. Only derived verifiers ($K_{sign}$) and salts are persisted.
5. **Encrypted Private Keys at Rest**: Developer private keys must never exist unencrypted on disk. Private keys must be encrypted with PBKDF2-HMAC-SHA256 (600,000+ iterations) and AES-256-GCM. Passphrases must be at least 12 characters.
6. **Mandatory Authenticated Decryption**: AES-256-GCM authentication must successfully complete before any decrypted plaintext is trusted, parsed, processed, exposed, or returned. Successful authentication occurs only after `decipher.final()` succeeds. Plaintext produced by `decipher.update()` must never be used, parsed, or returned before `decipher.final()` completes successfully.
7. **Explicit AAD Binding**: All AES-256-GCM operations must bind canonical AAD:
   - Secret blob: `${vaultId}:${dekVersion}`
   - Wrapped DEK: `${vaultId}:${dekVersion}:${recipientUsername}`
8. **Rollback Limitation Invariant**: AAD binding does not prevent rollback to an earlier valid state within the same `dekVersion`. Preventing rollback within the same DEK generation requires client-side state or another trusted monotonic counter.
9. **Mandatory Request Authentication**: HMAC-SHA512 request signatures, timestamps, and nonces must be verified before processing request payloads. Query parameters are forbidden on authenticated routes.
10. **Zero-Logging Invariant**: Plaintext secrets, private keys, unwrapped DEKs, master passphrases, and raw API tokens must never be logged.
11. **DEK Lifecycle and Versioning Invariant**:
    - Initial creation: `vaultVersion = 1`, `dekVersion = 1`.
    - Normal `set`: reuses existing DEK; `vaultVersion` increments, `dekVersion` unchanged.
    - `grant`: wraps existing DEK; `vaultVersion` increments, `dekVersion` unchanged.
    - `revoke`: rotates DEK; `vaultVersion` increments, `dekVersion` increments.
12. **Role Permission Invariant**:
    - `owner` can grant `admin`, `member`, `readonly`; can revoke non-owners; non-revocable.
    - `admin` can grant `member`, `readonly` only (**cannot grant `admin`**); can revoke `member`, `readonly` only (cannot revoke `owner` or another `admin`).
    - `member` can read and update secrets; cannot grant or revoke.
    - `readonly` can read secrets only; cannot modify state, grant, or revoke.
13. **Atomic Vault State Invariant**: The Vault Server must maintain complete vault state in `vaults/<vaultId>.json` and perform updates atomically using an in-process mutex and write-and-rename file strategy.
14. **Optimistic Concurrency Invariant**: Every mutable vault operation must validate `expectedVersion === currentVault.vaultVersion` in the signed request body. Mismatched versions must fail with HTTP 409 Conflict.
15. **Environment Isolation Invariant**: Each deployment environment (`development`, `staging`, `production`) must have a distinct `vaultId` with an independent DEK lifecycle.
16. **No Shell Execution**: Child processes must be invoked using `child_process.spawn` with `shell: false`. Command shims on Windows (`.cmd`/`.bat`) must be resolved safely without enabling shell interpretation.
17. **Volatile Memory Hygiene**: Sensitive Buffer instances must be overwritten with `buffer.fill(0)` as soon as their immediate cryptographic purpose is complete.
18. **Cryptographic Independence**: Cryptographic modules (`src/crypto/*`) must be pure and self-contained, with zero dependencies on CLI routing, chalk, network clients, or filesystem utilities.
19. **Coding Style Rules**: All conditional execution must use explicit `if-else` statements. The ternary operator (`? :`) is strictly prohibited across the entire project codebase, including utilities, tests, and documentation.

---

## 11. Key-Loss Policy & Disaster Recovery

- **Consequences of Private Key Loss**:
  The Vault Server possesses neither developer private keys nor master passphrases. If a developer loses `~/.envguard/key.enc` or forgets their master passphrase, their private key is mathematically unrecoverable. Stored vault data cannot be recovered by the server.
- **Recovery Procedure**:
  1. The user runs `envguard init` to generate a new keypair and register a new username/identity.
  2. An existing authorized `owner` or `admin` of the project vault runs `envguard grant <newUsername>` to wrap the existing DEK for the new identity.
  3. **Sole Owner Loss**: If the sole owner loses their private key and no other authorized members exist, the project vault is **permanently unrecoverable**. Teams must maintain at least two authorized administrative keys for business-critical vaults.

---

## 12. Complete Server API Specification

Maximum allowed request body size: **1 MB (1,048,576 bytes)**. Requests exceeding this limit are rejected with HTTP 413 Payload Too Large.
Rate Limiting: 10 consecutive failed authentication attempts from an IP address or username triggers a 15-minute temporary lockout (HTTP 429 Too Many Requests).

| Route | Method | Auth Required | Required Role | Request Body | Success Response | Error Responses |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/auth/register` | `POST` | No (Enrollment Key) | Public | `{ username, publicKey, salt, authVerifier, enrollmentKey }` | `201 Created` | `400` (Bad format), `403` (Bad enrollment key), `409` (Username exists), `413` |
| `/api/v1/users/:username` | `GET` | Yes (HMAC) | Any active user | None | `200 OK` `{ username, publicKey, publicKeyHex, publicKeyFingerprint, status }` | `401` (Auth fail), `404` (Not found) |
| `/api/v1/vault` | `POST` | Yes (HMAC) | Authenticated user | `{ vaultId, blob, wrappedDek }` | `201 Created` `{ vaultId, vaultVersion: 1, dekVersion: 1 }` | `400` (Bad format), `401`, `409` (Vault ID exists), `413` |
| `/api/v1/vault/:vaultId/secrets` | `GET` | Yes (HMAC) | `owner`, `admin`, `member`, `readonly` | None | `200 OK` `{ vaultVersion, dekVersion, blob, wrappedDeks }` | `401`, `403` (Not member), `404` (Vault not found) |
| `/api/v1/vault/:vaultId/secrets` | `PUT` | Yes (HMAC) | `owner`, `admin`, `member` | `{ expectedVersion, blob }` | `200 OK` `{ vaultVersion, dekVersion }` | `400`, `401`, `403` (Readonly), `404`, `409` (Version conflict), `413` |
| `/api/v1/vault/:vaultId/members` | `POST` | Yes (HMAC) | `owner`, `admin` | `{ expectedVersion, username, role, wrappedDek, publicKeyFingerprint }` | `200 OK` `{ vaultVersion, dekVersion }` | `400`, `401`, `403` (Admin granting admin), `404`, `409` (Conflict), `413` |
| `/api/v1/vault/:vaultId/members/:username` | `DELETE` | Yes (HMAC) | `owner`, `admin` | `{ expectedVersion, newBlob, newWrappedDeks }` | `200 OK` `{ vaultVersion, dekVersion }` | `400`, `401`, `403` (Revoking owner/admin), `404`, `409` (Conflict), `413` |

---

## 13. Finalized Design Decisions & Rationale

All architectural questions for Phase 0 have been reviewed, corrected, and finalized.

### 1. Intentional Removal of Session ECDH Layer
- **Decision**: The dual-layer session ECDH protocol was intentionally removed.
- **Rationale**: Transport confidentiality is provided by standard TLS (HTTPS), and request integrity/authentication is provided by HMAC-SHA512. X25519 ECDH remains strictly utilized for DEK wrapping and unwrapping. Removing an application-level session encryption layer eliminates duplicate key exchanges, handshake overhead, and protocol complexity without reducing cryptographic strength.

### 2. Separation of `vaultVersion` and `dekVersion`
- **Decision**: Monotonic concurrency versioning (`vaultVersion`) is decoupled from cryptographic DEK generation tracking (`dekVersion`).
- **Rationale**: Normal secret updates (`set`) and membership additions (`grant`) update vault state without rotating the DEK. `vaultVersion` increments on every mutation, while `dekVersion` increments solely when the underlying DEK is rotated (`revoke`).

### 3. Public-Key Fingerprinting and TOFU Key Pinning
- **Decision**: Mandatory recipient public-key verification via fingerprint display, `--fingerprint` CLI flags, and local TOFU pinning (`~/.envguard/known_keys.json`).
- **Rationale**: Prevents an actively malicious or compromised server from substituting an attacker's public key during `grant` or `revoke` operations.

### 4. Native Node.js HKDF API
- **Decision**: Replaced all conceptual HKDF references with Node.js native `crypto.hkdfSync(digest, ikm, salt, info, keylen)`.
- **Rationale**: Node.js does not provide `crypto.createHkdf`. Using standard `crypto.hkdfSync` ensures direct compatibility with the native Node.js runtime.

### 5. Explicit AAD Cryptographic Binding
- **Decision**: Every AES-256-GCM cipher operation requires explicit canonical AAD:
  - Secret blob: `${vaultId}:${dekVersion}`
  - Wrapped DEK: `${vaultId}:${dekVersion}:${recipientUsername}`
- **Rationale**: Cryptographically binds encrypted payloads and wrapped keys to their specific vault, DEK generation, and intended recipient, preventing ciphertext substitution across vaults or accounts.
