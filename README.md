# EnvGuard

EnvGuard is a zero-knowledge CLI tool and centralized vault system designed to eliminate plaintext `.env` files from developer workstations, source control repositories, and shared storage environments.

By combining native asymmetric cryptography (X25519 ECDH), authenticated symmetric encryption (AES-256-GCM), and HMAC-SHA512 canonical request signing, EnvGuard ensures that secrets are encrypted locally on client workstations, stored as oblivious ciphertext on a centralized Vault Server, and decrypted strictly in volatile memory at runtime for direct injection into child processes.

---

## Key Capabilities

EnvGuard provides a complete set of command-line tools for developer secret management:

* **`envguard init [username]`**:
  Initializes a developer cryptographic identity. Prompts for a minimum 12-character master passphrase, derives a 256-bit Key Encryption Key (KEK) via PBKDF2-HMAC-SHA256 (600,000 iterations), generates an asymmetric X25519 keypair in JWK format, derives a 32-byte API token with a 16-byte user salt, registers the public identity with the Vault Server using an enrollment bootstrap key, and writes `key.enc` and `credentials.json` (mode `0600`) to `~/.envguard/`.

* **`envguard project init <name>`**:
  CLI command stub (reserved for project-level `.envguard.json` configuration scaffolding).

* **`envguard set [KEY[=VALUE]] [--stdin] [--env <name>]`**:
  Encrypts and stores environment secrets:
  * **Input Modes**: Supports secure interactive hidden prompt (no terminal echo), standard input piping (`--stdin`), or inline argument (`KEY=VALUE`).
  * **Initial Vault Creation**: Generates a fresh 256-bit Data Encryption Key (DEK), encrypts the canonical secret map with AES-256-GCM using AAD `${vaultId}:1`, wraps the DEK for the owner using AAD `${vaultId}:1:${ownerUsername}`, and atomically initializes the vault on the server (`vaultVersion: 1`, `dekVersion: 1`).
  * **Subsequent Updates**: Reuses the active DEK (`dekVersion` unchanged), unwraps the DEK in memory, decrypts current secrets, merges updates, re-encrypts with AAD `${vaultId}:${currentDekVersion}`, and submits an optimistic concurrency update with `expectedVersion`.

* **`envguard run [--env <name>] -- <command> [args...]`**:
  Fetches the encrypted vault state, prompts for the master passphrase, unlocks the private key, unwraps the DEK in volatile memory, decrypts the secret map, and executes `<command>` with secrets injected directly into `process.env` using Node.js `child_process.spawn` with `shell: false`. No `.env` file or plaintext secret touches disk storage.

* **`envguard grant <username> [--role <role>] [--fingerprint <fp>] [--env <name>]`**:
  Grants vault access to a teammate:
  * **Authorization**: Enforced server-side. `owner` can grant `admin`, `member`, or `readonly`. `admin` can grant `member` or `readonly` only (admins cannot grant `admin`).
  * **DEK Preservation**: The DEK is **not** rotated on grant (`dekVersion` unchanged, `vaultVersion` increments). The active DEK is locally unwrapped and re-wrapped for the target user using their registered public key and AAD `${vaultId}:${currentDekVersion}:${targetUsername}`.
  * **Verification**: Verifies the target user's registered public-key fingerprint against `--fingerprint <fp>` if supplied.

* **`envguard revoke <username> [--env <name>]`**:
  Revokes vault access from a teammate:
  * **Authorization**: Enforced server-side. `owner` can revoke any non-owner member. `admin` can revoke `member` or `readonly` (cannot revoke `owner` or another `admin`).
  * **Mandatory DEK Rotation**: Unwraps the active DEK, decrypts current secrets, generates a fresh random 32-byte DEK, increments `dekVersion`, re-encrypts the secret map with AAD `${vaultId}:${newDekVersion}`, re-wraps the new DEK for **all remaining authorized members** using their registered public keys, and atomically commits the state via `storage.mutateVault()`. The revoked user receives no new wrapped DEK.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           EnvGuard CLI Client                           │
│                                                                         │
│  ┌─────────────────────────┐           ┌─────────────────────────────┐  │
│  │   Local Cryptography    │           │    Identity & Keystore      │  │
│  │  ─────────────────────  │           │  ─────────────────────────  │  │
│  │  • AES-256-GCM          │           │  • ~/.envguard/key.enc      │  │
│  │  • X25519 ECDH (JWK)    │           │  • credentials.json         │  │
│  │  • HKDF-SHA512          │           │  • PBKDF2-HMAC-SHA256       │  │
│  │  • Sensitive buffer wiping          │  • Master Passphrase Prompt │  │
│  └────────────┬────────────┘           └──────────────┬──────────────┘  │
│               │                                       │                 │
│               └───────────────────┬───────────────────┘                 │
│                                   │                                     │
│                     ┌─────────────▼──────────────┐                      │
│                     │ HMAC-SHA512 Request Signer │                      │
│                     └─────────────┬──────────────┘                      │
└───────────────────────────────────┼─────────────────────────────────────┘
                                    │ HTTPS (TLS 1.3) / Canonical HMAC
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          EnvGuard Vault Server                          │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ Request Authentication & Replay Filter                            │  │
│  │ • Timestamp freshness check (±300s window)                         │  │
│  │ • Nonce replay prevention cache (${username}:${nonce})            │  │
│  │ • Timing-safe dummy verifier computation                          │  │
│  │ • Payload sanitization (rejects plaintext/raw DEK fields)         │  │
│  └─────────────────────────────────┬─────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │ Authoritative Access Control & Concurrency Engine                 │  │
│  │ • Per-vault asynchronous mutex lock                               │  │
│  │ • Optimistic Concurrency Control (expectedVersion checking)       │  │
│  │ • Server-side role enforcement (owner, admin, member, readonly)   │  │
│  │ • Monotonic vaultVersion & dekVersion tracking                    │  │
│  └─────────────────────────────────┬─────────────────────────────────┘  │
│                                    │                                     │
│  ┌─────────────────────────────────▼─────────────────────────────────┐  │
│  │ Blind Atomic Storage (server-data/)                               │  │
│  │ • users.json: User metadata and auth verifiers (never raw tokens) │  │
│  │ • vaults/<vaultId>.json: Encrypted blob & wrapped DEKs only       │  │
│  │ • Atomic temporary-file-rename writes                             │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

* **Oblivious Server**: The Vault Server operates strictly over ciphertext and public keys. Under stated cryptographic assumptions, server compromise does not provide the private keys or unwrapped DEKs necessary to decrypt secret payloads.
* **Client-Side Cryptography**: All encryption, decryption, DEK generation, and key wrapping operations occur exclusively within volatile memory on client workstations.
* **Server-Side ACL Authority**: Access control lists and version increments are strictly enforced and committed atomically by the server inside serialized mutex boundaries.

---

## Security Model

### 1. Symmetric Encryption
* **Cipher**: AES-256-GCM (`aes-256-gcm`).
* **Key Length**: 256 bits (32 bytes).
* **IV / Nonce**: 96 bits (12 bytes) generated via cryptographically secure random bytes (`crypto.randomBytes(12)`). IVs are never reused.
* **Authentication Tag**: 128 bits (16 bytes).
* **Additional Authenticated Data (AAD)**:
  * Secret Blobs: Canonical string `${vaultId}:${dekVersion}`.
  * Wrapped DEKs: Canonical string `${vaultId}:${dekVersion}:${recipientUsername}`.
  * Tampering with ciphertext, IV, tag, or AAD causes authenticated decryption to fail closed.

### 2. Asymmetric Key Agreement & DEK Wrapping
* **Algorithm**: Curve25519 (X25519) Diffie-Hellman in JSON Web Key (JWK) format (`kty: 'OKP'`, `crv: 'X25519'`).
* **Ephemeral Keypairs**: A fresh ephemeral X25519 keypair is generated for every DEK wrapping operation.
* **Key Derivation**: Ephemeral shared secret derived via ECDH is passed to HKDF-SHA512 (`salt: empty`, `info: 'envguard-dek-wrap-v1'`, length: 32 bytes) to produce the key wrapping key.
* **DEK Wrap**: The 32-byte DEK is encrypted with AES-256-GCM using the derived wrapping key and recipient-bound AAD.

### 3. Identity Key Derivation & Protection
* **Master Passphrase**: Enforced minimum of 12 characters.
* **Key Encryption Key (KEK)**: Derived via PBKDF2-HMAC-SHA256 using 600,000 iterations and a 16-byte random salt.
* **Key Envelope (`~/.envguard/key.enc`)**: The developer's private key JWK is serialized, encrypted with AES-256-GCM using the KEK, and written with file permissions `0600`.

### 4. API Request Authentication
* **Mechanism**: Canonical request signing using HMAC-SHA512.
* **Signing Key ($K_{sign}$)**: Derived on the client when needed via HKDF-SHA512 (`info: 'envguard-client-signing-v1'`, 64 bytes) from the raw 32-byte API token $T$ and user salt. The raw token is stored in `~/.envguard/credentials.json` (`0600`) and never transmitted over the network.
* **Canonical Request**: Formatted as `${METHOD}\n${PATH}\n${TIMESTAMP}\n${NONCE}\n${BODY_HASH}`.
* **Freshness & Replay**: Timestamp skew must be $\le 300$ seconds. Nonces are cached in memory as `${username}:${nonce}` for 300 seconds and rejected if replayed.

### 5. Role-Based Access Control (RBAC)

| Role | Read/Run Secrets | Modify Secrets (`set`) | Grant Roles | Revoke Roles |
| :--- | :---: | :---: | :---: | :---: |
| **Owner** | Yes | Yes | `admin`, `member`, `readonly` | Any non-owner member |
| **Admin** | Yes | Yes | `member`, `readonly` | `member`, `readonly` |
| **Member** | Yes | Yes | No | No |
| **Readonly** | Yes | No | No | No |
| **Revoked** | No | No | No | No |

* Admins cannot grant admin privileges.
* Admins cannot revoke the owner or another admin.
* The owner role is immutable and cannot be revoked or granted.

### 6. Cryptographic Revocation & DEK Rotation
1. Caller executes `envguard revoke <username>`.
2. Client unwraps active DEK ($DEK_{old}$) and decrypts secret map.
3. Sensitive buffer $DEK_{old}$ is wiped via `.fill(0)`.
4. Fresh random 32-byte DEK ($DEK_{new}$) is generated; `newDekVersion = oldDekVersion + 1`.
5. Secrets re-encrypted with $DEK_{new}$ and AAD `${vaultId}:${newDekVersion}`.
6. $DEK_{new}$ is re-wrapped for each remaining member in authoritative `members` with AAD `${vaultId}:${newDekVersion}:${memberName}`.
7. Sensitive buffer $DEK_{new}$ is wiped via `.fill(0)`.
8. Server verifies caller permissions, verifies `newWrappedDeks` does not include revoked user, validates all remaining members have valid wrapped DEKs, and atomically commits the update.

---

## Threat Model

### Protected Against
* **Oblivious Server Compromise**: Compromise of stored server files (`users.json`, `vaults/*.json`) yields only ciphertext, public keys, and derived authentication verifiers. Under stated cryptographic assumptions, server data compromise does not provide plaintext secrets or private keys.
* **Accidental Repo Leaks & Backups**: Plaintext `.env` files are never written to disk during normal operation.
* **Unauthorized Access**: Unauthenticated requests and unauthorized roles fail closed at the server gateway.
* **Ciphertext & Envelope Tampering**: Any alteration of ciphertext, IV, tag, or AAD causes immediate authentication failure.
* **Replay Attacks**: Replay of captured authenticated requests is defeated by single-use nonces and the 300-second timestamp freshness window.
* **Concurrent Overwrite (Lost Updates)**: Monotonic `vaultVersion` counter and mutex locking reject stale updates with HTTP 409 Conflict.
* **Revoked Member Access**: After revocation, the secret payload is re-encrypted with a fresh DEK. The revoked member's old DEK fails authentication against the new blob, and the revoked user is denied vault retrieval.

### Documented Limitations
* **Compromised Client Endpoint**: An attacker with administrative or memory-dump access on an active developer workstation can access secrets residing in volatile memory or child process memory.
* **JavaScript / V8 Memory Zeroization**: Node.js `Buffer` instances holding sensitive keys are explicitly wiped via `.fill(0)`, but V8 engine string and object allocations cannot be guaranteed to be immediately purged from physical RAM until garbage collection occurs.
* **OS Memory Paging / Swap**: Operating system swapping of volatile memory pages to unencrypted swap partitions is outside application-level control.
* **Server-Side Verifier Compromise**: If the server storage is compromised, an adversary possessing stored verifiers ($K_{sign}$) could forge API signatures to query endpoints, but still cannot decrypt secret payloads without developer private keys.

---

## Usage Examples

### 1. Developer Initialization
```bash
envguard init alice
# Prompts for Master Passphrase (minimum 12 characters)
# Prompts for Server Enrollment Key
```

### 2. Provisioning Environment Secrets
```bash
# Interactive hidden prompt (prevents shell history leakage)
envguard set DATABASE_URL

# Standard input piping (for heredocs or CI automation)
cat <<EOF | envguard set --stdin
DATABASE_URL=postgres://app:secret@db.internal:5432/app
API_KEY=prod_live_9876543210
CACHE_PORT=6379
EOF

# Inline argument form (displays security warning regarding process table exposure)
envguard set STRIPE_SECRET=sk_live_123456789
```

### 3. Runtime Secret Injection
```bash
# Injects decrypted secrets into runtime memory of the child process
envguard run -- node server.js

# Run with environment override
envguard run --env production -- npm start
```

### 4. Team Access Management
```bash
# Grant member access to a teammate
envguard grant bob --role member

# Grant with public-key fingerprint verification
envguard grant charlie --role admin --fingerprint SHA256:abcd1234efgh5678...

# Revoke access (triggers mandatory DEK rotation)
envguard revoke bob
```

---

## Project Structure

```text
EnvGuard/
├── bin/
│   └── envguard.js          # CLI entrypoint executable
├── docs/
│   ├── design.md            # System architecture & threat model specification
│   └── demo.md              # 5–10 minute demonstration walkthrough script
├── scripts/
│   └── smoke.js             # Automated smoke testing script
├── src/
│   ├── client/
│   │   ├── api.js           # HTTP/HTTPS client & HMAC request signing
│   │   ├── keystore.js      # Local key.enc and credentials.json management
│   │   └── logger.js        # Terminal logging utilities
│   ├── commands/
│   │   ├── grant.js         # envguard grant command handler
│   │   ├── init.js          # envguard init command handler
│   │   ├── project.js       # envguard project command handler
│   │   ├── revoke.js        # envguard revoke command handler
│   │   ├── run.js           # envguard run command handler
│   │   └── set.js           # envguard set command handler
│   ├── crypto/
│   │   ├── aes.js           # AES-256-GCM authenticated encryption
│   │   ├── ecdh.js          # Native X25519 keypair & shared secret derivation
│   │   ├── envelope.js      # Envelope creation and unwrapping primitives
│   │   ├── hmac.js          # HMAC-SHA512 hashing primitives
│   │   └── kdf.js           # HKDF-SHA512 and PBKDF2 key derivation
│   └── server/
│       ├── auth.js          # Server-side HMAC verification & replay cache
│       ├── server.js        # HTTP/HTTPS Vault Server REST API
│       └── storage.js       # Atomic filesystem storage & mutex locks
├── test/
│   ├── aes.test.js          # AES-256-GCM unit tests
│   ├── ecdh.test.js         # X25519 ECDH unit tests
│   ├── envelope.test.js     # Cryptographic envelope composition tests
│   ├── grant.test.js        # Grant command & ACL tests
│   ├── hmac.test.js         # HMAC unit tests
│   ├── init.test.js         # Init command & keystore tests
│   ├── integration.test.js  # End-to-end integration & security regression tests
│   ├── kdf.test.js          # HKDF & PBKDF2 unit tests
│   ├── revoke.test.js       # Revoke command & DEK rotation tests
│   ├── run.test.js          # Run command & process injection tests
│   ├── server.test.js       # Server route & error handling tests
│   ├── set.test.js          # Set command & secret merging tests
│   └── storage.test.js      # Storage mutex & atomic file write tests
├── package.json
└── README.md
```

---

## Verification & Testing

EnvGuard is validated across unit, integration, and security test suites using Node.js built-in test runner:

```bash
# Run all automated test suites
npm test

# Run CLI smoke tests
npm run smoke

# Check dependencies
npm ls --depth=0
```

### Verified Test Results
* **Automated Unit & Integration Tests**: **250 / 250 passing** across 8 test suites.
* **CLI Smoke Tests**: **12 / 12 passing** (verifying registered commands, arguments, and failure modes).
* **End-to-End Integration Suite**: 13 comprehensive lifecycle and regression tests in [`test/integration.test.js`](file:///f:/EnvGuard/test/integration.test.js).
* **Security Audits**: Formally passed independent source-level audits for Phases 5, 6, 7, and 8 with zero security findings.
* **Zero Dependencies**: Pure Node.js built-in cryptography and standard libraries; runtime dependencies strictly limited to `chalk` and `commander`.
