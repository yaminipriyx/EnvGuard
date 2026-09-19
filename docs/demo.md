# EnvGuard — Live Demonstration Walkthrough (5–10 Minutes)

This script provides a practical, step-by-step demonstration of EnvGuard for evaluators, security auditors, and teammates. It highlights the zero-knowledge storage property, runtime secret injection without `.env` files, and cryptographic revocation with automated Data Encryption Key (DEK) rotation.

---

## Safety Guidelines

> [!IMPORTANT]
> **Never use real credentials during demonstrations.**
> Use clearly artificial demo values such as:
> * `DATABASE_URL=postgres://demo_user:fake_password_123@localhost:5432/demo_db`
> * `STRIPE_KEY=sk_test_fake_stripe_key_abcdef123456`
> * `API_TOKEN=demo_fake_api_token_99999`

---

## 1. Introduction (1 Minute)

### The Problem
Traditional development workflows rely heavily on local `.env` files. This creates major risks:
* Developers accidentally commit `.env` to Git repositories.
* Secrets sit in plaintext on developer laptops, unencrypted backups, and shared drives.
* Revoking access for an ex-employee requires manual credential rotation across all services, which teams often delay or omit.

### The EnvGuard Solution
* **Zero Plaintext on Disk**: Secrets are encrypted on the client and stored as ciphertext on a centralized Vault Server.
* **Runtime Volatile Injection**: Secrets are decrypted strictly in volatile RAM at command execution time and passed directly to child processes.
* **Cryptographic Revocation**: Revoking a member automatically rotates the encryption key (DEK) and re-encrypts the vault so the revoked member's old keys can never decrypt future data.

---

## 2. Environment Setup (30 Seconds)

Ensure the Vault Server is running in a background terminal:

```bash
# Terminal 1: Start Vault Server
node -e "
import { createServer } from './src/server/server.js';
const server = createServer({ dataDir: './server-data', enrollmentKey: 'demo-enrollment-key', host: '127.0.0.1' });
server.listen(3000, '127.0.0.1', () => console.log('Vault Server running on http://127.0.0.1:3000'));
"
```

Configure environment variable pointing to the demo server:
```bash
# Terminal 2 (Developer workstation)
export ENVGUARD_SERVER="http://127.0.0.1:3000"
# (On Windows PowerShell: $env:ENVGUARD_SERVER="http://127.0.0.1:3000")
```

---

## 3. Developer Initialization (1 Minute)

Initialize a new developer identity for Alice (the vault owner):

```bash
envguard init alice
```

1. Enter master passphrase: `demo-passphrase-alice-123` (minimum 12 characters).
2. Enter enrollment key: `demo-enrollment-key`.
3. Explain what happened:
   * A native X25519 asymmetric keypair was generated.
   * Alice's private key was encrypted locally using PBKDF2-HMAC-SHA256 (600,000 iterations) and stored in `~/.envguard/key.enc` (permissions `0600`).
   * A 32-byte API token was generated and stored locally in `~/.envguard/credentials.json`.
   * Only Alice's public key and HMAC verifier were sent to the server. Alice's master passphrase and private key **never left the workstation**.

---

## 4. Secret Provisioning & Storage Obliviousness (2 Minutes)

### Set Environment Secrets
Provision the project's secrets using interactive hidden input:

```bash
envguard set DATABASE_URL
# Enter value (hidden): postgres://demo_user:fake_password_123@localhost:5432/demo_db

envguard set STRIPE_KEY=sk_test_fake_stripe_key_abcdef123456
```

### Inspect the Server Filesystem
Show the audience that the Vault Server holds **zero plaintext secrets**:

```bash
# View the server storage directory
cat server-data/vaults/*.json
```

**Demonstration Point**:
* Show the audience that the server holds only:
  * `blob.ciphertext`: A random hex string.
  * `blob.iv` & `blob.tag`: AES-256-GCM metadata.
  * `wrappedDeks.alice`: Alice's wrapped DEK under her X25519 public key.
* Search the server file for `fake_password_123` or `postgres`:
  ```bash
  grep -i "fake_password" server-data/vaults/*.json
  # Result: Nothing found!
  ```

---

## 5. Runtime Secret Injection (1.5 Minutes)

Create a minimal sample application `demo-app.js`:

```javascript
// demo-app.js
console.log('--- DEMO APP STARTING ---');
console.log('DATABASE_URL present:', Boolean(process.env.DATABASE_URL));
console.log('STRIPE_KEY present:  ', Boolean(process.env.STRIPE_KEY));
if (process.env.DATABASE_URL) {
  console.log('Connected to DB successfully with injected secrets!');
} else {
  console.error('ERROR: No environment secrets found!');
}
```

Now run the app **without** EnvGuard:
```bash
node demo-app.js
# Result: False / Error (no environment variables present)
```

Now run the app **with** EnvGuard:
```bash
envguard run -- node demo-app.js
```
* Enter Alice's master passphrase: `demo-passphrase-alice-123`.
* Output:
  ```text
  --- DEMO APP STARTING ---
  DATABASE_URL present: true
  STRIPE_KEY present:   true
  Connected to DB successfully with injected secrets!
  ```

**Demonstration Point**:
* Check the current directory:
  ```bash
  ls -la
  ```
  **No `.env` file was ever created on disk.** The secrets existed only in volatile memory for the duration of the child process.

---

## 6. Teammate Collaboration: Granting Access (1 Minute)

Initialize a second developer, Bob:
```bash
# In a separate terminal or directory
ENVGUARD_HOME=./keystores/bob envguard init bob
# Passphrase: demo-passphrase-bob-12345
# Enrollment Key: demo-enrollment-key
```

Now Alice grants Bob member access to the vault:
```bash
envguard grant bob --role member
```

**Demonstration Point**:
* Inspect `server-data/vaults/*.json`.
* Show that `members` now has `"bob": "member"`.
* Show that `wrappedDeks` now contains an entry for `bob`.
* Show that `dekVersion` is still `1`: **Grant does not rotate the DEK**.

---

## 7. Revocation & Automated DEK Rotation (2 Minutes)

Suppose Bob leaves the team. Alice revokes Bob:

```bash
envguard revoke bob
```
* Enter Alice's passphrase to decrypt the vault.
* Alice's CLI:
  1. Decrypts the secrets with the old DEK.
  2. Generates a fresh 32-byte DEK ($DEK_2$).
  3. Re-encrypts the secret map with $DEK_2$.
  4. Wraps $DEK_2$ for Alice.
  5. Removes Bob from `members` and `wrappedDeks`.
  6. Atomically updates the server state.

**Demonstration Point**:
* Inspect `server-data/vaults/*.json`:
  * `dekVersion` is now `2`!
  * `wrappedDeks.bob` is completely gone!
  * `members.bob` is completely gone!

### Verify Revoked Access
Now attempt to run with Bob's credentials:
```bash
ENVGUARD_HOME=./keystores/bob envguard run -- node demo-app.js
```
* Output:
  ```text
  [error] Access denied: caller "bob" is not an authorized vault member
  ```
* Even if Bob kept an offline dump of his old wrapped DEK ($DEK_1$), Bob **cannot** decrypt the server's rotated secret blob because the vault was re-encrypted under $DEK_2$.

---

## 8. Summary & Q&A (30 Seconds)

Review what was demonstrated:
1. **Oblivious Storage**: Server never saw plaintext secrets.
2. **Runtime Injection**: Zero disk `.env` files.
3. **Cryptographic Revocation**: Automatic DEK rotation upon member removal.
4. **Zero Dependencies**: Pure native Node.js cryptography.
