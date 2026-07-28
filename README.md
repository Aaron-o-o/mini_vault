# Mini Vault

Mini Vault is a command-line secure-storage service implementing all eight required features in Assignment 1:

- Vault initialization/unlock using Argon2id and AES-256-GCM.
- Argon2 user authentication, 30-minute session tokens, and a five-minute lockout after five failed logins.
- AES-256-GCM encrypted KV storage with owner namespaces and denied-access audit logs.
- Owner-bound Transit encryption and Ed25519 signing keys, encrypted at rest by the vault DEK.
- Transit encrypt/decrypt and sign/verify operations without exposing private key material.

The project also implements three optional advanced features (suggested extra credit: `+0.8`): TOTP MFA (`+0.2`), KV versioning (`+0.3`), and a tamper-evident hash-chained audit log (`+0.3`).

## Project structure

```text
main.py                 CLI entry point
src/core/vault.py       Master passphrase, KEK, and DEK lifecycle
src/auth/auth.py        Registration, login, sessions, and lockout
src/kv/engine.py        Encrypted KV storage and access control
src/transit/engine.py   Named keys, encryption, and signatures
src/storage/storage.py  JSON persistence and audit logging
tests/                  Acceptance and security tests
```

## Setup

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest -q
```

## CLI usage

For normal use, start the interactive shell. It keeps the decrypted DEK only in that process's memory, so one successful `unlock` applies to subsequent commands until `lock` or `exit`. Exiting the shell clears the in-memory DEK.

```powershell
python main.py --data-dir data shell
```

Inside the shell:

```text
mini-vault> unlock
mini-vault> status
mini-vault> create-key --token <session-token> --key-name app-key
mini-vault> list-keys --token <session-token>
mini-vault> lock
mini-vault> exit
```

The existing one-shot subcommands remain available for scripts. Because each one-shot invocation is a new process, protected commands in that mode require `--master-passphrase`. Passing secrets directly on the command line may expose them in shell history; omit passphrases to use the hidden prompt.

```powershell
python main.py --data-dir data init
python main.py --data-dir data register alice@example.com
python main.py --data-dir data login alice@example.com
```

Save the token printed by `login`, then use it in the protected commands:

```powershell
$token = '<session-token>'
$master = '<master-passphrase>'

python main.py --data-dir data write --token $token --path db --data '{\"password\":\"hunter2\"}' --master-passphrase $master
python main.py --data-dir data read --token $token --path db --master-passphrase $master

python main.py --data-dir data create-key --token $token --key-name app-key --master-passphrase $master
python main.py --data-dir data list-keys --token $token --master-passphrase $master
python main.py --data-dir data encrypt --token $token --key-name app-key --plaintext-b64 aGVsbG8= --master-passphrase $master

python main.py --data-dir data create-signing-key --token $token --key-name app-sign --algorithm ED25519 --master-passphrase $master
python main.py --data-dir data sign --token $token --key-name app-sign --message-b64 aGVsbG8= --message-type RAW --master-passphrase $master
```

`sign` returns a structured JSON response containing `signature_b64`, `key_name`, and `signing_algorithm`, matching the assignment's I/O contract.

## Advanced features

### TOTP MFA

Enable MFA while authenticated, scan the returned `otpauth_uri` with an authenticator application, and then supply the current six-digit code on subsequent logins:

```powershell
python main.py --data-dir data enable-mfa --token $token
python main.py --data-dir data mfa-status --token $token
python main.py --data-dir data login alice@example.com --otp 123456
```

The enrollment secret is returned only by `enable-mfa`; `mfa-status` never exposes it. On disk, it is encrypted with AES-GCM using a key derived from the user's passphrase. TOTP uses SHA-1, six digits, 30-second periods, and a one-period clock-skew window, matching common authenticator applications.

### KV versioning

Every overwrite creates a new encrypted version while preserving earlier encrypted records. A normal read returns the newest value:

```powershell
python main.py --data-dir data list-versions --token $token --path db --master-passphrase $master
python main.py --data-dir data read --token $token --path db --version 1 --master-passphrase $master
```

Deleting a path permanently deletes its current value and all historical versions.

### Tamper-evident audit log

Every denied-access event contains `previous_hash` and `event_hash`. Each SHA-256 hash covers the canonical event and the preceding event hash, so editing, reordering, inserting, or removing an event from within the chain invalidates it:

```powershell
python main.py --data-dir data verify-audit --token $token
```

The command returns `valid`, `event_count`, and the first `invalid_index` when tampering is detected.

Run `python main.py --help` or `python main.py <command> --help` for the full command list.

## Security design

- The master passphrase is never stored. Argon2id derives a KEK from it and a random salt.
- The random 256-bit DEK is stored only as AES-GCM ciphertext and exists in plaintext only in process memory while unlocked.
- Every AES-GCM encryption uses a fresh 96-bit nonce. KV ciphertext and tags are stored separately to match the assignment contract.
- KV paths are normalized to `secret/<owner-email>/...`; cross-owner attempts are rejected before decryption and audited.
- Named AES keys and Ed25519 private keys are encrypted by the DEK before persistence. Key-list and creation responses expose metadata only.
- The CLI validates the session token before invoking KV or Transit permission checks.
- Transit ciphertext is self-describing: `vault:<key-name>:<base64(nonce+ciphertext+tag)>`.
- `RAW` signing input is SHA-256 hashed by Mini Vault; `DIGEST` input must already be exactly 32 bytes.

## Test coverage

The test suite covers restart-locked behavior, DEK protection, exact five-minute account lockout, session expiry, TOTP enrollment and enforcement, KV round trips and historical versions, ciphertext/tag tampering, plaintext leakage, ownership denial, audit hash-chain tampering, Transit round trips, malformed/tampered ciphertext, revoked keys, invalid key usage, digest validation, malformed signatures, tampered messages, cross-key signatures, and locked-state rejection for all Transit operations.

## Submission notes

The assignment also requires a group report under `docs/report/`, group-member roles, screenshots, test-data samples, and the final `StudentID1_StudentID2_StudentID3.zip` naming convention. Add those identity-specific artifacts before submission; they cannot be inferred from the source code.
