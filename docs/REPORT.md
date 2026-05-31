# Project Report (Academic Submission)

## Problem statement

Build a **local-only** password vault: encrypted file storage, safe CLI, no custom
cryptography, and honest documentation of limits (memory, metadata leakage, offline attacks).

## Threat model (summary)

| Threat | Mitigation |
| --- | --- |
| Offline read of vault file | scrypt KDF + Fernet authenticated encryption |
| Tampering with ciphertext | Fernet MAC; decrypt fails closed |
| Secret leakage via CLI defaults | Mask passwords/notes; `getpass` for master password |
| Shell history exposure | Master password never accepted as CLI argument |
| Partial write corruption | Atomic write (temp → fsync → replace) |
| Concurrent CLI writers | Write lock + monotonic `revision` in header |
| Weak KDF in file | Schema enforces minimum scrypt `n` (power of two) |

**Out of scope:** malware, keyloggers, clipboard sniffing, cloud sync, multi-user sharing,
web UI, browser extensions, constant-time unlock, secure string wiping in CPython.

## Design decisions (ADRs)

| Topic | Decision | Record |
| --- | --- | --- |
| Crypto library | Use `cryptography` only | [0001](adr/0001-use-cryptography.md) |
| Key derivation | Direct scrypt → Fernet key | [0002](adr/0002-direct-key-derivation.md), [0003](adr/0003-scrypt.md) |
| Symmetric encryption | Fernet tokens | [0004](adr/0004-fernet.md) |
| Password check | Decrypt body, no verifier field | [0005](adr/0005-no-password-verifier.md) |
| Parse/decrypt failures | Fail closed | [0006](adr/0006-fail-closed.md) |
| Memory claims | No secure wipe promise | [0007](adr/0007-memory-limitations.md) |
| Deployment | CLI only, no web | [0008](adr/0008-no-web-layer.md) |
| Writers | Lock file + revision | [0009](adr/0009-concurrent-writer-policy.md) |

## Requirements traceability

| ID | Requirement | Implementation | Tests |
| --- | --- | --- | --- |
| R1 | scrypt + Fernet via one module | `crypto_engine.py` | `test_crypto_engine.py`, `test_security.py` |
| R2 | Encrypted vault file | `VaultStore`, `serializer.py` | `test_store.py`, `test_serializer_schema.py` |
| R3 | Atomic persistence | `atomic.py` | `test_atomic.py` |
| R4 | Schema validation | `schema.py` | `test_serializer_schema.py`, `test_schema_limits.py` |
| R5 | CRUD + search | `vault.py` | `test_entries.py`, `test_vault_lifecycle.py` |
| R6 | Safe CLI | `cli.py` | `test_cli.py` |
| R7 | Master password policy | `vault.py` (`MIN_MASTER_PASSWORD_LENGTH`) | `test_schema_limits.py`, `test_cli.py` |
| R8 | Session safety | `lock()`, failed `unlock` / `verify_password` / `change_master_password` | `test_vault_session.py`, `test_vault_complete.py` |
| R9 | Concurrent write detection | `revision`, `VaultConflictError` | `test_revision.py` |
| R10 | Golden sample vault | `tests/fixtures/golden.pwv` | `test_golden_vault.py` |
| R11 | KDF cost upgrade on rotation | `Vault.change_master_password(..., kdf_params=)` | `test_vault_complete.py` (library API; not exposed in CLI) |

## Test strategy

- **Unit:** crypto round-trip, generator, schema edge cases.
- **Integration:** full CLI flows with mocked `getpass`.
- **Security:** single-module `cryptography` import rule.
- **Property:** header/body JSON round-trip (Hypothesis).
- **Concurrency:** write-lock stale recovery and cross-thread blocking (`test_lockfile_complete.py`); Windows-specific PID liveness paths run on the **Windows** CI matrix job (`windows-latest`).
- **CI:** Python 3.10 & 3.12 on Ubuntu, Windows, and macOS; ruff, mypy, pytest with ≥90% coverage; pre-commit; lockfile install job on 3.12.

## Limitations (honest)

1. Wrong password vs corrupt file — same `DecryptionError` message (by design).
2. Plaintext header reveals KDF parameters, salt, and revision.
3. Master password strength is length-only (≥12); no zxcvbn.
4. Best-effort lock file, not a cluster-wide distributed lock.
5. In-memory secrets may remain in process RAM until GC.
6. **`initialize()` leaves an unlocked session** — library callers should call `lock()` when done.
7. **Platform caveats (Windows):**
   - Directory fsync after `os.replace` is a no-op on Windows; atomic rename still holds, but directory-entry durability is POSIX-stronger (see `SECURITY.md`).
   - Write-lock stale recovery uses `OpenProcess` + exit code, not `os.kill(pid, 0)` (which would terminate the holder on Windows).
   - Unparseable PID text in a lock file is treated as stale and removed.
8. **`verify_password()` while already unlocked** validates against disk but does not refresh in-memory entries; re-`unlock` after external writes (see `ARCHITECTURE.md`).

## Future work (not required for scope)

- Optional clipboard copy with auto-clear.
- Encrypted backup export format.
- Argon2id if coursework allows dependency/policy change.

## How to reproduce

```powershell
python -m pip install -e ".[dev]"
# Or, for exact dependency pins (matches CI lockfile job on Python 3.12):
# python -m pip install -r requirements-lock.txt
# python -m pip install -e .

python scripts/generate_golden_vault.py
python -m pytest
python -m password_manager --vault tests/fixtures/golden.pwv check
# Master password: golden-password
```
