# Architecture Decision Record
## App — Password Manager
**Security Tools Group | Document 1 of 5**
**Status: Accepted**

---

## Context

The Security Tools group requires a local-only encrypted password vault for coursework and portfolio demonstration. The application must store password entries on disk, protect vault contents with a master password, avoid putting secrets on the command line, fail closed on invalid data or failed decryption, and document realistic threat-model limits.

The project is not a hosted password manager, browser extension, cloud sync service, secrets manager, or enterprise credential platform. It is a Python library plus argparse CLI that demonstrates secure local-file architecture: KDF-based key derivation, authenticated encryption, schema validation, atomic persistence, write locking, revision conflict checks, safe prompts, masked output, and defensive data copies.

The selected architecture separates responsibility by boundary:

```text
CLI → Vault domain layer → CryptoEngine / VaultStore → Serializer / Schema / Atomic write / WriteLock
```

---

## Decisions

### Decision 1 — Local-only vault

**Chosen:** Store one encrypted vault file locally and operate through CLI/library calls.

**Rejected:** Cloud sync, server storage, browser extension, or account-based access.

**Reason:** The academic goal is to show local security architecture, not distributed identity, sync conflict resolution, or network threat modeling. Local-only scope makes the trade-offs clear and keeps the implementation reviewable.

---

### Decision 2 — Single cryptography boundary

**Chosen:** Only `crypto_engine.py` imports `cryptography` and wraps scrypt + Fernet.

**Rejected:** Calling cryptography APIs directly throughout vault, store, and CLI modules.

**Reason:** Cryptographic behavior should be centralized and auditable. Isolating the dependency makes it easier to inspect, test, and enforce the rule that the rest of the app does not perform ad-hoc crypto.

---

### Decision 3 — scrypt for master-password KDF

**Chosen:** Derive the Fernet key from the master password using scrypt, with default parameters stored in the header.

**Rejected:** Plain hashing, PBKDF2-only design, or hard-coded key material.

**Reason:** A password vault must derive encryption keys from user-provided text. scrypt gives memory-hard derivation appropriate for local offline-file protection within the project scope. The KDF parameters are schema-validated and can be upgraded through library-level password rotation.

---

### Decision 4 — Fernet authenticated encryption

**Chosen:** Encrypt the serialized vault body with Fernet.

**Rejected:** Hand-rolled encryption mode or unauthenticated encryption.

**Reason:** The project should not invent cryptographic primitives. Fernet provides authenticated encryption through a well-reviewed library, and invalid ciphertext produces a safe `DecryptionError` path.

---

### Decision 5 — No separate password verifier

**Chosen:** The vault does not store a password verifier. Wrong password and corrupted ciphertext both fail through the same safe decryption message.

**Rejected:** Storing a verifier hash to check the password before decrypting.

**Reason:** A verifier can give attackers another offline target and can leak password-check semantics. Decrypting authenticated ciphertext is enough for verification in this scope.

---

### Decision 6 — JSON envelope with encrypted body

**Chosen:** Store a JSON envelope containing plaintext header metadata and encrypted body text.

**Rejected:** Encrypting the whole file, or storing many independent encrypted records.

**Reason:** Header metadata is needed to know how to derive the key and decrypt the vault. The sensitive entries live only in the encrypted body. The format stays inspectable and easy to validate.

---

### Decision 7 — Schema validation before trust

**Chosen:** Validate headers, encrypted body size, decrypted body shape, entry IDs, entry timestamps, KDF bounds, and field sizes before using vault data.

**Rejected:** Trusting parsed JSON and decrypted bytes directly.

**Reason:** File parsing and decryption are hostile boundaries. If schema validation fails, the vault must not partially trust data.

---

### Decision 8 — Atomic writes and same-directory write lock

**Chosen:** Use temp-file writes, fsync, `os.replace`, parent-directory fsync, and a same-directory lock file for writes.

**Rejected:** Directly overwriting the vault file.

**Reason:** A vault write must not leave a partially written file if the process crashes. The write lock also prevents casual concurrent CLI overwrites. Revision checks handle stale sessions.

---

### Decision 9 — Revision conflict detection

**Chosen:** The header carries a revision number. Before commit, the vault checks that the on-disk revision matches the in-memory header revision.

**Rejected:** Last-writer-wins writes.

**Reason:** Library users may hold an unlocked session while another process changes the vault. Revision checks prevent silent overwrite of a newer file.

---

### Decision 10 — In-memory session with explicit lock/unlock

**Chosen:** `Vault.unlock()` loads header/body/key into memory; `Vault.lock()` drops them. Operations requiring secrets require an unlocked session.

**Rejected:** Re-deriving and decrypting for every library call, or keeping a background session daemon.

**Reason:** The library needs a clear state model. The README documents that CLI commands use a fresh `Vault` per invocation, while library callers can manage sessions explicitly.

---

### Decision 11 — Safe CLI prompting

**Chosen:** Master passwords, entry passwords, and optional notes prompts use `getpass`; master password is never a CLI argument.

**Rejected:** `--master-password` or other command-line secret flags.

**Reason:** Command-line arguments can leak through shell history, process listings, logs, and test output. Prompting through `getpass` better matches the threat model.

---

### Decision 12 — Safe summaries by default

**Chosen:** `list` prints only IDs, service, username, and URL. `get` masks password unless `--reveal` is passed, and masks notes unless `--details` is requested.

**Rejected:** Printing full entries by default.

**Reason:** A password manager should avoid accidental terminal exposure. Revealing secrets must be explicit.

---

## Consequences

**Positive:**
- Crypto usage is isolated and testable.
- Failed decrypt/parse/schema paths do not expose partial vault data.
- Atomic writes reduce file-corruption risk.
- Write locks reduce concurrent mutation collisions.
- Revision checks prevent stale-session overwrites.
- CLI avoids command-line secret leakage.
- Public dataclasses returned by the library are defensive copies.
- Security limits are documented instead of overstated.

**Negative / Trade-offs:**
- No cloud sync or multi-device access.
- Metadata such as header fields, file size, file mtime, and Fernet timing remain visible.
- CPython cannot reliably wipe strings from memory.
- Weak master passwords remain vulnerable to offline guessing.
- Same-directory lock is best-effort, not a distributed lock.
- No browser integration or autofill.
- KDF upgrade is library-only, not exposed through CLI flags.

---

## Alternatives Not Explored

- Argon2 KDF.
- OS keychain integration.
- Multi-file item storage.
- Cloud sync and conflict resolution.
- Browser extension/autofill.
- Secret sharing or emergency recovery.
- Hardware security key support.
- Encrypted metadata hiding.
- GUI or TUI.

---

*Constitution reference: Article 1 (architectural thinking), Article 3.3 (scope discipline), Article 4 (engineering quality), Article 5 (trade-off documentation), Article 6 (behavior verification), and Article 7 (progressive complexity).*

---


# Technical Design Document
## App — Password Manager
**Security Tools Group | Document 2 of 5**

---

## Overview

Password Manager is a local encrypted vault implemented as a Python library plus argparse CLI. It stores a JSON envelope on disk. The envelope contains a plaintext header and a Fernet-encrypted serialized body. The body contains password entries.

**Package:** `password_manager`  
**Console script:** `pwvault`  
**Module entry point:** `python -m password_manager`  
**Python requirement:** `>=3.10`  
**Runtime dependency:** `cryptography>=42,<45`  
**Primary API:** `Vault`, `EntryCreate`, `EntryUpdate`, `KDFParams`

---

## Data Flow

### Initialize vault

```text
CLI init / Vault.initialize(master_password)
  │
  ├── require password length >= 12
  ├── generate salt
  ├── build VaultHeader
  ├── validate header
  ├── create empty VaultBody
  ├── serialize body
  ├── derive key with scrypt
  ├── encrypt body with Fernet
  └── VaultStore.initialize()
        ├── acquire WriteLock
        ├── refuse existing file
        ├── validate header/ciphertext
        ├── serialize envelope
        └── atomic_write()
```

---

### Unlock vault

```text
Vault.unlock(master_password)
  │
  ├── require password length >= 12
  ├── VaultStore.read()
  │     ├── read file bytes
  │     ├── parse envelope
  │     ├── validate header
  │     └── validate encrypted body size
  ├── derive key from header salt/kdf params
  ├── decrypt encrypted body
  ├── deserialize body
  ├── validate body and entries
  └── store header/body/key in memory
```

On any failure, the vault session is cleared.

---

### Add/update/delete entry

```text
Mutating CLI command
  │
  ├── collect interactive input before write lock
  ├── acquire WriteLock
  ├── create fresh Vault instance
  ├── unlock with master password
  ├── mutate in-memory body
  ├── validate candidate entry/body
  ├── serialize body
  ├── encrypt with session key
  ├── check on-disk revision
  ├── increment revision
  └── write atomically
```

If persistence fails, the in-memory mutation is rolled back.

---

### Get/list/search

```text
Read-only CLI command
  │
  ├── prompt master password
  ├── unlock vault
  ├── list safe summaries OR get one entry OR search summaries
  └── print masked output unless reveal/detail flags are explicit
```

---

## Module-Level Structure

```text
Password-Manager/
  password_manager/
    __init__.py
    __main__.py
    atomic.py
    cli.py
    crypto_engine.py
    errors.py
    generator.py
    lockfile.py
    models.py
    schema.py
    serializer.py
    store.py
    vault.py
  docs/
    ARCHITECTURE.md
    REPORT.md
    adr/
  scripts/
    generate_golden_vault.py
  tests/
    fixtures/golden.pwv
    test_*.py
  pyproject.toml
  requirements-dev.txt
  requirements-lock.txt
  README.md
  SECURITY.md
  CHANGELOG.md
  LICENSE
  .github/workflows/ci.yml
```

---

## Module Dependency Graph

```text
cli.py
  ├── Vault
  ├── EntryCreate / EntryUpdate / EntrySummary
  ├── generate_password
  ├── WriteLock
  ├── getpass
  └── argparse

vault.py
  ├── CryptoEngine
  ├── VaultStore
  ├── VaultSerializer
  ├── VaultSchema
  ├── WriteLock
  ├── models
  └── errors

store.py
  ├── atomic_write
  ├── WriteLock
  ├── VaultSerializer
  ├── VaultSchema
  └── StoredVault

crypto_engine.py
  └── cryptography only here

serializer.py
  ├── json/base64
  └── models

schema.py
  ├── constants/limits
  └── model validation

lockfile.py
  ├── same-directory lock file
  ├── PID/start-time liveness
  └── stale-lock cleanup
```

---

## Core Data Structures

### `KDFParams`

Fields:
- `name='scrypt'`
- `length=32`
- `n=2**14`
- `r=8`
- `p=1`

---

### `VaultHeader`

Fields:
- `format='py-password-vault'`
- `version=1`
- `kdf='scrypt'`
- `kdf_params`
- `salt`
- `cipher='fernet'`
- `revision`
- `created_at`
- `updated_at`

---

### `Entry`

Fields:
- `id`
- `service`
- `username`
- `password`
- `url`
- `notes`
- `created_at`
- `updated_at`

Returned entry objects are frozen defensive copies.

---

### `EntrySummary`

Safe non-secret view of an entry:
- `id`
- `service`
- `username`
- `url`
- timestamps

No password or notes.

---

### `EntryCreate`

Mutable command object for add operations:
- `service`
- `username`
- `password`
- optional `url`
- optional `notes`

---

### `EntryUpdate`

Mutable command object for partial update operations. `has_changes()` verifies that at least one field is provided.

---

### `VaultBody`

Fields:
- `version=1`
- `entries=[]`

The body is encrypted before storage.

---

### `StoredVault`

Fields:
- `header`
- `encrypted_body`

Returned by `VaultStore.read()`.

---

## Function and Class Reference

### `CryptoEngine.generate_salt(length=16)`

Returns random salt bytes from `os.urandom()`.

---

### `CryptoEngine.derive_key(password, salt, params)`

Derives a Fernet-compatible key using scrypt and URL-safe base64 encoding.

---

### `CryptoEngine.encrypt(key, plaintext)`

Encrypts plaintext bytes with Fernet.

---

### `CryptoEngine.decrypt(key, token)`

Decrypts Fernet token bytes. Invalid token paths raise `DecryptionError('decryption failed')`.

---

### `VaultSerializer`

Responsibilities:
- serialize header to dict
- parse header from dict
- serialize body to compact JSON bytes
- parse body bytes to `VaultBody`
- serialize full vault envelope
- parse full vault envelope

---

### `VaultSchema`

Validates:
- vault format/version
- KDF/cipher IDs
- scrypt parameter bounds
- salt length
- revision
- timezone-aware timestamps
- encrypted body size
- decrypted body size
- entry count
- UUID entry IDs
- required service/username/password
- field length caps
- duplicate IDs

---

### `VaultStore`

Responsibilities:
- check vault existence
- read and validate envelope/header/ciphertext
- read header for revision checks
- initialize under write lock
- write under write lock
- delegate atomic file replacement

---

### `Vault.initialize(master_password)`

Creates a new vault and leaves a library session unlocked. CLI users get a fresh process per command.

---

### `Vault.unlock(master_password)`

Decrypts and validates the vault. Clears any session on failure.

---

### `Vault.lock()`

Drops in-memory header, body, and key.

---

### `Vault.verify_password(master_password)` / `Vault.check()`

Decrypts and validates the vault without preserving a session when called from CLI-style usage. Failure clears any existing session.

---

### `Vault.add_entry(entry_data)`

Creates a UUID entry, validates it, appends it, saves, and returns a defensive copy.

---

### `Vault.list_entries()`

Returns safe summaries only.

---

### `Vault.get_entry(id_or_service)`

Finds by UUID or exact case-insensitive service name. If a service matches multiple entries, raises `AmbiguousEntryError` with safe summaries.

---

### `Vault.update_entry(id_or_service, updates)`

Applies partial updates, validates candidate before replacing the original, saves, and rolls back memory if save fails.

---

### `Vault.delete_entry(id_or_service)`

Removes one entry and saves; rolls back memory if save fails.

---

### `Vault.search(query)`

Case-insensitive search across service, username, URL, and notes. Returns safe summaries.

---

### `Vault.change_master_password(old_password, new_password, kdf_params=None)`

Re-authenticates, rejects password reuse, generates a new salt, optionally upgrades KDF params, re-encrypts the body, and preserves prior lock state on success.

---

### `generate_password()`

Uses the standard-library CSPRNG. Requires length at least 12 and at least one character class. Ensures at least one selected character from each enabled class, then shuffles via `secrets.randbelow()`.

---

## State Management

### On disk

```json
{
  "header": {
    "format": "py-password-vault",
    "version": 1,
    "revision": 0,
    "kdf": "scrypt",
    "kdf_params": { "length": 32, "n": 16384, "r": 8, "p": 1 },
    "salt": "base64-encoded-salt",
    "cipher": "fernet",
    "created_at": "...",
    "updated_at": "..."
  },
  "body": "fernet-token-as-text"
}
```

### In memory

Unlocked vault holds:
- header
- decrypted body
- derived Fernet key

Locked vault holds none of those session objects.

---

## Error Handling Strategy

All expected application errors inherit from `VaultError`. The CLI catches these and prints safe messages without tracebacks.

Important error types:
- `VaultAlreadyExistsError`
- `VaultNotFoundError`
- `VaultFormatError`
- `VaultConflictError`
- `SchemaError`
- `KDFError`
- `EncryptionError`
- `DecryptionError`
- `EntryNotFoundError`
- `AmbiguousEntryError`
- `VaultSessionLockedError`
- `VaultWriteLockError`

---

## External Dependencies

### Runtime

- `cryptography>=42,<45`

### Development

- pytest
- pytest-cov
- hypothesis
- ruff
- mypy
- pre-commit

---

## Concurrency Model

The app is synchronous. Mutating CLI commands acquire a `WriteLock`. Library writes also check the on-disk revision while holding the lock. The lock is same-directory, best-effort, and includes stale-lock cleanup.

There are no background services, daemons, network calls, or async tasks.

---

## Known Limitations

- No cloud sync.
- No browser integration.
- No secure memory wiping guarantee in CPython.
- Metadata remains visible.
- Weak master passwords remain vulnerable offline.
- No hardware security key integration.
- No multi-user sharing.
- No automatic backup.
- Locking is local filesystem best-effort.

---

## Verification Summary

The repo documents tests for:
- crypto round-trip and tamper detection
- single cryptography import boundary
- atomic write safety
- schema and serializer behavior
- serializer property round trips
- vault lifecycle and session rules
- revision conflicts
- golden fixture compatibility
- CLI safety and helpers

CI runs on Ubuntu, Windows, and macOS for Python 3.10 and 3.12, with Ruff, mypy, pytest coverage, pre-commit, and lockfile verification.

---

*Constitution reference: Article 4 (engineering quality), Article 6 (behavior verification), Article 7 (progressive complexity), and Article 8 (valid learner work).*

---


# Interface Design Specification
## App — Password Manager
**Security Tools Group | Document 3 of 5**

---

## Public CLI Interface

### Module invocation

```powershell
python -m password_manager --vault demo.pwv <command> [options]
```

### Console script

```powershell
pwvault --vault demo.pwv <command> [options]
```

Global option:

| Option | Default | Description |
|---|---|---|
| `--vault PATH` | `vault.pwv` | Vault file path |
| `--version` | none | Print version |

---

## CLI Commands

| Command | Purpose |
|---|---|
| `init` | Create a new encrypted vault; refuses existing file |
| `add` | Add entry |
| `list` | Show safe summaries only |
| `get` | Show one entry with masked secrets unless requested |
| `update` | Partial entry update |
| `delete` | Delete one entry |
| `search` | Search service, username, URL, and notes |
| `check` | Verify master password and schema validity |
| `lock` | Verify master password and exit with no session kept |
| `change-password` | Rotate master password and salt |
| `generate` | Generate standalone password without vault |

---

## Command Syntax

### Initialize

```powershell
python -m password_manager --vault demo.pwv init
```

Prompts:
- `New master password:`
- `Confirm master password:`

Rules:
- minimum 12 characters
- refuses existing vault

---

### Add entry

```powershell
python -m password_manager --vault demo.pwv add github --username you --generate --length 20
```

Options:
- `--username TEXT` required
- `--url TEXT`
- `--notes-prompt`
- `--generate`
- generator options

Without `--generate`, the entry password is prompted through `getpass`.

---

### List entries

```powershell
python -m password_manager --vault demo.pwv list
```

Output columns:
- ID
- SERVICE
- USERNAME
- URL

No password or notes are printed.

---

### Get entry

```powershell
python -m password_manager --vault demo.pwv get github
python -m password_manager --vault demo.pwv get github --reveal
python -m password_manager --vault demo.pwv get github --details
```

Default output masks password and notes.

---

### Update entry

```powershell
python -m password_manager --vault demo.pwv update github --username new-name
python -m password_manager --vault demo.pwv update github --password-prompt
python -m password_manager --vault demo.pwv update github --generate --length 24
python -m password_manager --vault demo.pwv update github --notes-prompt
```

Rules:
- at least one update must be supplied
- `--password-prompt` and `--generate` are mutually exclusive

---

### Delete entry

```powershell
python -m password_manager --vault demo.pwv delete github
python -m password_manager --vault demo.pwv delete github --yes
```

Without `--yes`, confirmation is requested before master-password prompt.

---

### Search entries

```powershell
python -m password_manager --vault demo.pwv search github
```

Searches:
- service
- username
- URL
- notes

Returns safe summaries.

---

### Check vault

```powershell
python -m password_manager --vault demo.pwv check
```

Expected success:

```text
OK: vault decrypted and validated
```

---

### Lock command

```powershell
python -m password_manager --vault demo.pwv lock
```

Expected success:

```text
OK: master password verified (no session kept).
```

---

### Change master password

```powershell
python -m password_manager --vault demo.pwv change-password
```

Prompts:
- current master password
- new master password
- confirmation

---

### Generate standalone password

```powershell
python -m password_manager generate --length 20
```

Generator options:
- `--length INT`
- `--no-uppercase`
- `--no-lowercase`
- `--no-digits`
- `--no-symbols`

Rules:
- length must be at least 12
- at least one character class must remain enabled

---

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Success; includes cancelled delete |
| `1` | Vault error, validation error, ambiguous entry, or value error |
| `2` | Usage error from argparse |
| `130` | Interrupted by Ctrl-C |

---

## Public Python API

### Import

```python
from password_manager import Vault, EntryCreate, EntryUpdate, KDFParams
```

Public exports include:
- `Vault`
- `Entry`
- `EntryCreate`
- `EntrySummary`
- `EntryUpdate`
- `KDFParams`
- expected error types
- `__version__`

---

### Initialize and add entry

```python
from password_manager import Vault, EntryCreate

vault = Vault("demo.pwv")
vault.initialize("correct horse battery staple")
vault.add_entry(
    EntryCreate(
        service="github",
        username="you",
        password="generated-or-entered-secret",
        url="https://github.com",
    )
)
```

---

### Unlock and read

```python
vault = Vault("demo.pwv")
vault.unlock("correct horse battery staple")
for item in vault.list_entries():
    print(item.service, item.username)
```

---

### Update

```python
vault.update_entry("github", EntryUpdate(username="new-user"))
```

---

### Delete

```python
vault.delete_entry("github")
```

---

### Change master password

```python
vault.change_master_password(
    old_password="correct horse battery staple",
    new_password="new correct horse battery staple",
)
```

Optional KDF upgrade:

```python
vault.change_master_password(old, new, kdf_params=KDFParams(n=2**15))
```

---

## Input Contracts

### Master password

- must be text
- must be non-empty
- must be at least 12 characters
- never accepted as a CLI argument

### Entry password

- generated passwords must be at least 12 characters
- manually entered entry passwords only need to be non-empty

### Entry service and username

- text
- non-empty
- not blank after stripping

### Entry notes

- optional text
- can be hidden through `--notes-prompt`

---

## Output Contracts

### Safe summary output

```text
ID                                   SERVICE              USERNAME             URL
<uuid>                               github               you                  https://github.com
```

### Masked get output

```text
password: ********
notes: ********
```

### Revealed get output

Only with:

```powershell
--reveal
```

### Details output

Only notes display with:

```powershell
--details
```

---

## File Format Contract

Top-level JSON envelope:

```json
{
  "header": { ... },
  "body": "fernet-token-as-text"
}
```

Header fields:
- `format`
- `version`
- `revision`
- `kdf`
- `kdf_params`
- `salt`
- `cipher`
- `created_at`
- `updated_at`

Encrypted body contains:
- body version
- list of entries

---

## Side Effects

| Operation | Side Effect |
|---|---|
| `init` | Creates vault file |
| `add` | Writes new encrypted body and increments revision |
| `update` | Writes changed encrypted body and increments revision |
| `delete` | Writes encrypted body without deleted entry and increments revision |
| `change-password` | Generates new salt, re-encrypts body, writes header/body |
| `generate` | Prints generated password; no vault file touched |
| `check`/`lock` | Reads/decrypts/validates vault; no write |

---

*Constitution reference: Article 4 (input/output boundaries), Article 6 (verification), and Article 8 (understandable and verifiable work).*

---


# Runbook
## App — Password Manager
**Security Tools Group | Document 4 of 5**

---

## Requirements

### Runtime

- Python 3.10 or newer
- `cryptography>=42,<45`

### Development

- pytest
- pytest-cov
- hypothesis
- ruff
- mypy
- pre-commit

---

## Installation

### Runtime/editable install

```powershell
python -m pip install -e .
```

### Development install

```powershell
python -m pip install -e ".[dev]"
```

### Reproducible grading install

```powershell
python -m pip install -r requirements-lock.txt
python -m pip install -e .
```

---

## Smoke Test

```powershell
python -m password_manager --vault demo.pwv init
python -m password_manager --vault demo.pwv add github --username you --generate --length 20
python -m password_manager --vault demo.pwv list
python -m password_manager --vault demo.pwv check
```

Expected:
- vault is created
- generated password is not echoed during add
- list shows safe summary only
- check prints `OK: vault decrypted and validated`

---

## Standard Operating Procedures

### Create a new vault

```powershell
python -m password_manager --vault vault.pwv init
```

Use a strong passphrase of at least 12 characters.

---

### Add an entry with generated password

```powershell
python -m password_manager --vault vault.pwv add github --username you --generate --length 24
```

---

### Add notes without echoing them

```powershell
python -m password_manager --vault vault.pwv add github --username you --generate --notes-prompt
```

---

### List entries safely

```powershell
python -m password_manager --vault vault.pwv list
```

---

### Reveal one password

```powershell
python -m password_manager --vault vault.pwv get github --reveal
```

Use only when the terminal is private.

---

### Show notes explicitly

```powershell
python -m password_manager --vault vault.pwv get github --details
```

---

### Update an entry

```powershell
python -m password_manager --vault vault.pwv update github --username new-user
python -m password_manager --vault vault.pwv update github --generate --length 24
```

---

### Delete an entry

```powershell
python -m password_manager --vault vault.pwv delete github
```

To skip confirmation:

```powershell
python -m password_manager --vault vault.pwv delete github --yes
```

---

### Search entries

```powershell
python -m password_manager --vault vault.pwv search git
```

---

### Verify vault health

```powershell
python -m password_manager --vault vault.pwv check
```

---

### Change master password

```powershell
python -m password_manager --vault vault.pwv change-password
```

---

## Running Tests

```powershell
python -m pytest
```

Coverage gate:

```text
>= 90% on password_manager package
```

---

## Running Quality Checks

```powershell
ruff check password_manager tests
mypy password_manager
pre-commit run --all-files
```

---

## CI Parity

The CI workflow runs:
- Ubuntu, Windows, macOS
- Python 3.10 and 3.12
- package install with dev tools
- Ruff
- mypy
- pytest with coverage
- pre-commit on Python 3.12
- lockfile install verification on Python 3.12

---

## Health Checks

### CLI import

```powershell
python -m password_manager --help
```

Expected:
- help output appears

---

### Script entry point

```powershell
pwvault --help
```

Expected:
- help output appears if Python Scripts directory is on PATH

---

### Vault check

```powershell
python -m password_manager --vault vault.pwv check
```

Expected:
```text
OK: vault decrypted and validated
```

---

### Golden fixture

Use fixture:

```text
tests/fixtures/golden.pwv
```

Master password:

```text
golden-password
```

Expected:
- decrypts and validates under test suite

---

## Known Failure Modes

### Wrong master password

Expected:
```text
ERROR: decryption failed
```

Meaning:
- password wrong, ciphertext invalid, or vault tampered
- intentionally same safe message

---

### Vault file missing

Expected:
```text
ERROR: vault file does not exist
```

Resolution:
- check `--vault` path
- run `init` to create new vault

---

### Vault already exists

Expected during init:
```text
ERROR: vault file already exists
```

Resolution:
- choose another `--vault` path
- do not overwrite without backup

---

### Ambiguous service name

Trigger:
- multiple entries share same service
- user tries `get service` instead of UUID

Resolution:
- use one of the printed UUIDs

---

### Vault conflict

Expected:
```text
ERROR: vault was modified by another process; re-open and retry
```

Resolution:
- close stale sessions
- rerun command
- reload library `Vault` instance

---

### Vault locked by another writer

Expected:
```text
ERROR: vault is locked by another writer
```

Resolution:
- wait for the other command to finish
- investigate stale lock if process crashed

---

### Generated password too short

Expected:
```text
ERROR: password length must be at least 12
```

Resolution:
- use `--length 12` or higher

---

### No character classes enabled

Trigger:
```powershell
--no-uppercase --no-lowercase --no-digits --no-symbols
```

Resolution:
- keep at least one class enabled

---

## Troubleshooting Decision Tree

```text
Command fails
  ├── Usage error?
  │     └── Check command syntax and required flags
  ├── Vault missing?
  │     └── Check --vault path or run init
  ├── Decryption failed?
  │     ├── Re-enter master password
  │     ├── Check correct vault file
  │     └── Treat as possible corruption/tamper
  ├── Ambiguous entry?
  │     └── Use UUID instead of service name
  ├── Writer lock error?
  │     └── Wait and retry; inspect stale lock if needed
  ├── Conflict error?
  │     └── Re-open vault and retry
  └── Schema/format error?
        └── Restore from backup; do not trust partial data
```

---

## Recovery Procedures

### Recover from accidental terminal exposure

1. Assume exposed password/notes are compromised.
2. Change the password at the service.
3. Update vault entry.
4. Clear terminal scrollback if appropriate.

---

### Recover from corrupted vault file

1. Do not manually edit the vault further.
2. Restore from backup if available.
3. Run `check` after restoration.
4. If no backup exists, treat vault contents as unrecoverable unless the master password and ciphertext are intact.

---

### Recover from stale lock

The lock layer attempts stale-lock cleanup. If the lock persists:
1. Confirm no active `pwvault` process is running.
2. Confirm the lock file is stale.
3. Remove the `.vaultname.lock` file carefully.
4. Run `check` before mutating the vault again.

---

### Recover from lost master password

There is no recovery path. This is expected for a local encrypted vault.

---

## Maintenance Notes

- Keep `cryptography` imports isolated to `crypto_engine.py`.
- Preserve generic decryption failure messages.
- Do not add command-line master-password flags.
- Keep list/search outputs secret-free.
- Keep schema limits conservative.
- Add tests before changing vault format.
- Preserve golden fixture compatibility or document format migration.
- Run tests on Windows behavior when changing lockfile code.
- Keep threat-model limitations visible in docs.

---

*Constitution reference: Article 6 (behavior verification), Article 5 (constraints and trade-offs), and Article 8 (verifiable learner work).*

---


# Lessons Learned
## App — Password Manager
**Security Tools Group | Document 5 of 5**

---

## Why This Design Was Chosen

This design was chosen because a password manager forces a stronger boundary mindset than ordinary CRUD tools. Data is not merely stored; it must be encrypted, validated, written safely, and displayed carefully. The project’s value comes from those boundaries.

The strongest design choice was isolating crypto. `crypto_engine.py` is the only place that imports `cryptography`, which makes the security surface easier to review. The rest of the app treats cryptography through a small interface: derive key, encrypt, decrypt, generate salt.

The second important choice was fail-closed loading. The vault does not use parsed data merely because JSON decoding succeeded. It validates the header, ciphertext size, decrypted body, entry IDs, timestamps, and field lengths. If any layer fails, the vault does not partially trust the file.

The third important choice was avoiding CLI secret flags. A CLI password manager can easily leak secrets through shell history or process listings. Prompting is less convenient, but safer.

---

## What Was Intentionally Omitted

**Cloud sync:** Out of scope because sync adds accounts, remote storage, merge conflicts, and network threat modeling.

**Autofill/browser extension:** Out of scope for a CLI/library project.

**Secure memory wiping:** CPython strings cannot be reliably wiped; the app documents this instead of pretending otherwise.

**Master-password recovery:** Not compatible with local-only encryption without adding escrow or recovery secrets.

**Secrets manager integration:** This app is the vault, not an adapter to external vaults.

**Multi-user sharing:** Out of scope.

**Argon2:** Could be a future KDF option, but scrypt was sufficient for the academic scope.

---

## Biggest Weakness

The biggest weakness is memory exposure. Once unlocked, decrypted entries and derived keys exist in Python memory. The app can drop references with `lock()`, but it cannot guarantee memory wiping. Malware, debuggers, memory scraping, and compromised machines are outside the protection boundary.

The second weakness is metadata exposure. Header fields, file size, mtime, and Fernet token timing remain visible. Hiding all metadata would require a more complex design.

The third weakness is user password quality. scrypt slows offline guessing, but weak master passwords remain attackable.

---

## Scaling Considerations

**If the vault grows large:**
- entry count and decrypted body size limits already exist
- consider paging or per-record encryption only with a new ADR
- preserve schema validation before trust

**If cloud sync is added:**
- design identity, sync metadata, conflict resolution, and remote threat model
- keep local encryption independent of transport
- add explicit revision/vector logic

**If KDF upgrades become CLI-visible:**
- expose safe presets, not raw parameters
- preserve schema bounds
- document migration behavior

**If GUI/TUI is added:**
- keep CLI-safe display defaults
- preserve no-command-line-secret rule
- avoid logging revealed secrets

---

## What the Next Refactor Would Be

1. **Add CLI KDF upgrade preset** — allow `change-password --kdf stronger` without exposing raw scrypt internals.

2. **Add export/import with explicit warning banners** — only if encrypted export semantics are defined clearly.

3. **Add audit-style local operation log** — keep it metadata-only and avoid secret content.

4. **Add backup guidance** — document safe backup workflow for encrypted vault files.

5. **Add format migration hooks** — prepare for future header/body version changes.

---

## What This Project Taught

- **Security architecture is boundary design.** Crypto, storage, schema, CLI, and session state each need a clear responsibility.

- **Fail-closed behavior is a product feature.** Bad decrypt, parse, or schema data must not leak partial state.

- **Safe defaults matter.** Masking output and avoiding command-line secret arguments reduce accidental exposure.

- **Local file persistence is tricky.** Atomic writes, fsync, locks, stale-lock cleanup, and revision checks are all needed for a serious local tool.

- **Documentation must include limits.** A portfolio security project should be honest about memory, metadata, weak passwords, and malware.

- **Tests enforce architecture.** The test suite does more than check outputs; it enforces crypto import isolation, golden fixture compatibility, lock behavior, schema limits, CLI safety, and revision conflicts.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation), Article 6 (verification), and Article 7 (progressive complexity) for Password Manager.*
