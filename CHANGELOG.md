# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.1.2] - 2026-05-31

### Fixed

- `read_header()` now enforces `MAX_ENCRYPTED_BODY_BYTES` on the revision-check path.
- R8 session test for failed `change_master_password` re-auth in `test_vault_session.py`.

### Documentation & tooling

- REPORT: lockfile reproducer, stale-session limitation, lockfile Windows CI note.
- Additional lockfile helper tests; lockfile regenerated via `piptools compile`.

## [0.1.1] - 2026-05-31

### Security hardening

- Failed `verify_password()` / `check` clears any unlocked session (fail-closed).
- Failed `change_master_password()` re-authentication clears any unlocked session.
- Saving after the vault file was deleted raises `VaultNotFoundError` (no silent recreate).
- Vault write I/O failures surface as `VaultError` (CLI exit 1, no traceback).

### Fixed

- Empty or whitespace-only `search` queries rejected (`ValueError`); CLI validates before password prompt.
- CLI write-lock contention and persistence error paths covered by tests.

### Documentation & tooling

- Exit codes, library immutability, KDF library-only wording, CI badge, copyright.
- `requirements-lock.txt`, pre-commit CI job, lockfile install job on Python 3.12.
- REPORT platform caveats, expanded test map, R8/R11 traceability.
- README/SECURITY session fail-closed wording; CLI `lock` success message clarified.

## [0.1.0] - 2026-05-30

### Added

- Encrypted vault format (`py-password-vault` v1) with scrypt + Fernet.
- `Vault` library: init, unlock/lock, CRUD, search, master-password rotation.
- `pwvault` / `python -m password_manager` CLI with safe defaults.
- Atomic writes, write lock, header `revision` for concurrent-write detection.
- Schema validation, password generator, nine ADRs.
- Test suite with golden fixture, Hypothesis round-trip, CI (ruff, mypy, coverage).

### Security hardening (post-review)

- Failed `unlock()` clears prior in-memory session.
- `verify_password()` / `check` without forcing an unlocked session on success.
- `change_master_password()` preserves unlocked session when already open (on success).
- Master password minimum length (12 characters).
- Split `VaultSessionLockedError` / `VaultWriteLockError`; removed unused `ClipboardError`.
- Stale lock cleanup; directory fsync after atomic replace.
- CLI: init guard, documented `--generate`, ambiguous-entry summaries, `lock` command.

### Documentation

- `docs/ARCHITECTURE.md`, `docs/REPORT.md`, `SECURITY.md`, expanded README.
