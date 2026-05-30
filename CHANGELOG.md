# Changelog

All notable changes to this project are documented here.

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
- `verify_password()` / `check` without forcing an unlocked session.
- `change_master_password()` preserves unlocked session when already open.
- Master password minimum length (12 characters).
- Split `VaultSessionLockedError` / `VaultWriteLockError`; removed unused `ClipboardError`.
- Stale lock cleanup; directory fsync after atomic replace.
- CLI: init guard, documented `--generate`, ambiguous-entry summaries, `lock` command.

### Documentation

- `docs/ARCHITECTURE.md`, `docs/REPORT.md`, `SECURITY.md`, expanded README.
