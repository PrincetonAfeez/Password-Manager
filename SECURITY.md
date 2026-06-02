# Security Policy

## Supported scope

This project is a **local academic/portfolio** password vault. It is not audited for
production deployment. Report issues for learning and repository hygiene, not for a
paid bug bounty program.

## Reporting

If you discover a security concern:

1. **Do not** open a public issue with exploit details or real vault files.
2. Contact the repository owner privately (course instructor or GitHub private advisory).
3. Include steps to reproduce and impact on confidentiality/integrity.

## In scope

- Broken authenticated encryption or KDF bypass
- Secret leakage via default CLI output or logs
- Vault corruption on crash during write
- Session remaining unlocked after failed re-authentication (report regressions only)

**Mitigated today:** `unlock()`, `verify_password()` / `check`, and
`change_master_password()` call `lock()` on any re-authentication failure so an
unlocked session never survives a wrong password (`test_vault_session.py`,
`test_vault_complete.py`).
- Revision/lock bypass allowing silent data loss

## Out of scope

- Weak master passwords chosen by the user (length-only policy documented)
- Malware, keyloggers, or physical access to an unlocked machine
- Side-channel/timing attacks on offline unlock
- Denial of service via very large vault files (partially bounded by schema limits)

## Platform caveats

- **Directory fsync on Windows.** `atomic_write` calls `os.fsync` on the parent
  directory after `os.replace`. On POSIX this flushes the directory inode so the
  rename survives a crash; on Windows opening a directory fd is rejected, so the
  call silently no-ops. The `os.replace` itself remains atomic with respect to a
  crash, but durability of the directory entry is best-effort. Treat the "partial
  write corruption" mitigation as POSIX-only.
- **Write-lock stale recovery on Windows.** Liveness of the PID inside a `.lock`
  file is checked via `OpenProcess` + `GetExitCodeProcess` (see `lockfile.py`).
  `os.kill(pid, 0)` is **not** used on Windows because it maps to
  `TerminateProcess`, which would kill the holder. If a lock file contains an
  unparseable PID (e.g. a partial write from a crashed acquirer), the file is
  treated as stale and removed.

## Dependencies

Cryptography is delegated to the [`cryptography`](https://pypi.org/project/cryptography/)
package (see ADR 0001). Keep it updated via `pip install -U cryptography` in dev
environments; CI and `requirements-dev.txt` use version-bounded ranges
(`cryptography>=42,<45`). Exact pins for grading: [`requirements-lock.txt`](requirements-lock.txt).

## Repository hygiene

- **Never commit** real `*.pwv` vaults or master passwords.
- `tests/fixtures/golden.pwv` uses the documented test password `golden-password` only.
- Add `*.pwv` and `.*.lock` to `.gitignore` (already listed).
