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
- Session remaining unlocked after failed re-authentication
- Revision/lock bypass allowing silent data loss

## Out of scope

- Weak master passwords chosen by the user (length-only policy documented)
- Malware, keyloggers, or physical access to an unlocked machine
- Side-channel/timing attacks on offline unlock
- Denial of service via very large vault files (partially bounded by schema limits)

## Dependencies

Cryptography is delegated to the [`cryptography`](https://pypi.org/project/cryptography/)
package (see ADR 0001). Keep it updated via `pip install -U cryptography` in dev
environments; CI pins `cryptography>=42,<45`.

## Repository hygiene

- **Never commit** real `*.pwv` vaults or master passwords.
- `tests/fixtures/golden.pwv` uses the documented test password `golden-password` only.
- Add `*.pwv` and `.*.lock` to `.gitignore` (already listed).
