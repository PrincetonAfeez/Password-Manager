# ADR 0009: Concurrent Writer Policy

## Status

Accepted (updated 2026-05-30)

## Context

Multiple terminal sessions might run CLI commands against the same vault file.
We need to reduce lost updates without building a full distributed system.

## Decision

1. **Write lock file** — `.{vault}.lock` in the vault directory, acquired with `O_CREAT|O_EXCL`.
2. **Reentrant lock in one thread** — nested acquire (CLI session + `VaultStore.write`) must not deadlock.
3. **Stale lock recovery** — remove lock if owning PID is dead or file age exceeds 300 seconds.
4. **Header `revision`** — monotonic integer; every persist increments it after verifying disk matches memory.
5. **CLI scope** — mutating commands hold the write lock for the whole command after unlock.

## Consequences

- Two processes cannot reliably interleave long edit sessions; last writer wins if revision checks are bypassed.
- A crash may leave a lock until stale cleanup or manual deletion.
- Readers do not take the lock; `os.replace` still gives readers atomic file snapshots.

## Alternatives considered

- Database backend — out of scope for local academic project.
- File locking APIs only (no revision) — insufficient to detect stale in-memory state.
