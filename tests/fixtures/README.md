# Test fixtures

## `golden.pwv`

Encrypted sample vault for graders and integration tests.

| Field | Value |
| --- | --- |
| Master password | `golden-password` |
| Entry service | `example.com` |
| Entry username | `demo-user` |

Regenerate after format changes:

```powershell
python scripts/generate_golden_vault.py
```

Verify:

```powershell
python -m password_manager --vault tests/fixtures/golden.pwv check
```
