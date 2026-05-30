# Contributing

## Development setup

```powershell
python -m pip install -e ".[dev]"
pre-commit install
```

## Checks before a PR or submission

```powershell
ruff check password_manager tests
mypy password_manager
python -m pytest
```

## Regenerating the golden vault fixture

```powershell
python scripts/generate_golden_vault.py
```

## Repository layout

| Path | Purpose |
| --- | --- |
| `password_manager/` | Library and CLI |
| `tests/` | Pytest suite |
| `docs/adr/` | Architecture decision records |
| `docs/ARCHITECTURE.md` | Layer diagram and data flow |
| `docs/REPORT.md` | Academic submission summary |

## GitHub topics (suggested)

`python`, `cryptography`, `security`, `cli`, `password-manager`, `portfolio`

## Rename clone folder (portfolio)

Prefer cloning as `local-password-manager` (no spaces) for clean URLs.
