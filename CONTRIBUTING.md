# Contributing

## Development setup

```powershell
python -m pip install -e ".[dev]"
pre-commit install
```

## Checks before a PR or submission

These run in CI (matrix on 3.10/3.12 × Ubuntu/Windows/macOS, plus pre-commit and lockfile jobs):

```powershell
ruff check password_manager tests
mypy password_manager
python -m pytest
pre-commit run --all-files
```

## Regenerating the lockfile

Use Python 3.10 or 3.12 (matches CI). From a clean venv:

```powershell
python -m pip install pip-tools
python -m piptools compile requirements-dev.txt -o requirements-lock.txt --strip-extras
```

Then run `python -m pytest` and commit `requirements-lock.txt`.

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
