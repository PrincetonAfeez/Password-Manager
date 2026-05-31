# Test suite

Run: `python -m pytest` (coverage gate ≥90% on `password_manager`).

| Module | Test files |
| --- | --- |
| `vault.py` | `test_vault_lifecycle.py`, `test_vault_session.py`, `test_vault_complete.py`, `test_vault_internals.py`, `test_entries.py`, `test_revision.py` |
| `cli.py` | `test_cli.py`, `test_cli_helpers.py`, `test_cli_internals.py` |
| `crypto_engine.py` | `test_crypto_engine.py`, `test_crypto_engine_complete.py` |
| `schema.py` | `test_serializer_schema.py`, `test_schema_limits.py`, `test_schema_complete.py` |
| `serializer.py` | `test_serializer_schema.py`, `test_serializer_complete.py`, `test_serializer_property.py` |
| `store.py` | `test_store.py`, `test_store_complete.py` |
| `lockfile.py` | `test_store.py`, `test_lockfile_complete.py` |
| `atomic.py` | `test_atomic.py`, `test_atomic_complete.py` |
| `generator.py` | `test_generator.py`, `test_generator_complete.py` |
| `models.py` / `errors.py` | `test_models.py`, `test_errors.py` |
| Package / security | `test_package.py`, `test_security.py`, `test_golden_vault.py` |

Shared fixtures: `conftest.py`.
