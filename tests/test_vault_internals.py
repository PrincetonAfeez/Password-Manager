"""Test vault internals."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from password_manager.errors import (
    DecryptionError,
    VaultConflictError,
    VaultNotFoundError,
    VaultSessionLockedError,
)
from password_manager.vault import Vault


def test_ensure_revision_raises_when_file_missing(vault_path, master_password):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    header = vault._require_header()
    with patch.object(vault.store, "exists", return_value=False):
        with pytest.raises(VaultNotFoundError):
            vault._ensure_revision_current(header)


def test_ensure_revision_raises_on_mismatch(vault_with_entry, master_password):
    vault = vault_with_entry
    stale_header = replace(vault._require_header(), revision=0)
    with pytest.raises(VaultConflictError):
        vault._ensure_revision_current(stale_header)


def test_verify_unlocked_password_rejects_wrong_key(vault_with_entry, master_password):
    with pytest.raises(DecryptionError):
        vault_with_entry._verify_unlocked_password("wrong-password99")


def test_required_text_and_password_type_checks(vault_path, master_password):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    with pytest.raises(ValueError, match="must be text"):
        vault._require_password(123)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="must not be empty"):
        vault._require_password("")
    with pytest.raises(ValueError, match="field"):
        vault._required_text("", "field")
    with pytest.raises(ValueError, match="must not be blank"):
        vault._required_text("   ", "service")


def test_require_key_body_header_when_locked(vault_path, master_password):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    vault.lock()
    with pytest.raises(VaultSessionLockedError):
        vault._require_key()
    with pytest.raises(VaultSessionLockedError):
        vault._require_body()
    with pytest.raises(VaultSessionLockedError):
        vault._require_header()
