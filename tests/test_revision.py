"""Test revision functionality."""

from pathlib import Path

import pytest

from password_manager.errors import VaultConflictError, VaultNotFoundError
from password_manager.models import EntryCreate
from password_manager.vault import Vault


def test_concurrent_revision_conflict(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    first = Vault(path)
    first.initialize("master password 1")
    first.add_entry(EntryCreate("github", "user", "secret"))

    second = Vault(path)
    second.unlock("master password 1")

    first.unlock("master password 1")
    first.add_entry(EntryCreate("gitlab", "user", "secret2"))

    with pytest.raises(VaultConflictError):
        second.add_entry(EntryCreate("bitbucket", "user", "secret3"))


def test_save_after_vault_file_deleted_raises(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.add_entry(EntryCreate("github", "user", "secret"))
    path.unlink()

    with pytest.raises(VaultNotFoundError):
        vault.add_entry(EntryCreate("gitlab", "user", "secret2"))
