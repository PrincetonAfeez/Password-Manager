"""Test vault lifecycle."""

from pathlib import Path

import pytest

from password_manager.errors import DecryptionError, VaultAlreadyExistsError
from password_manager.models import EntryCreate
from password_manager.vault import Vault


def test_initialize_unlock_and_check(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)

    vault.initialize("master password")
    vault.lock()
    vault.unlock("master password")

    assert vault.is_unlocked()
    vault.lock()
    assert vault.verify_password("master password") is True
    assert not vault.is_unlocked()


def test_initialize_refuses_overwrite(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize("master password")

    with pytest.raises(VaultAlreadyExistsError):
        Vault(path).initialize("master password")


def test_wrong_password_and_corrupt_body_fail(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize("master password")

    with pytest.raises(DecryptionError):
        Vault(path).unlock("wrong password")

    data = path.read_text(encoding="utf-8")
    path.write_text(data.replace("gAAAA", "gAAAB", 1), encoding="utf-8")

    with pytest.raises(DecryptionError):
        Vault(path).unlock("master password")


def test_change_password_rotates_key_and_preserves_entries(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("old password")
    entry = vault.add_entry(EntryCreate("github", "user", "entry secret"))
    old_salt = vault.store.read().header.salt

    vault.change_master_password("old password", "new password")

    with pytest.raises(DecryptionError):
        Vault(path).unlock("old password")

    reopened = Vault(path)
    reopened.unlock("new password")

    assert reopened.get_entry(entry.id).password == "entry secret"
    assert reopened.store.read().header.salt != old_salt
