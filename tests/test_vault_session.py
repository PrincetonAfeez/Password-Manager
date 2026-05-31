"""Test vault session functionality."""

from pathlib import Path

import pytest

from password_manager.errors import DecryptionError
from password_manager.models import EntryCreate
from password_manager.vault import Vault


def test_unlock_wrong_password_clears_unlocked_session(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.add_entry(EntryCreate("github", "user", "entry secret"))
    vault.unlock("master password 1")

    with pytest.raises(DecryptionError):
        vault.unlock("wrong password 99")

    assert not vault.is_unlocked()


def test_verify_password_does_not_unlock_vault(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.lock()

    assert vault.verify_password("master password 1") is True
    assert not vault.is_unlocked()


def test_verify_password_preserves_unlocked_session(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.unlock("master password 1")

    assert vault.verify_password("master password 1") is True
    assert vault.is_unlocked()


def test_verify_password_wrong_password_clears_unlocked_session(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.add_entry(EntryCreate("github", "user", "entry secret"))
    vault.unlock("master password 1")

    with pytest.raises(DecryptionError):
        vault.verify_password("wrong password 99")

    assert not vault.is_unlocked()


def test_check_does_not_unlock_vault(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.lock()

    assert vault.check("master password 1") is True
    assert not vault.is_unlocked()


def test_change_master_password_wrong_old_clears_unlocked_session(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("master password 1")
    vault.add_entry(EntryCreate("github", "user", "entry secret"))
    vault.unlock("master password 1")

    with pytest.raises(DecryptionError):
        vault.change_master_password("wrong password 99", "new password 12")

    assert not vault.is_unlocked()


def test_change_master_password_while_unlocked_preserves_entries(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize("old password 12")
    entry = vault.add_entry(EntryCreate("github", "user", "entry secret"))

    vault.change_master_password("old password 12", "new password 12")

    assert vault.is_unlocked()
    assert vault.get_entry(entry.id).password == "entry secret"

    with pytest.raises(DecryptionError):
        Vault(path).unlock("old password 12")

    reopened = Vault(path)
    reopened.unlock("new password 12")
    assert reopened.get_entry(entry.id).password == "entry secret"
