"""Test CLI internal functions."""

import argparse
from unittest.mock import patch

import pytest

from password_manager import cli
from password_manager.errors import DecryptionError


def test_run_readonly_unknown_command(vault_with_entry, master_password):
    args = argparse.Namespace(command="not-a-real-command")
    with pytest.raises(ValueError, match="unknown command"):
        cli._run_readonly_command(vault_with_entry, args)


def test_run_readonly_get_notes_masked(vault_with_entry, master_password, capsys):
    args = argparse.Namespace(command="get", entry="github", reveal=False, details=False)
    cli._run_readonly_command(vault_with_entry, args)
    out = capsys.readouterr().out
    assert "notes: ********" in out


def test_updates_from_args_with_generate(monkeypatch):
    args = argparse.Namespace(
        password_prompt=False,
        generate=True,
        notes_prompt=False,
        service=None,
        username=None,
        url=None,
        length=12,
        no_uppercase=False,
        no_lowercase=False,
        no_digits=False,
        no_symbols=True,
    )
    updates = cli._updates_from_args(args)
    assert updates.password is not None
    assert len(updates.password) == 12


def test_unlock_vault_error_clears_session(vault_path, master_password):
    from password_manager.vault import Vault

    vault = Vault(vault_path)
    vault.initialize(master_password)
    with patch.object(vault, "_load_unlocked_state", side_effect=DecryptionError("failed")):
        with pytest.raises(DecryptionError):
            vault.unlock("wrong-password-99")
    assert not vault.is_unlocked()
