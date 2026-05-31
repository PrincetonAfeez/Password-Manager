"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from password_manager.models import EntryCreate
from password_manager.vault import Vault

MASTER = "master password 12"


@pytest.fixture
def master_password() -> str:
    return MASTER


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "vault.pwv"


@pytest.fixture
def unlocked_vault(vault_path: Path, master_password: str) -> Vault:
    vault = Vault(vault_path)
    vault.initialize(master_password)
    return vault


@pytest.fixture
def vault_with_entry(unlocked_vault: Vault) -> Vault:
    unlocked_vault.add_entry(
        EntryCreate(
            service="github",
            username="demo",
            password="entry-password",
            url="https://github.com",
            notes="demo notes",
        )
    )
    return unlocked_vault
