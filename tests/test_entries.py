"""Test entry functionality."""

from pathlib import Path

import pytest

from password_manager.errors import AmbiguousEntryError, EntryNotFoundError
from password_manager.models import EntryCreate, EntryUpdate
from password_manager.vault import Vault


def unlocked_vault(tmp_path: Path) -> Vault:
    vault = Vault(tmp_path / "vault.pwv")
    vault.initialize("master password")
    return vault


def test_crud_search_and_safe_summaries(tmp_path: Path):
    vault = unlocked_vault(tmp_path)
    entry = vault.add_entry(
        EntryCreate(
            service="github",
            username="user",
            password="entry secret",
            url="https://github.com",
            notes="recovery code",
        )
    )

    summaries = vault.list_entries()
    assert summaries[0].id == entry.id
    assert not hasattr(summaries[0], "password")
    assert not hasattr(summaries[0], "notes")

    assert vault.get_entry(entry.id).password == "entry secret"
    assert vault.search("git")[0].id == entry.id
    assert vault.search("github.com")[0].id == entry.id
    assert vault.search("recovery")[0].id == entry.id

    with pytest.raises(ValueError, match="must not be empty"):
        vault.search("")

    updated = vault.update_entry(entry.id, EntryUpdate(username="new-user", password="new secret"))
    assert updated.username == "new-user"
    assert updated.password == "new secret"

    vault.delete_entry(entry.id)

    with pytest.raises(EntryNotFoundError):
        vault.get_entry(entry.id)


def test_duplicate_service_requires_id(tmp_path: Path):
    vault = unlocked_vault(tmp_path)
    first = vault.add_entry(EntryCreate("github", "one", "secret 1"))
    second = vault.add_entry(EntryCreate("github", "two", "secret 2"))

    with pytest.raises(AmbiguousEntryError):
        vault.get_entry("github")

    assert vault.get_entry(first.id).username == "one"
    assert vault.get_entry(second.id).username == "two"
