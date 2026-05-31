"""Test vault functionality."""

from pathlib import Path
from uuid import UUID

import pytest

from password_manager.errors import (
    AmbiguousEntryError,
    DecryptionError,
    EntryNotFoundError,
    VaultAlreadyExistsError,
    VaultSessionLockedError,
)
from password_manager.models import EntryCreate, EntryUpdate
from password_manager.vault import Vault


def test_initialize_leaves_vault_unlocked(vault_path: Path, master_password: str):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    assert vault.is_unlocked()


def test_initialize_twice_raises(vault_path: Path, master_password: str):
    Vault(vault_path).initialize(master_password)
    with pytest.raises(VaultAlreadyExistsError):
        Vault(vault_path).initialize(master_password)


def test_all_crud_methods(vault_with_entry: Vault, master_password: str):
    vault = vault_with_entry
    entry = vault.get_entry("github")
    assert entry.username == "demo"

    by_id = vault.get_entry(entry.id)
    assert by_id.id == entry.id

    matches = vault.find_matching_entries("github")
    assert len(matches) == 1

    vault.update_entry(
        entry.id,
        EntryUpdate(
            service="gitlab",
            username="new",
            password="newpw",
            url="https://g.com",
            notes="n2",
        ),
    )
    updated = vault.get_entry("gitlab")
    assert updated.password == "newpw"
    assert updated.url == "https://g.com"

    results = vault.search("gitlab")
    assert len(results) == 1

    vault.delete_entry(entry.id)
    assert vault.list_entries() == []


def test_get_entry_by_uuid(vault_with_entry: Vault):
    entry = vault_with_entry.list_entries()[0]
    loaded = vault_with_entry.get_entry(entry.id)
    assert UUID(loaded.id)


def test_update_entry_no_changes(vault_with_entry: Vault):
    with pytest.raises(ValueError, match="no updates provided"):
        vault_with_entry.update_entry("github", EntryUpdate())


def test_add_entry_rejects_empty_fields(vault_with_entry: Vault):
    with pytest.raises(ValueError, match="service"):
        vault_with_entry.add_entry(EntryCreate("", "u", "p"))
    with pytest.raises(ValueError, match="username"):
        vault_with_entry.add_entry(EntryCreate("s", "", "p"))
    with pytest.raises(ValueError, match="password"):
        vault_with_entry.add_entry(EntryCreate("s", "u", ""))


def test_master_password_validation(vault_path: Path):
    vault = Vault(vault_path)
    with pytest.raises(ValueError, match="must not be empty"):
        vault.initialize("")
    with pytest.raises(ValueError, match="at least"):
        vault.initialize("short")


def test_session_locked_errors(vault_path: Path, master_password: str):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    vault.lock()
    with pytest.raises(VaultSessionLockedError):
        vault.add_entry(EntryCreate("s", "u", "p"))
    with pytest.raises(VaultSessionLockedError):
        vault.list_entries()
    with pytest.raises(VaultSessionLockedError):
        vault.get_entry("x")
    with pytest.raises(VaultSessionLockedError):
        vault.update_entry("x", EntryUpdate(username="a"))
    with pytest.raises(VaultSessionLockedError):
        vault.delete_entry("x")
    with pytest.raises(VaultSessionLockedError):
        vault.search("x")
    with pytest.raises(VaultSessionLockedError):
        vault.find_matching_entries("x")


def test_entry_not_found(vault_with_entry: Vault):
    with pytest.raises(EntryNotFoundError):
        vault_with_entry.get_entry("nonexistent-service")


def test_change_master_password_wrong_old_while_unlocked(
    vault_with_entry: Vault, master_password: str
):
    with pytest.raises(DecryptionError):
        vault_with_entry.change_master_password("wrong-password99", "new-password12")

    assert not vault_with_entry.is_unlocked()


def test_change_master_password_locked_path(vault_path: Path, master_password: str):
    vault = Vault(vault_path)
    vault.initialize(master_password)
    vault.add_entry(EntryCreate("s", "u", "p"))
    vault.lock()
    vault.change_master_password(master_password, "new-password-99")
    # Locked-path rotation now preserves prior lock state — vault stays locked.
    assert not vault.is_unlocked()
    vault.unlock("new-password-99")
    assert vault.get_entry("s").password == "p"


def test_change_master_password_rejects_reuse(vault_with_entry: Vault, master_password: str):
    with pytest.raises(ValueError, match="must differ"):
        vault_with_entry.change_master_password(master_password, master_password)


def test_change_master_password_upgrades_kdf(vault_path: Path, master_password: str):
    from password_manager.models import KDFParams

    vault = Vault(vault_path)
    vault.initialize(master_password)
    vault.add_entry(EntryCreate("s", "u", "p"))
    stronger = KDFParams(n=2**15)
    vault.change_master_password(master_password, "new-password-99", kdf_params=stronger)

    rotated = vault.store.read().header
    assert rotated.kdf_params.n == 2**15

    reopened = Vault(vault_path)
    reopened.unlock("new-password-99")
    assert reopened.get_entry("s").password == "p"


def test_update_entry_rollback_on_validation_failure(vault_with_entry: Vault):
    from password_manager.errors import SchemaError
    from password_manager.schema import MAX_NOTES_LENGTH

    original = vault_with_entry.list_entries()[0]
    original_notes = vault_with_entry.get_entry(original.id).notes

    with pytest.raises(SchemaError, match="notes"):
        vault_with_entry.update_entry(
            original.id, EntryUpdate(notes="x" * (MAX_NOTES_LENGTH + 1))
        )

    # Original state preserved — schema rejection didn't mutate the live entry.
    after = vault_with_entry.get_entry(original.id)
    assert after.notes == original_notes
    assert after.updated_at == original.updated_at


def test_get_entry_returns_defensive_copy(vault_with_entry: Vault):
    snapshot = vault_with_entry.get_entry("github")
    snapshot_id = snapshot.id

    # The returned Entry is frozen, so any attempted mutation raises and
    # in-memory state is unaffected — verify via a second read.
    second = vault_with_entry.get_entry(snapshot_id)
    assert second.password == snapshot.password
    assert second is not snapshot  # different objects


def test_custom_dependencies(tmp_path: Path):
    from password_manager.crypto_engine import CryptoEngine
    from password_manager.schema import VaultSchema
    from password_manager.serializer import VaultSerializer

    vault = Vault(
        tmp_path / "v.pwv",
        crypto=CryptoEngine(),
        serializer=VaultSerializer(),
        schema=VaultSchema(),
    )
    vault.initialize("custom-deps-12")
    assert vault.is_unlocked()


def test_update_url_and_notes_only(vault_with_entry: Vault):
    entry = vault_with_entry.list_entries()[0]
    updated = vault_with_entry.update_entry(
        entry.id,
        EntryUpdate(url="https://updated.example", notes="updated notes"),
    )
    assert updated.url == "https://updated.example"
    assert updated.notes == "updated notes"


def test_ambiguous_entry_includes_summaries(vault_with_entry: Vault):
    vault_with_entry.add_entry(EntryCreate("github", "two", "pw2"))
    with pytest.raises(AmbiguousEntryError) as exc_info:
        vault_with_entry.get_entry("github")
    assert len(exc_info.value.entries) == 2
