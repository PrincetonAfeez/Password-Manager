"""Test models functionality."""

from datetime import datetime, timezone

from password_manager.models import (
    EntryCreate,
    EntrySummary,
    EntryUpdate,
    KDFParams,
    StoredVault,
    VaultBody,
    VaultHeader,
    utc_now,
)


def test_utc_now_is_timezone_aware():
    value = utc_now()
    assert value.tzinfo is not None
    assert value.utcoffset() is not None


def test_entry_update_has_changes_false():
    assert not EntryUpdate().has_changes()


def test_entry_update_has_changes_true_for_each_field():
    assert EntryUpdate(service="x").has_changes()
    assert EntryUpdate(username="x").has_changes()
    assert EntryUpdate(password="x").has_changes()
    assert EntryUpdate(url="").has_changes()
    assert EntryUpdate(notes="").has_changes()


def test_dataclass_defaults():
    params = KDFParams()
    assert params.n == 2**14
    header = VaultHeader(salt=b"0" * 16)
    assert header.revision == 0
    body = VaultBody()
    assert body.entries == []


def test_stored_vault_is_frozen_tuple_like():
    header = VaultHeader(salt=b"0" * 16)
    stored = StoredVault(header=header, encrypted_body=b"token")
    assert stored.encrypted_body == b"token"


def test_entry_create_and_summary_types():
    create = EntryCreate("svc", "user", "pw", url="u", notes="n")
    assert create.notes == "n"
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    summary = EntrySummary("id", "svc", "user", "url", now, now)
    assert summary.id == "id"
