"""Test error functionality."""

from password_manager.errors import (
    AmbiguousEntryError,
    DecryptionError,
    EncryptionError,
    EntryNotFoundError,
    KDFError,
    SchemaError,
    VaultAlreadyExistsError,
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultLockedError,
    VaultNotFoundError,
    VaultSessionLockedError,
    VaultWriteLockError,
)
from password_manager.models import EntrySummary, utc_now


def test_error_hierarchy():
    assert issubclass(DecryptionError, VaultError)
    assert issubclass(VaultSessionLockedError, VaultLockedError)
    assert issubclass(VaultWriteLockError, VaultLockedError)
    assert issubclass(SchemaError, VaultError)
    assert issubclass(KDFError, VaultError)
    assert issubclass(EncryptionError, VaultError)


def test_ambiguous_entry_error_carries_summaries():
    summary = EntrySummary(
        id="12345678-1234-5678-1234-567812345678",
        service="github",
        username="one",
        url="",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    exc = AmbiguousEntryError("ambiguous", entries=[summary])
    assert len(exc.entries) == 1
    assert exc.entries[0].service == "github"


def test_vault_error_messages_are_safe_strings():
    for exc_type in (
        VaultNotFoundError,
        VaultAlreadyExistsError,
        VaultFormatError,
        VaultConflictError,
        EntryNotFoundError,
    ):
        message = str(exc_type("safe message"))
        assert "traceback" not in message.lower()
