"""Test store functionality."""

from pathlib import Path
from unittest.mock import patch

import pytest

from password_manager.errors import (
    SchemaError,
    VaultAlreadyExistsError,
    VaultError,
    VaultFormatError,
    VaultNotFoundError,
)
from password_manager.models import EntryCreate
from password_manager.schema import MAX_ENCRYPTED_BODY_BYTES
from password_manager.serializer import VaultSerializer
from password_manager.store import VaultStore
from password_manager.vault import Vault


def test_exists_false(tmp_path: Path):
    assert not VaultStore(tmp_path / "missing.pwv").exists()


def test_read_missing_vault(tmp_path: Path):
    with pytest.raises(VaultNotFoundError):
        VaultStore(tmp_path / "missing.pwv").read()


def test_initialize_refuses_existing_file(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize(master_password)
    header = Vault(path).store.read().header
    with pytest.raises(VaultAlreadyExistsError):
        VaultStore(path).initialize(header, b"body")


def test_read_oserror_wrapped(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize(master_password)
    with patch.object(Path, "read_bytes", side_effect=OSError("denied")):
        with pytest.raises(VaultFormatError, match="could not be read"):
            VaultStore(path).read()


def test_write_oserror_wrapped(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize(master_password)
    with patch("password_manager.store.atomic_write", side_effect=OSError("disk full")):
        with pytest.raises(VaultError, match="could not be written"):
            vault.add_entry(EntryCreate("s", "u", "p"))


def test_read_header_rejects_oversized_body(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize(master_password)
    stored = VaultStore(path).read()
    oversized = VaultSerializer().dumps_envelope(
        stored.header,
        b"x" * (MAX_ENCRYPTED_BODY_BYTES + 1),
    )
    path.write_bytes(oversized)

    with pytest.raises(SchemaError, match="too large"):
        VaultStore(path).read_header()


def test_read_header_returns_header_for_valid_vault(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize(master_password)
    header = VaultStore(path).read_header()
    assert header.format == "py-password-vault"


def test_write_persists_readable_vault(tmp_path: Path, master_password: str):
    path = tmp_path / "vault.pwv"
    vault = Vault(path)
    vault.initialize(master_password)
    vault.add_entry(EntryCreate("s", "u", "p"))
    stored = VaultStore(path).read()
    assert stored.header.revision >= 1


def test_store_custom_serializer_schema(tmp_path: Path):
    from password_manager.schema import VaultSchema
    from password_manager.serializer import VaultSerializer

    store = VaultStore(tmp_path / "v.pwv", VaultSerializer(), VaultSchema())
    assert store.serializer is not None
    assert store.schema is not None
