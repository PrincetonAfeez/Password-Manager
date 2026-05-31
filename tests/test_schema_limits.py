"""Test schema limits."""

from pathlib import Path

import pytest

from password_manager.errors import SchemaError
from password_manager.models import Entry, VaultBody, VaultHeader
from password_manager.schema import MAX_DECRYPTED_BODY_BYTES, MAX_ENTRIES, VaultSchema
from password_manager.vault import Vault


def test_schema_rejects_too_many_entries():
    schema = VaultSchema()
    entry = Entry(
        id="12345678-1234-5678-1234-567812345678",
        service="github",
        username="user",
        password="secret",
    )
    body = VaultBody(entries=[entry] * (MAX_ENTRIES + 1))

    with pytest.raises(SchemaError, match="too many entries"):
        schema.validate_body(body)


def test_schema_rejects_oversized_plaintext():
    schema = VaultSchema()
    body = VaultBody()

    with pytest.raises(SchemaError, match="decrypted body is too large"):
        schema.validate_body(body, plaintext_size=MAX_DECRYPTED_BODY_BYTES + 1)


def test_initialize_rejects_short_master_password(tmp_path: Path):
    with pytest.raises(ValueError, match="at least"):
        Vault(tmp_path / "vault.pwv").initialize("short")


def test_header_requires_non_negative_revision():
    schema = VaultSchema()
    header = VaultHeader(salt=b"0" * 16, revision=-1)

    with pytest.raises(SchemaError, match="revision"):
        schema.validate_header(header)
