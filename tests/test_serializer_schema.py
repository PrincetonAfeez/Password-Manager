"""Test serializer schema functionality."""

import pytest

from password_manager.errors import SchemaError, VaultFormatError
from password_manager.models import Entry, KDFParams, VaultBody, VaultHeader
from password_manager.schema import VaultSchema
from password_manager.serializer import VaultSerializer


def test_header_and_body_round_trip():
    serializer = VaultSerializer()
    header = VaultHeader(salt=b"0" * 16)
    body = VaultBody(
        entries=[
            Entry(
                id="12345678-1234-5678-1234-567812345678",
                service="github",
                username="user",
                password="secret",
            )
        ]
    )

    loaded_header = serializer.loads_header(serializer.dumps_header(header))
    loaded_body = serializer.loads_body(serializer.dumps_body(body))

    assert loaded_header.salt == b"0" * 16
    assert loaded_header.revision == 0
    assert loaded_body.entries[0].service == "github"


def test_schema_rejects_unsafe_kdf_params_before_derivation():
    schema = VaultSchema()
    header = VaultHeader(salt=b"0" * 16, kdf_params=KDFParams(n=2**8))

    with pytest.raises(SchemaError):
        schema.validate_header(header)


def test_schema_rejects_duplicate_entry_ids():
    schema = VaultSchema()
    entry = Entry(
        id="12345678-1234-5678-1234-567812345678",
        service="github",
        username="user",
        password="secret",
    )

    with pytest.raises(SchemaError):
        schema.validate_body(VaultBody(entries=[entry, entry]))


def test_malformed_envelope_raises_vault_format_error():
    serializer = VaultSerializer()

    with pytest.raises(VaultFormatError):
        serializer.loads_envelope(b"{not json")
