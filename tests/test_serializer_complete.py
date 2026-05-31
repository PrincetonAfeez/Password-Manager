"""Test serializer functionality."""

import json
from datetime import datetime, timezone

import pytest

from password_manager.errors import VaultFormatError
from password_manager.models import Entry, VaultBody, VaultHeader
from password_manager.serializer import VaultSerializer

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture
def serializer() -> VaultSerializer:
    return VaultSerializer()


def test_dumps_and_loads_envelope_round_trip(serializer: VaultSerializer):
    from password_manager.crypto_engine import CryptoEngine
    from password_manager.models import KDFParams

    header = VaultHeader(salt=b"1" * 16, revision=3, created_at=NOW, updated_at=NOW)
    engine = CryptoEngine()
    key = engine.derive_key("password", header.salt, KDFParams())
    token = engine.encrypt(key, b'{"version":1,"entries":[]}')
    raw = serializer.dumps_envelope(header, token)
    loaded_header, loaded_body = serializer.loads_envelope(raw)
    assert loaded_header.revision == 3
    assert loaded_body == token
    assert raw.endswith(b"\n")


def test_loads_header_missing_revision_defaults_zero(serializer: VaultSerializer):
    data = serializer.dumps_header(VaultHeader(salt=b"0" * 16, created_at=NOW, updated_at=NOW))
    del data["revision"]
    header = serializer.loads_header(data)
    assert header.revision == 0


@pytest.mark.parametrize(
    "bad_header",
    [
        {},
        {"format": "py-password-vault"},
        {
            "format": "x",
            "version": 1,
            "kdf": "scrypt",
            "kdf_params": {},
            "salt": "!!",
            "cipher": "fernet",
            "created_at": "x",
            "updated_at": "x",
        },
    ],
)
def test_loads_header_malformed(serializer: VaultSerializer, bad_header: dict):
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_header(bad_header)


def test_loads_header_invalid_base64_salt(serializer: VaultSerializer):
    data = serializer.dumps_header(VaultHeader(salt=b"0" * 16, created_at=NOW, updated_at=NOW))
    data["salt"] = "!!!not-base64!!!"
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_header(data)


def test_loads_header_invalid_datetime(serializer: VaultSerializer):
    data = serializer.dumps_header(VaultHeader(salt=b"0" * 16, created_at=NOW, updated_at=NOW))
    data["created_at"] = "not-a-datetime"
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_header(data)


def test_loads_body_malformed(serializer: VaultSerializer):
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_body(b"{not json")
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_body(b'{"version":1}')


def test_loads_envelope_malformed(serializer: VaultSerializer):
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_envelope(b"{")
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_envelope(b'{"header":{}, "body": 1}')


def test_loads_envelope_body_must_be_text(serializer: VaultSerializer):
    header = serializer.dumps_header(VaultHeader(salt=b"0" * 16, created_at=NOW, updated_at=NOW))
    raw = json.dumps({"header": header, "body": 1}).encode("utf-8")
    with pytest.raises(VaultFormatError, match="malformed"):
        serializer.loads_envelope(raw)


def test_parse_datetime_rejects_non_string(serializer: VaultSerializer):
    with pytest.raises(ValueError, match="datetime must be text"):
        serializer._parse_datetime(123)  # type: ignore[arg-type]


def test_entry_from_dict_defaults_url_notes(serializer: VaultSerializer):
    entry = serializer._entry_from_dict(
        {
            "id": "12345678-1234-5678-1234-567812345678",
            "service": "s",
            "username": "u",
            "password": "p",
            "created_at": NOW.isoformat(),
            "updated_at": NOW.isoformat(),
        }
    )
    assert entry.url == ""
    assert entry.notes == ""


def test_entry_round_trip_through_body(serializer: VaultSerializer):
    entry = Entry(
        id="12345678-1234-5678-1234-567812345678",
        service="svc",
        username="usr",
        password="pw",
        url="https://x.com",
        notes="n",
        created_at=NOW,
        updated_at=NOW,
    )
    body = VaultBody(entries=[entry])
    loaded = serializer.loads_body(serializer.dumps_body(body))
    assert loaded.entries[0].notes == "n"
