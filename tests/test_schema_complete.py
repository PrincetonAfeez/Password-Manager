"""Test schema functionality."""

from datetime import datetime, timezone

import pytest

from password_manager.errors import SchemaError
from password_manager.models import Entry, KDFParams, VaultBody, VaultHeader
from password_manager.schema import (
    MAX_ENCRYPTED_BODY_BYTES,
    MAX_SCRYPT_N,
    MIN_SCRYPT_N,
    VaultSchema,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
VALID_ENTRY = Entry(
    id="12345678-1234-5678-1234-567812345678",
    service="github",
    username="user",
    password="secret",
    created_at=NOW,
    updated_at=NOW,
)


def valid_header(**overrides) -> VaultHeader:
    base = dict(salt=b"0" * 16, created_at=NOW, updated_at=NOW)
    base.update(overrides)
    return VaultHeader(**base)


@pytest.fixture
def schema() -> VaultSchema:
    return VaultSchema()


@pytest.mark.parametrize(
    "header_kwargs,match",
    [
        ({"format": "other"}, "unsupported vault format"),
        ({"version": 99}, "unsupported vault version"),
        ({"kdf": "pbkdf2"}, "unsupported KDF"),
        ({"kdf_params": KDFParams(name="argon2")}, "unsupported KDF"),
        ({"cipher": "aes"}, "unsupported cipher"),
        ({"kdf_params": KDFParams(length=16)}, "unsupported key length"),
        ({"salt": b"short"}, "invalid salt length"),
        ({"salt": b"x" * 65}, "invalid salt length"),
        ({"revision": -1}, "invalid header revision"),
    ],
)
def test_validate_header_rejects_invalid(schema: VaultSchema, header_kwargs, match: str):
    with pytest.raises(SchemaError, match=match):
        schema.validate_header(valid_header(**header_kwargs))


@pytest.mark.parametrize(
    "n,match",
    [
        (MIN_SCRYPT_N - 1, "unsafe scrypt n"),
        (MAX_SCRYPT_N + 1, "unsafe scrypt n"),
        (2**14 + 1, "power of two"),
        (2**13, "unsafe scrypt n"),
    ],
)
def test_validate_header_rejects_bad_scrypt_n(schema: VaultSchema, n: int, match: str):
    with pytest.raises(SchemaError, match=match):
        schema.validate_header(valid_header(kdf_params=KDFParams(n=n)))


@pytest.mark.parametrize(
    "r,p,match",
    [
        (0, 1, "unsafe scrypt r"),
        (17, 1, "unsafe scrypt r"),
        (8, 0, "unsafe scrypt p"),
        (8, 9, "unsafe scrypt p"),
    ],
)
def test_validate_header_rejects_bad_scrypt_r_p(
    schema: VaultSchema, r: int, p: int, match: str
):
    with pytest.raises(SchemaError, match=match):
        schema.validate_header(valid_header(kdf_params=KDFParams(n=2**14, r=r, p=p)))


def test_validate_header_rejects_naive_datetime(schema: VaultSchema):
    naive = datetime(2026, 1, 1)
    with pytest.raises(SchemaError, match="timezone-aware"):
        schema.validate_header(valid_header(created_at=naive))


def test_validate_encrypted_body_size_empty(schema: VaultSchema):
    with pytest.raises(SchemaError, match="missing encrypted body"):
        schema.validate_encrypted_body_size(b"")


def test_validate_encrypted_body_size_too_large(schema: VaultSchema):
    with pytest.raises(SchemaError, match="too large"):
        schema.validate_encrypted_body_size(b"x" * (MAX_ENCRYPTED_BODY_BYTES + 1))


def test_validate_body_wrong_version(schema: VaultSchema):
    with pytest.raises(SchemaError, match="unsupported body version"):
        schema.validate_body(VaultBody(version=99))


def test_validate_body_entries_not_list(schema: VaultSchema):
    body = VaultBody()
    body.entries = "not-a-list"  # type: ignore[assignment]
    with pytest.raises(SchemaError, match="entries must be a list"):
        schema.validate_body(body)


@pytest.mark.parametrize(
    "entry_kwargs,match",
    [
        ({"id": "not-a-uuid"}, "invalid entry id"),
        ({"service": ""}, "entry service is required"),
        ({"username": ""}, "entry username is required"),
        ({"password": ""}, "entry password is required"),
        ({"url": 123}, "entry url must be text"),  # type: ignore[arg-type]
        ({"notes": None}, "entry notes must be text"),  # type: ignore[arg-type]
    ],
)
def test_validate_entry_rejects_invalid(schema: VaultSchema, entry_kwargs, match: str):
    entry = Entry(**{**VALID_ENTRY.__dict__, **entry_kwargs})
    with pytest.raises(SchemaError, match=match):
        schema.validate_entry(entry)


def test_validate_entry_rejects_naive_datetime(schema: VaultSchema):
    entry = Entry(
        id=VALID_ENTRY.id,
        service="s",
        username="u",
        password="p",
        created_at=datetime(2026, 1, 1),
        updated_at=NOW,
    )
    with pytest.raises(SchemaError, match="timezone-aware"):
        schema.validate_entry(entry)
