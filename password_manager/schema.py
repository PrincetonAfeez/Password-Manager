"""Schema and guardrail validation for vault data."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from .errors import SchemaError
from .models import Entry, VaultBody, VaultHeader

FORMAT_ID = "py-password-vault"
HEADER_VERSION = 1
BODY_VERSION = 1
KDF_ID = "scrypt"
CIPHER_ID = "fernet"

MIN_SALT_BYTES = 16
MAX_SALT_BYTES = 64
MIN_SCRYPT_N = 2**14
MAX_SCRYPT_N = 2**18
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 8
MAX_ENCRYPTED_BODY_BYTES = 50 * 1024 * 1024
MAX_DECRYPTED_BODY_BYTES = 10 * 1024 * 1024
MAX_ENTRIES = 10_000

MAX_SERVICE_LENGTH = 256
MAX_USERNAME_LENGTH = 256
MAX_PASSWORD_LENGTH = 1024
MAX_URL_LENGTH = 2048
MAX_NOTES_LENGTH = 65536


class VaultSchema:
    def validate_header(self, header: VaultHeader) -> None:
        if header.format != FORMAT_ID:
            raise SchemaError("unsupported vault format")
        if header.version != HEADER_VERSION:
            raise SchemaError("unsupported vault version")
        if header.kdf != KDF_ID or header.kdf_params.name != KDF_ID:
            raise SchemaError("unsupported KDF")
        if header.cipher != CIPHER_ID:
            raise SchemaError("unsupported cipher")
        if header.kdf_params.length != 32:
            raise SchemaError("unsupported key length")
        if not MIN_SALT_BYTES <= len(header.salt) <= MAX_SALT_BYTES:
            raise SchemaError("invalid salt length")
        self._validate_scrypt_params(header.kdf_params.n, header.kdf_params.r, header.kdf_params.p)
        if not isinstance(header.revision, int) or header.revision < 0:
            raise SchemaError("invalid header revision")
        self._validate_datetime(header.created_at, "header created_at")
        self._validate_datetime(header.updated_at, "header updated_at")
        if header.updated_at < header.created_at:
            raise SchemaError("header updated_at precedes created_at")

    def validate_encrypted_body_size(self, encrypted_body: bytes) -> None:
        if not encrypted_body:
            raise SchemaError("missing encrypted body")
        if len(encrypted_body) > MAX_ENCRYPTED_BODY_BYTES:
            raise SchemaError("encrypted body is too large")

    def validate_body(self, body: VaultBody, *, plaintext_size: int | None = None) -> None:
        if body.version != BODY_VERSION:
            raise SchemaError("unsupported body version")
        if not isinstance(body.entries, list):
            raise SchemaError("entries must be a list")
        if len(body.entries) > MAX_ENTRIES:
            raise SchemaError("too many entries")
        if plaintext_size is not None and plaintext_size > MAX_DECRYPTED_BODY_BYTES:
            raise SchemaError("decrypted body is too large")

        ids: set[str] = set()
        for entry in body.entries:
            self.validate_entry(entry)
            if entry.id in ids:
                raise SchemaError("duplicate entry id")
            ids.add(entry.id)

    def validate_entry(self, entry: Entry) -> None:
        try:
            UUID(entry.id)
        except ValueError as exc:
            raise SchemaError("invalid entry id") from exc

        for field_name in ("service", "username"):
            value = getattr(entry, field_name)
            if not isinstance(value, str) or not value.strip():
                raise SchemaError(f"entry {field_name} is required")

        if not isinstance(entry.password, str) or entry.password == "":
            raise SchemaError("entry password is required")

        for field_name in ("url", "notes"):
            value = getattr(entry, field_name)
            if not isinstance(value, str):
                raise SchemaError(f"entry {field_name} must be text")

        self._validate_field_length(entry.service, MAX_SERVICE_LENGTH, "service")
        self._validate_field_length(entry.username, MAX_USERNAME_LENGTH, "username")
        self._validate_field_length(entry.password, MAX_PASSWORD_LENGTH, "password")
        self._validate_field_length(entry.url, MAX_URL_LENGTH, "url")
        self._validate_field_length(entry.notes, MAX_NOTES_LENGTH, "notes")

        self._validate_datetime(entry.created_at, "entry created_at")
        self._validate_datetime(entry.updated_at, "entry updated_at")
        if entry.updated_at < entry.created_at:
            raise SchemaError("entry updated_at precedes created_at")

    def _validate_field_length(self, value: str, max_length: int, field_name: str) -> None:
        if len(value) > max_length:
            raise SchemaError(f"entry {field_name} exceeds maximum length")

    def _validate_scrypt_params(self, n: int, r: int, p: int) -> None:
        if not isinstance(n, int) or n < MIN_SCRYPT_N or n > MAX_SCRYPT_N:
            raise SchemaError("unsafe scrypt n parameter")
        if n & (n - 1) != 0:
            raise SchemaError("scrypt n must be a power of two")
        if not isinstance(r, int) or r < 1 or r > MAX_SCRYPT_R:
            raise SchemaError("unsafe scrypt r parameter")
        if not isinstance(p, int) or p < 1 or p > MAX_SCRYPT_P:
            raise SchemaError("unsafe scrypt p parameter")

    def _validate_datetime(self, value: datetime, label: str) -> None:
        if not isinstance(value, datetime):
            raise SchemaError(f"{label} must be a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise SchemaError(f"{label} must be timezone-aware")
