"""Dataclasses used by the vault library."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class KDFParams:
    name: str = "scrypt"
    length: int = 32
    n: int = 2**14
    r: int = 8
    p: int = 1


@dataclass(frozen=True)
class VaultHeader:
    format: str = "py-password-vault"
    version: int = 1
    kdf: str = "scrypt"
    kdf_params: KDFParams = field(default_factory=KDFParams)
    salt: bytes = b""
    cipher: str = "fernet"
    revision: int = 0
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class Entry:
    id: str
    service: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class EntrySummary:
    id: str
    service: str
    username: str
    url: str
    created_at: datetime
    updated_at: datetime


@dataclass
class EntryCreate:
    service: str
    username: str
    password: str
    url: str = ""
    notes: str = ""


@dataclass
class EntryUpdate:
    service: str | None = None
    username: str | None = None
    password: str | None = None
    url: str | None = None
    notes: str | None = None

    def has_changes(self) -> bool:
        return any(
            value is not None
            for value in (
                self.service,
                self.username,
                self.password,
                self.url,
                self.notes,
            )
        )


@dataclass
class VaultBody:
    version: int = 1
    entries: list[Entry] = field(default_factory=list)


@dataclass(frozen=True)
class StoredVault:
    header: VaultHeader
    encrypted_body: bytes
