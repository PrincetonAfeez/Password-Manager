"""Domain layer for encrypted password vault operations."""

from __future__ import annotations

import hmac
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from .crypto_engine import CryptoEngine
from .errors import (
    AmbiguousEntryError,
    DecryptionError,
    EntryNotFoundError,
    VaultConflictError,
    VaultNotFoundError,
    VaultSessionLockedError,
)
from .lockfile import WriteLock
from .models import (
    Entry,
    EntryCreate,
    EntrySummary,
    EntryUpdate,
    KDFParams,
    VaultBody,
    VaultHeader,
    utc_now,
)
from .schema import VaultSchema
from .serializer import VaultSerializer
from .store import VaultStore

MIN_MASTER_PASSWORD_LENGTH = 12


class Vault:
    """Encrypted local vault: derive key from master password, store entries on disk."""

    def __init__(
        self,
        path: str | Path,
        *,
        crypto: CryptoEngine | None = None,
        serializer: VaultSerializer | None = None,
        schema: VaultSchema | None = None,
        kdf_params: KDFParams | None = None,
    ) -> None:
        self.path = Path(path)
        self.crypto = crypto or CryptoEngine()
        self.serializer = serializer or VaultSerializer()
        self.schema = schema or VaultSchema()
        self.store = VaultStore(self.path, self.serializer, self.schema)
        self.kdf_params = kdf_params or KDFParams()
        self._header: VaultHeader | None = None
        self._body: VaultBody | None = None
        self._key: bytes | None = None

    def initialize(self, master_password: str) -> None:
        """Create a new vault file at ``self.path`` (fails if the file already exists).

        Leaves an unlocked in-memory session. Library callers that do not need a
        session should call :meth:`lock` afterward.
        """
        self._require_password(master_password)
        now = utc_now()
        header = VaultHeader(
            kdf_params=self.kdf_params,
            salt=self.crypto.generate_salt(),
            revision=0,
            created_at=now,
            updated_at=now,
        )
        self.schema.validate_header(header)
        body = VaultBody()
        plaintext = self.serializer.dumps_body(body)
        key = self.crypto.derive_key(master_password, header.salt, header.kdf_params)
        encrypted_body = self.crypto.encrypt(key, plaintext)
        self.store.initialize(header, encrypted_body)
        self._header = header
        self._body = body
        self._key = key

    def unlock(self, master_password: str) -> None:
        """Decrypt the vault and load entries into memory; clears session on any failure."""
        self._require_password(master_password)
        try:
            header, body, key = self._load_unlocked_state(master_password)
        except BaseException:
            self.lock()
            raise
        self._header = header
        self._body = body
        self._key = key

    def lock(self) -> None:
        """Drop in-memory header, body, and key (does not modify the vault file)."""
        self._key = None
        self._body = None
        self._header = None

    def is_unlocked(self) -> bool:
        """Return whether header, body, and key are loaded in memory."""
        return self._key is not None and self._body is not None and self._header is not None

    def verify_password(self, master_password: str) -> bool:
        """Validate the master password without loading a session when locked.

        On failure, clears any unlocked session (same fail-closed rule as
        :meth:`unlock`).
        """
        self._require_password(master_password)
        try:
            self._load_unlocked_state(master_password)
        except BaseException:
            self.lock()
            raise
        return True

    def check(self, master_password: str) -> bool:
        """Alias for :meth:`verify_password` (decrypt + schema check only)."""
        return self.verify_password(master_password)

    def add_entry(self, entry_data: EntryCreate) -> Entry:
        """Append an entry and persist the vault (requires unlocked session).

        Returns a defensive copy so external mutation can't desync memory from disk.
        """
        body = self._require_body()
        now = utc_now()
        entry = Entry(
            id=str(uuid4()),
            service=self._required_text(entry_data.service, "service"),
            username=self._required_text(entry_data.username, "username"),
            password=self._required_text(entry_data.password, "password"),
            url=entry_data.url or "",
            notes=entry_data.notes or "",
            created_at=now,
            updated_at=now,
        )
        self.schema.validate_entry(entry)
        body.entries.append(entry)
        try:
            self._save()
        except BaseException:
            body.entries.pop()
            raise
        return replace(entry)

    def list_entries(self) -> list[EntrySummary]:
        """Return safe summaries (no passwords or notes)."""
        body = self._require_body()
        return [self._summary(entry) for entry in body.entries]

    def get_entry(self, entry_id_or_service: str) -> Entry:
        """Return one entry by UUID or exact service name (case-insensitive).

        Returns a defensive copy so external mutation can't desync memory from disk.
        """
        return replace(self._find_one(entry_id_or_service))

    def update_entry(self, entry_id_or_service: str, updates: EntryUpdate) -> Entry:
        """Apply partial updates and persist (requires unlocked session).

        Validation runs against a candidate Entry before any in-memory state is
        replaced, and on persistence failure the original Entry is restored.
        """
        if not updates.has_changes():
            raise ValueError("no updates provided")

        body = self._require_body()
        original = self._find_one(entry_id_or_service)
        index = body.entries.index(original)

        candidate = replace(
            original,
            service=(
                self._required_text(updates.service, "service")
                if updates.service is not None
                else original.service
            ),
            username=(
                self._required_text(updates.username, "username")
                if updates.username is not None
                else original.username
            ),
            password=(
                self._required_text(updates.password, "password")
                if updates.password is not None
                else original.password
            ),
            url=updates.url if updates.url is not None else original.url,
            notes=updates.notes if updates.notes is not None else original.notes,
            updated_at=utc_now(),
        )
        self.schema.validate_entry(candidate)

        body.entries[index] = candidate
        try:
            self._save()
        except BaseException:
            body.entries[index] = original
            raise
        return replace(candidate)

    def delete_entry(self, entry_id_or_service: str) -> None:
        """Remove one entry and persist (requires unlocked session)."""
        body = self._require_body()
        entry = self._find_one(entry_id_or_service)
        previous_entries = list(body.entries)
        body.entries = [item for item in body.entries if item.id != entry.id]
        try:
            self._save()
        except BaseException:
            body.entries = previous_entries
            raise

    def search(self, query: str) -> list[EntrySummary]:
        """Case-insensitive search across service, username, url, and notes."""
        if not isinstance(query, str) or not query.strip():
            raise ValueError("search query must not be empty")
        body = self._require_body()
        normalized = query.casefold()
        return [
            self._summary(entry)
            for entry in body.entries
            if normalized in entry.service.casefold()
            or normalized in entry.username.casefold()
            or normalized in entry.url.casefold()
            or normalized in entry.notes.casefold()
        ]

    def change_master_password(
        self,
        old_password: str,
        new_password: str,
        *,
        kdf_params: KDFParams | None = None,
    ) -> None:
        """Rotate master password and salt (optionally upgrade KDF cost).

        Re-encrypts the vault body with a new master password and a fresh salt.
        Pass ``kdf_params`` to raise scrypt cost during rotation without changing
        the password-only semantics.

        The vault's lock state before the call is preserved on success: if it was
        locked, it stays locked; if it was unlocked, it stays unlocked. Failed
        re-authentication clears any unlocked session (same fail-closed rule as
        :meth:`unlock`). The new password must differ from the current password.
        """
        self._require_password(new_password)
        self._reject_password_reuse(old_password, new_password)
        was_unlocked = self.is_unlocked()
        try:
            if was_unlocked:
                self._verify_unlocked_password(old_password)
            else:
                self.unlock(old_password)
        except BaseException:
            self.lock()
            raise

        try:
            header = self._require_header()
            body = self._require_body()
            new_kdf = kdf_params or header.kdf_params
            new_header = VaultHeader(
                format=header.format,
                version=header.version,
                kdf=header.kdf,
                kdf_params=new_kdf,
                salt=self.crypto.generate_salt(),
                cipher=header.cipher,
                revision=header.revision,
                created_at=header.created_at,
                updated_at=self._next_updated_at(header),
            )
            self.schema.validate_header(new_header)
            new_key = self.crypto.derive_key(new_password, new_header.salt, new_header.kdf_params)
            plaintext = self.serializer.dumps_body(body)
            self.schema.validate_body(body, plaintext_size=len(plaintext))
            encrypted_body = self.crypto.encrypt(new_key, plaintext)
            persisted = self._commit(new_header, encrypted_body)
            self._header = persisted
            self._key = new_key
        finally:
            if not was_unlocked:
                self.lock()

    def find_matching_entries(self, entry_id_or_service: str) -> list[Entry]:
        """Return all entries matching an id or service name (may be ambiguous).

        Returns defensive copies so external mutation can't desync memory from disk.
        """
        return [replace(entry) for entry in self._matching_entries(entry_id_or_service)]

    def _matching_entries(self, entry_id_or_service: str) -> list[Entry]:
        """Internal: return live Entry references inside ``self._body.entries``."""
        body = self._require_body()
        matches = [entry for entry in body.entries if entry.id == entry_id_or_service]
        if not matches:
            matches = [
                entry
                for entry in body.entries
                if entry.service.casefold() == entry_id_or_service.casefold()
            ]
        return matches

    def _save(self) -> None:
        header = self._require_header()
        body = self._require_body()
        key = self._require_key()
        plaintext = self.serializer.dumps_body(body)
        self.schema.validate_body(body, plaintext_size=len(plaintext))
        encrypted_body = self.crypto.encrypt(key, plaintext)
        write_header = replace(header, updated_at=self._next_updated_at(header))
        persisted = self._commit(write_header, encrypted_body)
        self._header = persisted

    def _commit(self, header: VaultHeader, encrypted_body: bytes) -> VaultHeader:
        """Atomically check the on-disk revision and persist.

        The write lock is held across the revision check and the write so the
        check-then-write sequence is race-free even for direct library users
        who don't hold an outer lock.
        """
        with WriteLock(self.path):
            self._ensure_revision_current(header)
            persisted = replace(header, revision=header.revision + 1)
            self.store.write(persisted, encrypted_body)
            return persisted

    def _ensure_revision_current(self, header: VaultHeader) -> None:
        if not self.store.exists():
            raise VaultNotFoundError("vault file does not exist")
        stored_header = self.store.read_header()
        if stored_header.revision != header.revision:
            raise VaultConflictError("vault was modified by another process; re-open and retry")

    def _load_unlocked_state(self, master_password: str) -> tuple[VaultHeader, VaultBody, bytes]:
        stored = self.store.read()
        key = self.crypto.derive_key(master_password, stored.header.salt, stored.header.kdf_params)
        plaintext = self.crypto.decrypt(key, stored.encrypted_body)
        body = self.serializer.loads_body(plaintext)
        self.schema.validate_body(body, plaintext_size=len(plaintext))
        return stored.header, body, key

    def _verify_unlocked_password(self, master_password: str) -> None:
        self._require_password(master_password)
        header = self._require_header()
        key = self._require_key()
        candidate = self.crypto.derive_key(master_password, header.salt, header.kdf_params)
        if not hmac.compare_digest(candidate, key):
            raise DecryptionError("decryption failed")

    def _find_one(self, entry_id_or_service: str) -> Entry:
        matches = self._matching_entries(entry_id_or_service)

        if not matches:
            raise EntryNotFoundError("entry not found")
        if len(matches) > 1:
            summaries = [self._summary(entry) for entry in matches]
            safe = ", ".join(f"{entry.id} ({entry.service}/{entry.username})" for entry in matches)
            raise AmbiguousEntryError(
                f"ambiguous entry; use one of these ids: {safe}",
                entries=summaries,
            )
        return matches[0]

    def _summary(self, entry: Entry) -> EntrySummary:
        return EntrySummary(
            id=entry.id,
            service=entry.service,
            username=entry.username,
            url=entry.url,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )

    def _require_header(self) -> VaultHeader:
        if self._header is None:
            raise VaultSessionLockedError("vault session is locked")
        return self._header

    def _require_body(self) -> VaultBody:
        if self._body is None:
            raise VaultSessionLockedError("vault session is locked")
        return self._body

    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultSessionLockedError("vault session is locked")
        return self._key

    def _require_password(self, password: str) -> None:
        if not isinstance(password, str):
            raise ValueError("password must be text")
        if password == "":
            raise ValueError("password must not be empty")
        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                f"password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters"
            )

    def _required_text(self, value: str, field_name: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be text")
        if value == "":
            raise ValueError(f"{field_name} must not be empty")
        if field_name in {"service", "username"} and not value.strip():
            raise ValueError(f"{field_name} must not be blank")
        return value

    @staticmethod
    def _reject_password_reuse(old_password: str, new_password: str) -> None:
        if hmac.compare_digest(old_password, new_password):
            raise ValueError("new password must differ from current password")

    @staticmethod
    def _next_updated_at(header: VaultHeader) -> datetime:
        """Return ``utc_now()`` clamped to not move backward relative to the
        header's existing timestamps. Defends against system-clock skew that
        would otherwise make ``validate_header`` reject the write.
        """
        now = utc_now()
        floor = max(header.updated_at, header.created_at)
        return floor if now < floor else now
