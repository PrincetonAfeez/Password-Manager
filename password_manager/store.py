"""Vault file persistence."""

from __future__ import annotations

from pathlib import Path

from .atomic import atomic_write
from .errors import VaultAlreadyExistsError, VaultError, VaultFormatError, VaultNotFoundError
from .lockfile import WriteLock
from .models import StoredVault, VaultHeader
from .schema import VaultSchema
from .serializer import VaultSerializer


class VaultStore:
    def __init__(
        self,
        path: str | Path,
        serializer: VaultSerializer | None = None,
        schema: VaultSchema | None = None,
    ) -> None:
        self.path = Path(path)
        self.serializer = serializer or VaultSerializer()
        self.schema = schema or VaultSchema()

    def exists(self) -> bool:
        return self.path.exists()

    def read(self) -> StoredVault:
        if not self.exists():
            raise VaultNotFoundError("vault file does not exist")

        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise VaultFormatError("vault file could not be read") from exc

        header, encrypted_body = self.serializer.loads_envelope(data)
        self.schema.validate_header(header)
        self.schema.validate_encrypted_body_size(encrypted_body)
        return StoredVault(header=header, encrypted_body=encrypted_body)

    def read_header(self) -> VaultHeader:
        """Return only the validated header for revision checks.

        Parses the envelope to read the header but still enforces
        ``MAX_ENCRYPTED_BODY_BYTES`` on the ciphertext token so oversized files
        cannot bypass size limits on the save path.
        """
        if not self.exists():
            raise VaultNotFoundError("vault file does not exist")

        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise VaultFormatError("vault file could not be read") from exc

        header, encrypted_body = self.serializer.loads_envelope(data)
        self.schema.validate_header(header)
        self.schema.validate_encrypted_body_size(encrypted_body)
        return header

    def initialize(self, header: VaultHeader, encrypted_body: bytes) -> None:
        with WriteLock(self.path):
            if self.exists():
                raise VaultAlreadyExistsError("vault file already exists")
            self._write_unlocked(header, encrypted_body)

    def write(self, header: VaultHeader, encrypted_body: bytes) -> None:
        with WriteLock(self.path):
            self._write_unlocked(header, encrypted_body)

    def _write_unlocked(self, header: VaultHeader, encrypted_body: bytes) -> None:
        self.schema.validate_header(header)
        self.schema.validate_encrypted_body_size(encrypted_body)
        try:
            atomic_write(self.path, self.serializer.dumps_envelope(header, encrypted_body))
        except OSError as exc:
            raise VaultError("vault file could not be written") from exc
