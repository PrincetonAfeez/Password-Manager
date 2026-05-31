"""Project-specific errors.

The CLI catches these and prints safe messages without tracebacks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import EntrySummary


class VaultError(Exception):
    """Base class for expected application errors."""


class VaultLockedError(VaultError):
    """Base class for vault lock failures."""


class VaultSessionLockedError(VaultLockedError):
    """Raised when an operation needs an unlocked in-memory vault session."""


class VaultWriteLockError(VaultLockedError):
    """Raised when another process holds the vault write lock."""


class VaultAlreadyExistsError(VaultError):
    """Raised when initializing over an existing vault."""


class VaultNotFoundError(VaultError):
    """Raised when a vault path does not exist."""


class VaultFormatError(VaultError):
    """Raised when the vault envelope cannot be parsed safely."""


class VaultConflictError(VaultError):
    """Raised when the on-disk vault revision changed before a write."""


class SchemaError(VaultError):
    """Raised when header/body data does not match the expected schema."""


class KDFError(VaultError):
    """Raised when key derivation fails."""


class EncryptionError(VaultError):
    """Raised when encryption fails."""


class DecryptionError(VaultError):
    """Raised when authenticated decryption fails."""


class EntryNotFoundError(VaultError):
    """Raised when no entry matches the requested identifier."""


class AmbiguousEntryError(VaultError):
    """Raised when a non-id identifier matches more than one entry."""

    def __init__(
        self,
        message: str,
        *,
        entries: list[EntrySummary] | None = None,
    ) -> None:
        super().__init__(message)
        self.entries: list[EntrySummary] = list(entries or [])
