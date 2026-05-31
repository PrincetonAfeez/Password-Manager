"""Local encrypted password vault library."""

from .errors import (
    AmbiguousEntryError,
    DecryptionError,
    EncryptionError,
    EntryNotFoundError,
    KDFError,
    SchemaError,
    VaultAlreadyExistsError,
    VaultConflictError,
    VaultError,
    VaultFormatError,
    VaultLockedError,
    VaultNotFoundError,
    VaultSessionLockedError,
    VaultWriteLockError,
)
from .models import Entry, EntryCreate, EntrySummary, EntryUpdate, KDFParams
from .vault import Vault

__version__ = "0.1.2"

__all__ = [
    "AmbiguousEntryError",
    "DecryptionError",
    "EncryptionError",
    "Entry",
    "EntryCreate",
    "EntryNotFoundError",
    "EntrySummary",
    "EntryUpdate",
    "KDFError",
    "KDFParams",
    "SchemaError",
    "Vault",
    "VaultAlreadyExistsError",
    "VaultConflictError",
    "VaultError",
    "VaultFormatError",
    "VaultLockedError",
    "VaultNotFoundError",
    "VaultSessionLockedError",
    "VaultWriteLockError",
    "__version__",
]
