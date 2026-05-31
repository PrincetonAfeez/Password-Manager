"""Test store functionality."""

from pathlib import Path
from threading import Thread

import pytest

from password_manager.errors import VaultFormatError, VaultWriteLockError
from password_manager.lockfile import WriteLock
from password_manager.store import VaultStore
from password_manager.vault import Vault


def test_store_reads_header_and_body(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    Vault(path).initialize("master password")

    stored = VaultStore(path).read()

    assert stored.header.format == "py-password-vault"
    assert stored.encrypted_body


def test_malformed_json_raises_format_error(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    path.write_text("not json", encoding="utf-8")

    with pytest.raises(VaultFormatError):
        VaultStore(path).read()


def test_write_lock_is_reentrant_in_same_thread(tmp_path: Path):
    path = tmp_path / "vault.pwv"

    with WriteLock(path):
        with WriteLock(path):
            pass


def test_write_lock_blocks_other_thread(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    result: list[Exception] = []

    def acquire_second() -> None:
        try:
            with WriteLock(path, timeout=0.2, poll_interval=0.01):
                pass
        except Exception as exc:
            result.append(exc)

    with WriteLock(path):
        thread = Thread(target=acquire_second)
        thread.start()
        thread.join()

    assert len(result) == 1
    assert isinstance(result[0], VaultWriteLockError)
