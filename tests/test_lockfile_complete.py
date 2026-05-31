"""Test lockfile functionality."""

import os
from pathlib import Path
from threading import Thread

import pytest

from password_manager import lockfile as lockfile_module
from password_manager.errors import VaultWriteLockError
from password_manager.lockfile import (
    LOCK_MAX_AGE_SECONDS,
    WriteLock,
    _format_lock_token,
    _holder_is_alive,
    _lock_depths,
    _parse_lock_token,
    _pid_alive,
)


def test_lock_depths_initializes_thread_local():
    depths = _lock_depths()
    assert isinstance(depths, dict)


def test_remove_stale_lock_by_age(tmp_path: Path, monkeypatch):
    """Force the age branch by claiming the holder PID is alive — only the age
    threshold should be able to clean up the lock."""
    monkeypatch.setattr(lockfile_module, "_pid_alive", lambda pid: True)

    path = tmp_path / "vault.pwv"
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.write_text(str(os.getpid()), encoding="ascii")
    ancient = os.path.getmtime(lock_path) - LOCK_MAX_AGE_SECONDS - 10
    os.utime(lock_path, (ancient, ancient))

    with WriteLock(path):
        pass
    assert not lock_path.exists()


def test_remove_stale_lock_age_branch_respects_live_holder(tmp_path: Path, monkeypatch):
    """If the holder PID is alive and the lock is fresh, do NOT delete it."""
    monkeypatch.setattr(lockfile_module, "_pid_alive", lambda pid: True)

    path = tmp_path / "vault.pwv"
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.write_text(str(os.getpid()), encoding="ascii")

    with pytest.raises(VaultWriteLockError):
        with WriteLock(path, timeout=0.05, poll_interval=0.01):
            pass
    assert lock_path.exists()


def test_remove_stale_lock_dead_pid(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.write_text("999999", encoding="ascii")

    with WriteLock(path):
        # Our acquire either replaced the file with our own token, or the file
        # was unlinked and recreated under our PID.
        if lock_path.exists():
            assert lock_path.read_text().split()[0] == str(os.getpid())


def test_remove_stale_lock_invalid_pid_text(tmp_path: Path):
    """A lock file with unparseable PID content (e.g. partial write from a
    crashed acquirer) is treated as stale and removed, otherwise it would
    wedge the lock forever."""
    path = tmp_path / "vault.pwv"
    lock = path.with_name(f".{path.name}.lock")
    lock.write_text("not-a-pid", encoding="ascii")
    with WriteLock(path, timeout=0.5, poll_interval=0.01):
        assert lock.read_text(encoding="ascii").split()[0] == str(os.getpid())


def test_exit_when_depth_zero_is_noop(tmp_path: Path):
    lock = WriteLock(tmp_path / "v.pwv")
    lock.__exit__(None, None, None)


def test_nested_lock_does_not_deadlock(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    with WriteLock(path):
        with WriteLock(path):
            assert _lock_depths().get(str(path.with_name(f".{path.name}.lock").resolve()), 0) >= 1


def test_other_thread_blocks(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    errors: list[Exception] = []

    def worker() -> None:
        try:
            with WriteLock(path, timeout=0.2, poll_interval=0.01):
                pass
        except Exception as exc:
            errors.append(exc)

    with WriteLock(path):
        thread = Thread(target=worker)
        thread.start()
        thread.join()
    assert len(errors) == 1
    assert isinstance(errors[0], VaultWriteLockError)


def test_remove_stale_lock_stat_oserror(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.write_text("1", encoding="ascii")

    def fail_stat(*args, **kwargs):
        raise OSError("stat failed")

    monkeypatch.setattr(lock_path.__class__, "stat", fail_stat)
    WriteLock(path)._remove_stale_lock()


def test_pid_alive_rejects_non_positive_pid():
    assert not _pid_alive(0)
    assert not _pid_alive(-1)


def test_parse_lock_token_variants():
    assert _parse_lock_token("12345") == (12345, None)
    assert _parse_lock_token("12345 67890") == (12345, 67890)
    assert _parse_lock_token("") is None
    assert _parse_lock_token("not-a-pid") is None


def test_format_lock_token_with_and_without_start_time():
    assert _format_lock_token(42, None) == b"42"
    assert _format_lock_token(42, 999) == b"42 999"


def test_holder_is_alive_respects_pid_liveness(monkeypatch):
    monkeypatch.setattr(lockfile_module, "_pid_alive", lambda pid: False)
    assert not _holder_is_alive(999, 123)


def test_holder_is_alive_matches_start_time(monkeypatch):
    monkeypatch.setattr(lockfile_module, "_pid_alive", lambda pid: True)
    monkeypatch.setattr(lockfile_module, "_process_start_time", lambda pid: 555)
    assert _holder_is_alive(os.getpid(), 555)
    assert not _holder_is_alive(os.getpid(), 556)


def test_remove_stale_lock_read_oserror(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.write_text(str(os.getpid()), encoding="ascii")

    def fail_read_text(*args, **kwargs):
        raise OSError("read failed")

    monkeypatch.setattr(lock_path.__class__, "read_text", fail_read_text)
    WriteLock(path)._remove_stale_lock()
    assert lock_path.exists()
