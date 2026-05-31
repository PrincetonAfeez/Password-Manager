"""Test atomic write functionality."""

from pathlib import Path

import pytest

from password_manager import atomic as atomic_module
from password_manager.atomic import _fsync_parent_directory, atomic_write


def test_atomic_write_creates_parent_directory(tmp_path: Path):
    path = tmp_path / "nested" / "dir" / "vault.pwv"
    atomic_write(path, b"payload")
    assert path.read_bytes() == b"payload"


def test_fsync_parent_directory_success(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    path.write_bytes(b"x")
    closed: list[int] = []

    def fake_open(directory, flags):
        return 42

    def fake_fsync(fd: int) -> None:
        assert fd == 42

    def fake_close(fd: int) -> None:
        closed.append(fd)

    monkeypatch.setattr(atomic_module.os, "open", fake_open)
    monkeypatch.setattr(atomic_module.os, "fsync", fake_fsync)
    monkeypatch.setattr(atomic_module.os, "close", fake_close)
    _fsync_parent_directory(path)
    assert closed == [42]


def test_fsync_parent_directory_swallows_oserror(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"

    def fail_open(*args, **kwargs):
        raise OSError("no directory sync")

    monkeypatch.setattr(atomic_module.os, "open", fail_open)
    _fsync_parent_directory(path)


def test_atomic_write_unlinks_temp_on_replace_failure(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    path.write_bytes(b"old")

    def fail_replace(source, destination):
        raise RuntimeError("replace failed")

    monkeypatch.setattr(atomic_module.os, "replace", fail_replace)
    with pytest.raises(RuntimeError):
        atomic_write(path, b"new")
    assert path.read_bytes() == b"old"
