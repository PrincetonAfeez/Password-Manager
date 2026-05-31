"""Test atomic write functionality."""

from pathlib import Path

import pytest

from password_manager import atomic as atomic_module
from password_manager.atomic import atomic_write


def test_atomic_write_replaces_file(tmp_path: Path):
    path = tmp_path / "vault.pwv"
    path.write_bytes(b"old")

    atomic_write(path, b"new")

    assert path.read_bytes() == b"new"


def test_atomic_write_failure_leaves_old_file(tmp_path: Path, monkeypatch):
    path = tmp_path / "vault.pwv"
    path.write_bytes(b"old")

    def fail_replace(source, destination):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(atomic_module.os, "replace", fail_replace)

    with pytest.raises(RuntimeError):
        atomic_write(path, b"new")

    assert path.read_bytes() == b"old"
