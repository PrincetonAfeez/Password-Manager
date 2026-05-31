"""Atomic file writes for vault persistence."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp:
            temp_name = temp.name
            temp.write(data)
            temp.flush()
            os.fsync(temp.fileno())

        os.replace(temp_name, path)
        temp_name = None
        _fsync_parent_directory(path)
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def _fsync_parent_directory(path: Path) -> None:
    directory_fd: int | None = None
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
