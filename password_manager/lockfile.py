"""Best-effort same-directory write lock."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from .errors import VaultWriteLockError

LOCK_MAX_AGE_SECONDS = 300.0
LOCK_FILE_MODE = 0o600
_thread_depths: threading.local = threading.local()


def _lock_depths() -> dict[str, int]:
    depths = getattr(_thread_depths, "depths", None)
    if depths is None:
        depths = {}
        _thread_depths.depths = depths
    return depths


# Module-level Windows API setup so _pid_alive / _process_start_time don't
# re-bind ctypes signatures on every poll.
if os.name == "nt":
    import ctypes as _ctypes
    from ctypes import wintypes as _wintypes

    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _STILL_ACTIVE = 259
    _ERROR_INVALID_PARAMETER = 87

    _kernel32 = _ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.restype = _wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = (_wintypes.DWORD, _wintypes.BOOL, _wintypes.DWORD)
    _kernel32.GetExitCodeProcess.argtypes = (
        _wintypes.HANDLE,
        _ctypes.POINTER(_wintypes.DWORD),
    )
    _kernel32.GetExitCodeProcess.restype = _wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = (
        _wintypes.HANDLE,
        _ctypes.POINTER(_wintypes.FILETIME),
        _ctypes.POINTER(_wintypes.FILETIME),
        _ctypes.POINTER(_wintypes.FILETIME),
        _ctypes.POINTER(_wintypes.FILETIME),
    )
    _kernel32.GetProcessTimes.restype = _wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (_wintypes.HANDLE,)


def _pid_alive(pid: int) -> bool:
    """Return True if a process with this PID currently exists.

    On POSIX, ``os.kill(pid, 0)`` is the canonical liveness check. On Windows,
    ``os.kill`` with sig=0 maps to ``TerminateProcess(handle, 0)``, which would
    actually terminate the holder — so we use ``OpenProcess`` + ``GetExitCodeProcess``
    via ctypes instead.
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            err = _ctypes.get_last_error()
            return err != _ERROR_INVALID_PARAMETER
        try:
            exit_code = _wintypes.DWORD()
            if not _kernel32.GetExitCodeProcess(handle, _ctypes.byref(exit_code)):
                return True
            return exit_code.value == _STILL_ACTIVE
        finally:
            _kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _process_start_time(pid: int) -> int | None:
    """Return a stable integer fingerprint of the process's start time, or None
    if it can't be determined on this platform.

    Combined with the PID, this defeats stale-lock PID-reuse: a recycled PID
    will have a different start time than the original holder's.
    """
    if pid <= 0:
        return None

    if os.name == "nt":
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            creation = _wintypes.FILETIME()
            exit_t = _wintypes.FILETIME()
            kernel_t = _wintypes.FILETIME()
            user_t = _wintypes.FILETIME()
            if not _kernel32.GetProcessTimes(
                handle,
                _ctypes.byref(creation),
                _ctypes.byref(exit_t),
                _ctypes.byref(kernel_t),
                _ctypes.byref(user_t),
            ):
                return None
            return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        finally:
            _kernel32.CloseHandle(handle)

    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        # The `comm` field (index 2) is wrapped in parens and may contain
        # spaces/parens itself; split after the LAST closing paren.
        rpar = data.rfind(b")")
        if rpar < 0:
            return None
        fields = data[rpar + 2 :].split()
        # After comm, fields are 0-indexed starting at `state` (field 3).
        # `starttime` is field 22 → index 22 - 3 = 19.
        if len(fields) < 20:
            return None
        try:
            return int(fields[19])
        except ValueError:
            return None

    # macOS and other POSIX without /proc — no portable way without an
    # extra dependency. Caller falls back to age-based stale-lock cleanup.
    return None


def _format_lock_token(pid: int, start_time: int | None) -> bytes:
    if start_time is None:
        return str(pid).encode("ascii")
    return f"{pid} {start_time}".encode("ascii")


def _parse_lock_token(raw: str) -> tuple[int, int | None] | None:
    parts = raw.split()
    if not parts:
        return None
    try:
        pid = int(parts[0])
    except ValueError:
        return None
    start_time: int | None = None
    if len(parts) >= 2:
        try:
            start_time = int(parts[1])
        except ValueError:
            start_time = None
    return pid, start_time


def _holder_is_alive(pid: int, recorded_start_time: int | None) -> bool:
    """Liveness check that defeats PID reuse when start_time is available."""
    if not _pid_alive(pid):
        return False
    if recorded_start_time is None:
        # Legacy lock file (pid only) or unsupported platform — best-effort:
        # treat the holder as alive and rely on LOCK_MAX_AGE_SECONDS as the
        # ultimate safety net.
        return True
    current = _process_start_time(pid)
    if current is None:
        return True  # can't verify; assume alive
    return current == recorded_start_time


class WriteLock:
    def __init__(self, vault_path: Path, timeout: float = 5.0, poll_interval: float = 0.05) -> None:
        self.vault_path = Path(vault_path)
        self.lock_path = self.vault_path.with_name(f".{self.vault_path.name}.lock")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._fd: int | None = None
        self._key = str(self.lock_path.resolve())
        self._acquired_here = False

    def __enter__(self) -> "WriteLock":
        depths = _lock_depths()
        depths[self._key] = depths.get(self._key, 0) + 1
        if depths[self._key] > 1:
            return self

        try:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            start = time.monotonic()
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY

            while True:
                self._remove_stale_lock()
                try:
                    fd = os.open(self.lock_path, flags, LOCK_FILE_MODE)
                except FileExistsError as exc:
                    if time.monotonic() - start >= self.timeout:
                        raise VaultWriteLockError(
                            "vault is locked by another writer"
                        ) from exc
                    time.sleep(self.poll_interval)
                    continue

                try:
                    token = _format_lock_token(os.getpid(), _process_start_time(os.getpid()))
                    os.write(fd, token)
                except BaseException:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(self.lock_path)
                    except OSError:
                        pass
                    raise

                self._fd = fd
                self._acquired_here = True
                return self
        except BaseException:
            depths[self._key] -= 1
            if depths[self._key] == 0:
                del depths[self._key]
            raise

    def __exit__(self, exc_type, exc, tb) -> None:
        depths = _lock_depths()
        current = depths.get(self._key, 0)
        if current == 0:
            return

        depths[self._key] = current - 1
        if depths[self._key] > 0:
            return

        del depths[self._key]
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._acquired_here:
            try:
                os.unlink(self.lock_path)
            except FileNotFoundError:
                pass
            self._acquired_here = False

    def _remove_stale_lock(self) -> None:
        if not self.lock_path.exists():
            return

        try:
            stat_before = self.lock_path.stat()
        except OSError:
            return

        age = time.time() - stat_before.st_mtime
        if age > LOCK_MAX_AGE_SECONDS:
            self._unlink_if_unchanged(stat_before)
            return

        try:
            raw = self.lock_path.read_text(encoding="ascii").strip()
        except OSError:
            return

        token = _parse_lock_token(raw)
        if token is None:
            # Unparseable lock contents (e.g. partial write from a crashed
            # acquirer) — treat as stale rather than letting the file wedge
            # the lock forever.
            self._unlink_if_unchanged(stat_before)
            return

        pid, recorded_start = token
        if _holder_is_alive(pid, recorded_start):
            return

        self._unlink_if_unchanged(stat_before)

    def _unlink_if_unchanged(self, stat_before: os.stat_result) -> None:
        """Unlink the lock file only if its mtime hasn't changed since we
        inspected it. Shrinks the TOCTOU window between liveness check and
        removal so we don't destroy a fresh lock another process just created."""
        try:
            stat_now = self.lock_path.stat()
        except OSError:
            return
        if stat_now.st_mtime_ns != stat_before.st_mtime_ns:
            return
        try:
            os.unlink(self.lock_path)
        except OSError:
            pass
