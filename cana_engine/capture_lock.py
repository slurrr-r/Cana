r"""
capture_lock.py
===============

Machine-wide capture singleton.

On Windows the production lock is a named mutex. File locking remains
for Linux/development.

Windows note
------------
An object created under the ``Global\`` namespace requires the
``SeCreateGlobalPrivilege`` ("Create global objects") right. That right
is granted by default to service accounts and administrators but *not*
to a standard interactive user. A plain ``CreateMutex(..., "Global\\..")``
from an unelevated process therefore fails with ``ERROR_ACCESS_DENIED``
(5). The singleton still has to protect against a second capture engine,
so this module degrades in a controlled way:

1. Try the machine-wide ``Global\`` mutex first. When the engine runs in
   the Windows service (LocalSystem) this is the production path.
2. If the process is not allowed to create global objects, fall back to
   the session-local ``Local\`` mutex. Duplicate engines in the same
   session/desktop are still refused.

Every failure is translated to :class:`CaptureLockError` so the engine
reports a lock conflict instead of "unexpected engine termination", and
a creation failure is never silently ignored.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from cana_engine.config import program_data_dir
from cana_engine.logging_setup import log_lifecycle

#: Base name of the singleton mutex, shared by all CANA processes.
MUTEX_BASE_NAME = "CANACaptureSingleton"

#: Machine-wide namespace (needs SeCreateGlobalPrivilege to create).
GLOBAL_MUTEX_NAME = r"Global\{}".format(MUTEX_BASE_NAME)

#: Session-local namespace (no special privilege required).
LOCAL_MUTEX_NAME = r"Local\{}".format(MUTEX_BASE_NAME)

#: Backwards-compatible alias for the production mutex name.
MUTEX_NAME = GLOBAL_MUTEX_NAME

#: Preferred order: machine-wide, then session-local.
_WINDOWS_MUTEX_NAMES: List[str] = [GLOBAL_MUTEX_NAME, LOCAL_MUTEX_NAME]

ERROR_ACCESS_DENIED = 5
ERROR_FILE_NOT_FOUND = 2
SYNCHRONIZE = 0x00100000

_lock_handle = None
_lock_path: Optional[Path] = None
_mutex_handle = None
_mutex_name: Optional[str] = None


class CaptureLockError(RuntimeError):
    """Raised when another capture engine already holds the singleton."""


def capture_lock_path() -> Path:
    return program_data_dir() / "capture.lock"


def _winerror(exc: BaseException) -> Optional[int]:
    """Best-effort extraction of a Win32 error code from a pywin32 error."""
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


def _owns_mutex(win32event, handle) -> bool:
    """Return True when a 0-timeout wait grants ownership of ``handle``."""
    waited = win32event.WaitForSingleObject(handle, 0)
    abandoned = getattr(win32event, "WAIT_ABANDONED", 0x80)
    timeout = getattr(win32event, "WAIT_TIMEOUT", 0x102)
    if waited == timeout:
        return False
    if waited in {win32event.WAIT_OBJECT_0, abandoned}:
        return True
    return False


def _open_existing_mutex(win32api, win32event, pywintypes, name):
    """Return a handle if ``name`` already exists, else ``None``.

    ``OpenMutex`` only needs ``SYNCHRONIZE`` on the DACL; creating an
    object in the ``Global\\`` namespace is what needs
    ``SeCreateGlobalPrivilege``. Probing first therefore lets an
    unprivileged process detect a singleton owned by another account. If
    the object exists but this process may not open it, we conservatively
    report a duplicate rather than starting a second engine.
    """
    opener = getattr(win32event, "OpenMutex", None)
    if opener is None:
        return None
    try:
        return opener(SYNCHRONIZE, False, name)
    except pywintypes.error as exc:
        code = _winerror(exc)
        if code == ERROR_FILE_NOT_FOUND:
            return None
        if code == ERROR_ACCESS_DENIED:
            raise CaptureLockError(
                "another CANA capture engine is already running"
            ) from exc
        return None


def _acquire_windows_mutex() -> None:
    global _mutex_handle, _mutex_name
    try:
        import pywintypes
        import win32api
        import win32event
    except ImportError as exc:
        raise CaptureLockError("Windows capture mutex requires pywin32") from exc

    last_error: Optional[BaseException] = None
    for name in _WINDOWS_MUTEX_NAMES:
        existing = _open_existing_mutex(win32api, win32event, pywintypes, name)
        if existing is not None:
            if _owns_mutex(win32event, existing):
                _mutex_handle = existing
                _mutex_name = name
                log_lifecycle("CAPTURE_LOCK_ACQUIRED", name)
                return
            win32api.CloseHandle(existing)
            raise CaptureLockError(
                "another CANA capture engine is already running"
            )

        try:
            handle = win32event.CreateMutex(None, False, name)
        except pywintypes.error as exc:
            if _winerror(exc) == ERROR_ACCESS_DENIED:
                # Not allowed to create objects in this namespace; a less
                # privileged namespace may still work.
                last_error = exc
                continue
            raise CaptureLockError(
                f"could not create the CANA capture mutex '{name}': {exc}"
            ) from exc
        if not _owns_mutex(win32event, handle):
            win32api.CloseHandle(handle)
            raise CaptureLockError(
                "another CANA capture engine is already running"
            )
        _mutex_handle = handle
        _mutex_name = name
        log_lifecycle("CAPTURE_LOCK_ACQUIRED", name)
        return

    raise CaptureLockError(
        "could not create the CANA capture singleton mutex "
        "(access denied; the process may lack SeCreateGlobalPrivilege)"
    ) from last_error


def _release_windows_mutex() -> None:
    global _mutex_handle, _mutex_name
    handle = _mutex_handle
    name = _mutex_name
    _mutex_handle = None
    _mutex_name = None
    if handle is None:
        return
    try:
        import win32api
        import win32event

        win32event.ReleaseMutex(handle)
        win32api.CloseHandle(handle)
    except Exception:  # noqa: BLE001 - releasing must never raise
        pass
    log_lifecycle("CAPTURE_LOCK_RELEASED", name or "")


def acquire_capture_lock(path: Optional[Path] = None) -> None:
    """Acquire an exclusive lock. Raises if another capture is active."""
    global _lock_handle, _lock_path
    if os.name == "nt":
        _acquire_windows_mutex()
        return
    path = Path(path) if path is not None else capture_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+")
    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise CaptureLockError(
            "another CANA capture engine is already running"
        ) from exc
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    _lock_handle = handle
    _lock_path = path
    log_lifecycle("CAPTURE_LOCK_ACQUIRED", str(path))


def release_capture_lock() -> None:
    global _lock_handle, _lock_path
    if os.name == "nt":
        _release_windows_mutex()
        return
    handle = _lock_handle
    _lock_handle = None
    if handle is None:
        return
    try:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        handle.close()
    except OSError:
        pass
    log_lifecycle("CAPTURE_LOCK_RELEASED", str(_lock_path or ""))
    _lock_path = None


__all__ = [
    "CaptureLockError",
    "GLOBAL_MUTEX_NAME",
    "LOCAL_MUTEX_NAME",
    "MUTEX_BASE_NAME",
    "MUTEX_NAME",
    "acquire_capture_lock",
    "capture_lock_path",
    "release_capture_lock",
]
