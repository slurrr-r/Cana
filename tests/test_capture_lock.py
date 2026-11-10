"""Windows named-mutex capture-singleton behaviour (simulated pywin32).

These tests exercise the Windows code path on any platform by injecting
stand-in ``pywintypes`` / ``win32api`` / ``win32event`` modules. They
reproduce the production failure ``(5, 'CreateMutex', 'Access is denied.')``
that occurs when a standard user process tries to create the ``Global\\``
mutex without ``SeCreateGlobalPrivilege``.
"""

from __future__ import annotations

import sys
import types

import pytest

from cana_engine import capture_lock

WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
WAIT_ABANDONED = 0x80


class FakeWinError(Exception):
    """Stands in for ``pywintypes.error``."""

    def __init__(self, code: int, func: str = "CreateMutex", msg: str = "Access is denied.") -> None:
        super().__init__(code, func, msg)
        self.winerror = code
        self.funcname = func
        self.strerror = msg


@pytest.fixture(autouse=True)
def _reset_mutex_state():
    capture_lock._mutex_handle = None
    capture_lock._mutex_name = None
    yield
    capture_lock._mutex_handle = None
    capture_lock._mutex_name = None


def _install_fake_win32(
    monkeypatch,
    create_mutex,
    wait_value=WAIT_OBJECT_0,
    open_mutex=None,
):
    win32api = types.ModuleType("win32api")
    closed = []
    win32api.CloseHandle = lambda handle: closed.append(handle)

    win32event = types.ModuleType("win32event")
    win32event.WAIT_OBJECT_0 = WAIT_OBJECT_0
    win32event.WAIT_TIMEOUT = WAIT_TIMEOUT
    win32event.WAIT_ABANDONED = WAIT_ABANDONED
    win32event.CreateMutex = create_mutex
    win32event.WaitForSingleObject = lambda handle, timeout: wait_value
    released = []
    win32event.ReleaseMutex = lambda handle: released.append(handle)
    if open_mutex is not None:
        win32event.OpenMutex = open_mutex

    pywintypes = types.ModuleType("pywintypes")
    pywintypes.error = FakeWinError

    monkeypatch.setitem(sys.modules, "win32api", win32api)
    monkeypatch.setitem(sys.modules, "win32event", win32event)
    monkeypatch.setitem(sys.modules, "pywintypes", pywintypes)
    return {"closed": closed, "released": released}


def test_global_mutex_used_when_permitted(monkeypatch) -> None:
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        return f"handle:{name}"

    _install_fake_win32(monkeypatch, create_mutex, WAIT_OBJECT_0)
    capture_lock._acquire_windows_mutex()
    assert created == [capture_lock.GLOBAL_MUTEX_NAME]
    assert capture_lock._mutex_name == capture_lock.GLOBAL_MUTEX_NAME
    assert capture_lock._mutex_handle == f"handle:{capture_lock.GLOBAL_MUTEX_NAME}"


def test_missing_mutex_is_created(monkeypatch) -> None:
    """OpenMutex raising FILE_NOT_FOUND (no object yet) falls through to create."""
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        return f"handle:{name}"

    def open_mutex(access, inherit, name):
        raise FakeWinError(capture_lock.ERROR_FILE_NOT_FOUND, "OpenMutex", "not found")

    _install_fake_win32(
        monkeypatch, create_mutex, WAIT_OBJECT_0, open_mutex=open_mutex
    )
    capture_lock._acquire_windows_mutex()
    assert created == [capture_lock.GLOBAL_MUTEX_NAME]


def test_falls_back_to_local_namespace_on_access_denied(monkeypatch) -> None:
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        if name == capture_lock.GLOBAL_MUTEX_NAME:
            raise FakeWinError(capture_lock.ERROR_ACCESS_DENIED)
        return f"handle:{name}"

    _install_fake_win32(monkeypatch, create_mutex, WAIT_OBJECT_0)
    capture_lock._acquire_windows_mutex()
    assert created == [capture_lock.GLOBAL_MUTEX_NAME, capture_lock.LOCAL_MUTEX_NAME]
    assert capture_lock._mutex_name == capture_lock.LOCAL_MUTEX_NAME


def test_busy_mutex_reports_already_running(monkeypatch) -> None:
    _install_fake_win32(monkeypatch, lambda s, o, n: "h", WAIT_TIMEOUT)
    with pytest.raises(capture_lock.CaptureLockError, match="already running"):
        capture_lock._acquire_windows_mutex()
    assert capture_lock._mutex_handle is None


def test_access_denied_everywhere_raises_capture_lock_error(monkeypatch) -> None:
    def create_mutex(security, owner, name):
        raise FakeWinError(capture_lock.ERROR_ACCESS_DENIED)

    _install_fake_win32(monkeypatch, create_mutex, WAIT_OBJECT_0)
    with pytest.raises(capture_lock.CaptureLockError) as info:
        capture_lock._acquire_windows_mutex()
    assert isinstance(info.value.__cause__, FakeWinError)


def test_non_access_error_is_wrapped_not_raised_raw(monkeypatch) -> None:
    calls = []

    def create_mutex(security, owner, name):
        calls.append(name)
        raise FakeWinError(87, msg="The parameter is incorrect.")

    _install_fake_win32(monkeypatch, create_mutex, WAIT_OBJECT_0)
    with pytest.raises(capture_lock.CaptureLockError):
        capture_lock._acquire_windows_mutex()
    assert calls == [capture_lock.GLOBAL_MUTEX_NAME]


def test_existing_global_mutex_owned_by_other_account_is_refused(monkeypatch) -> None:
    """A service-owned Global mutex is detected even without create rights.

    The unprivileged process cannot create a Global object, but OpenMutex
    reports ERROR_ACCESS_DENIED because the object exists and is owned by
    another account. It must be refused, not silently fall back to Local.
    """
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        raise FakeWinError(capture_lock.ERROR_ACCESS_DENIED)

    def open_mutex(access, inherit, name):
        raise FakeWinError(capture_lock.ERROR_ACCESS_DENIED, "OpenMutex")

    _install_fake_win32(
        monkeypatch, create_mutex, WAIT_OBJECT_0, open_mutex=open_mutex
    )
    with pytest.raises(capture_lock.CaptureLockError, match="already running"):
        capture_lock._acquire_windows_mutex()
    assert created == []


def test_existing_held_mutex_is_refused(monkeypatch) -> None:
    """An existing Global mutex that is currently owned is refused."""
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        return "h"

    def open_mutex(access, inherit, name):
        return f"opened:{name}"

    _install_fake_win32(
        monkeypatch, create_mutex, WAIT_TIMEOUT, open_mutex=open_mutex
    )
    with pytest.raises(capture_lock.CaptureLockError, match="already running"):
        capture_lock._acquire_windows_mutex()
    assert created == []
    assert capture_lock._mutex_handle is None


def test_existing_free_mutex_is_taken_over(monkeypatch) -> None:
    """An existing but unheld Global mutex is adopted, not recreated."""
    created = []

    def create_mutex(security, owner, name):
        created.append(name)
        return f"handle:{name}"

    def open_mutex(access, inherit, name):
        return f"opened:{name}"

    _install_fake_win32(
        monkeypatch, create_mutex, WAIT_OBJECT_0, open_mutex=open_mutex
    )
    capture_lock._acquire_windows_mutex()
    assert created == []
    assert capture_lock._mutex_handle == f"opened:{capture_lock.GLOBAL_MUTEX_NAME}"


def test_release_releases_and_closes_acquired_handle(monkeypatch) -> None:
    def create_mutex(security, owner, name):
        return "h"

    fake = _install_fake_win32(monkeypatch, create_mutex, WAIT_OBJECT_0)
    capture_lock._acquire_windows_mutex()
    capture_lock._release_windows_mutex()
    assert fake["released"] == ["h"]
    assert fake["closed"] == ["h"]
    assert capture_lock._mutex_handle is None
    assert capture_lock._mutex_name is None


def test_release_without_acquire_is_safe() -> None:
    capture_lock._release_windows_mutex()
    assert capture_lock._mutex_handle is None
