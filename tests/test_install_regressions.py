"""Windows installation failures that mocks of the entire installer missed."""

from types import SimpleNamespace
import sys

from cana_service import install
from cana_ui.controller import request_windows_service_install


def test_explorer_sid_uses_windows_session_api_and_closes_handles(monkeypatch):
    closed = []
    handle = SimpleNamespace(Close=lambda: closed.append('process'))
    token = SimpleNamespace(Close=lambda: closed.append('token'))
    monkeypatch.setitem(sys.modules, 'psutil', SimpleNamespace(
        process_iter=lambda _: [SimpleNamespace(info={'name': 'explorer.exe'}, pid=42)]))
    monkeypatch.setitem(sys.modules, 'win32api', SimpleNamespace(
        GetCurrentProcessId=lambda: 1, OpenProcess=lambda *_: handle))
    monkeypatch.setitem(sys.modules, 'win32ts', SimpleNamespace(ProcessIdToSessionId=lambda _: 2))
    monkeypatch.setitem(sys.modules, 'win32con', SimpleNamespace(PROCESS_QUERY_LIMITED_INFORMATION=0x1000))
    monkeypatch.setitem(sys.modules, 'win32security', SimpleNamespace(
        TOKEN_QUERY=8, OpenProcessToken=lambda *_: token))
    monkeypatch.setattr(install, '_sid_from_token', lambda _: 'S-1-5-21-1-2-3-1001')
    assert install._explorer_owner_sid() == 'S-1-5-21-1-2-3-1001'
    assert closed == ['token', 'process']


def test_failed_installer_does_not_report_success(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    result = request_windows_service_install(lambda *_: 1, is_windows=True)
    assert 'failed' in result
    assert 'install.log' in result


def test_source_ui_does_not_register_python_as_system_service(monkeypatch):
    monkeypatch.delattr(sys, 'frozen', raising=False)
    def forbidden(*_):
        raise AssertionError('must not elevate source checkout')
    assert 'CANA-Setup.exe' in request_windows_service_install(forbidden, is_windows=True)


def test_pipe_retries_gap_between_server_instances(monkeypatch):
    from cana_engine import ipc

    attempts = []
    closed = []

    def connect(*_):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError(2, 'pipe temporarily absent')
        return 42

    monkeypatch.setattr(ipc, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setitem(sys.modules, 'pywintypes', SimpleNamespace(error=OSError))
    monkeypatch.setitem(sys.modules, 'win32file', SimpleNamespace(
        CreateFile=connect, GENERIC_READ=1, GENERIC_WRITE=2, OPEN_EXISTING=3,
        WriteFile=lambda *_: None, ReadFile=lambda *_: (0, b'{"ok": true}'),
        CloseHandle=closed.append))
    monkeypatch.setitem(sys.modules, 'win32pipe', SimpleNamespace(
        WaitNamedPipe=lambda *_: None, PIPE_READMODE_MESSAGE=2,
        SetNamedPipeHandleState=lambda *_: None))
    assert ipc._windows_pipe_request('status', None) == {'ok': True}
    assert len(attempts) == 2
    assert closed == [42]
