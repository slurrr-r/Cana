"""In-process named-pipe protocol tests (Linux-capable)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from packet_capture.interface import NetworkInterface
from cana_engine.config import CANAConfig, load_config
from cana_engine import engine as engine_mod
from cana_engine.engine import CANAEngine
from cana_engine.capture_lock import release_capture_lock
from cana_engine.pipe import (
    InProcessPipeServer,
    PipeCommandHandler,
    SID_SYSTEM,
)


@pytest.fixture(autouse=True)
def _disable_activity_tracker(monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)


def _reset_capture_singleton_state() -> None:
    release_capture_lock()
    engine_mod._active_capture_engines = 0
    engine_mod._capture_guard_token = None
    engine_mod._capture_lock_token = None
    if engine_mod._capture_guard.locked():
        engine_mod._capture_guard.release()


@pytest.fixture(autouse=True)
def _reset_capture_singleton() -> None:
    _reset_capture_singleton_state()
    yield
    _reset_capture_singleton_state()


def _iface() -> list:
    return [
        NetworkInterface(
            index=1,
            name="eth0",
            display_name="Ethernet",
            ip_address="10.0.0.1",
            is_likely_active=True,
        )
    ]


def _runner(settings, stop_event=None, engine_out=None, **kwargs):
    class Fake:
        def stop(self):
            if stop_event is not None:
                stop_event.set()

        def is_running(self):
            return stop_event is None or not stop_event.is_set()

        stats = type("S", (), {"packets_dropped_queue_full": 0})()

    if engine_out is not None:
        engine_out["engine"] = Fake()
    if stop_event is not None:
        stop_event.wait(3)
    return []


def _engine(tmp_path: Path) -> CANAEngine:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
        packet_filter="ALL",
    )
    return CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )


def test_allowed_sid_can_start_and_stop(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM, "S-1-5-21-user"}, persist=False)
    server = InProcessPipeServer(handler)
    started = server.request("S-1-5-21-user", "start")
    assert started["ok"] is True
    stopped = server.request("S-1-5-21-user", "stop")
    assert stopped["ok"] is True
    assert engine.status().running is False


def test_start_starts_engine_when_monitoring_already_enabled(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=True,
        packet_filter="ALL",
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    assert engine.status().running is False
    started = server.request(SID_SYSTEM, "start")
    assert started["ok"] is True
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    assert engine.status().running is True
    assert engine.config.monitoring_enabled is True
    engine.stop()


def test_denied_sid_causes_no_mutation(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request("S-1-5-21-attacker", "start")
    assert result["ok"] is False
    assert result["status"] == 403
    assert engine.status().running is False


def test_unknown_command_rejected(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(SID_SYSTEM, "shell")
    assert result["ok"] is False
    assert result["status"] == 400


def test_invalid_boolean_config_rejected(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"monitoring_enabled": "banana"}}
    )
    assert result["ok"] is False
    assert result["status"] == 400
    assert engine.config.monitoring_enabled is False


def test_unknown_config_keys_rejected(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"eval": "os.system('id')"}}
    )
    assert result["ok"] is False
    assert engine.config.packet_filter == "ALL"


def test_start_rejects_unexpected_fields(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(SID_SYSTEM, "start", {"something": "unexpected"})
    assert result["ok"] is False
    assert result["status"] == 400
    assert engine.config.monitoring_enabled is False
    assert engine.status().running is False


def test_apply_config_requires_config_object(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(SID_SYSTEM, "apply_config", {"packet_filter": "TCP"})
    assert result["ok"] is False
    assert result["status"] == 400
    assert engine.config.packet_filter == "ALL"


def test_apply_config_rejects_extra_fields(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(
        SID_SYSTEM,
        "apply_config",
        {"config": {"packet_filter": "TCP"}, "extra": 1},
    )
    assert result["ok"] is False
    assert engine.config.packet_filter == "ALL"


def test_named_pipe_server_reads_before_impersonate() -> None:
    import inspect

    from cana_engine.pipe import NamedPipeServer

    source = inspect.getsource(NamedPipeServer._serve)
    read_at = source.index("_read_pipe_message")
    impersonate_at = source.index("_windows_connected_client_identity")
    assert read_at < impersonate_at


def test_windows_connected_client_sid_impersonates_then_reverts() -> None:
    from types import SimpleNamespace

    from cana_engine.pipe import _windows_connected_client_sid

    calls = []

    class FakeWin32:
        TokenUser = 1

        def ImpersonateNamedPipeClient(self, handle):
            calls.append(("impersonate", handle))

        def OpenThreadToken(self, thread, access, open_as_self):
            assert open_as_self is False
            calls.append("thread_token")
            return "token"

        def GetTokenInformation(self, token, info):
            return ("sid-obj",)

        def ConvertSidToStringSid(self, sid):
            return "S-1-5-21-user"

        def RevertToSelf(self):
            calls.append("revert")

        def GetCurrentThread(self):
            return "thread"

    fake = FakeWin32()
    sid = _windows_connected_client_sid(
        "pipe-handle", fake, fake, fake, SimpleNamespace(TOKEN_QUERY=8)
    )
    assert sid == "S-1-5-21-user"
    assert calls[0] == ("impersonate", "pipe-handle")
    assert "thread_token" in calls
    assert calls[-1] == "revert"


def test_windows_connected_client_sid_reverts_on_failure() -> None:
    from types import SimpleNamespace

    from cana_engine.pipe import _windows_connected_client_sid

    calls = []

    class FakeWin32:
        def ImpersonateNamedPipeClient(self, handle):
            calls.append("impersonate")

        def OpenThreadToken(self, thread, access, open_as_self):
            raise OSError("no thread token")

        def RevertToSelf(self):
            calls.append("revert")

        def GetCurrentThread(self):
            return "thread"

    fake = FakeWin32()
    with pytest.raises(OSError):
        _windows_connected_client_sid(
            "pipe-handle", fake, fake, fake, SimpleNamespace(TOKEN_QUERY=8)
        )
    assert calls == ["impersonate", "revert"]


def test_allowlisted_config_persists(tmp_path) -> None:
    engine = _engine(tmp_path)
    path = tmp_path / "cana.json"
    handler = PipeCommandHandler(
        engine, {SID_SYSTEM}, persist=True, config_path=path
    )
    server = InProcessPipeServer(handler)
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"packet_filter": "TCP"}}
    )
    assert result["ok"] is True
    assert engine.config.packet_filter == "TCP"
    loaded = load_config(path)
    assert loaded.packet_filter == "TCP"


def test_invalid_apply_config_leaves_runtime_and_disk(tmp_path) -> None:
    engine = _engine(tmp_path)
    path = tmp_path / "cana.json"
    handler = PipeCommandHandler(
        engine, {SID_SYSTEM}, persist=True, config_path=path
    )
    server = InProcessPipeServer(handler)
    server.request(
        SID_SYSTEM, "apply_config", {"config": {"packet_filter": "TCP"}}
    )
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"packet_filter": "FTP"}}
    )
    assert result["ok"] is False
    assert engine.config.packet_filter == "TCP"
    assert load_config(path).packet_filter == "TCP"


def test_status_and_get_config_commands(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    status = server.request(SID_SYSTEM, "status")
    assert status["ok"] is True
    assert "display_state" in status
    config = server.request(SID_SYSTEM, "get_config")
    assert config["ok"] is True
    assert "control_token" not in (config.get("config") or {})


def test_start_does_not_mutate_if_persist_fails(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    path = tmp_path / "cana.json"
    handler = PipeCommandHandler(
        engine, {SID_SYSTEM}, persist=True, config_path=path
    )

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("cana_engine.pipe.save_config", boom)
    server = InProcessPipeServer(handler)
    result = server.request(SID_SYSTEM, "start")
    assert result["ok"] is False
    assert engine.config.monitoring_enabled is False
    assert engine.status().running is False


def test_stop_does_not_mutate_if_persist_fails(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    path = tmp_path / "cana.json"
    handler = PipeCommandHandler(
        engine, {SID_SYSTEM}, persist=True, config_path=path
    )
    server = InProcessPipeServer(handler)
    started = server.request(SID_SYSTEM, "start")
    assert started["ok"] is True
    assert engine.config.monitoring_enabled is True
    try:
        def boom(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr("cana_engine.pipe.save_config", boom)
        result = server.request(SID_SYSTEM, "stop")
        assert result["ok"] is False
        assert engine.config.monitoring_enabled is True
    finally:
        engine.stop()


def test_apply_config_rolls_back_disk_if_replace_fails(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    path = tmp_path / "cana.json"
    handler = PipeCommandHandler(
        engine, {SID_SYSTEM}, persist=True, config_path=path
    )
    server = InProcessPipeServer(handler)
    server.request(
        SID_SYSTEM, "apply_config", {"config": {"packet_filter": "TCP"}}
    )
    assert load_config(path).packet_filter == "TCP"

    def boom(candidate, wait=True):
        raise RuntimeError("apply failed")

    monkeypatch.setattr(engine, "replace_config", boom)
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"packet_filter": "UDP"}}
    )
    assert result["ok"] is False
    assert load_config(path).packet_filter == "TCP"
    assert engine.config.packet_filter == "TCP"


def test_admins_group_sid_is_not_treated_as_token_user(tmp_path) -> None:
    from cana_engine.pipe import SID_ADMINS

    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM, SID_ADMINS}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(SID_ADMINS, "status")
    assert result["ok"] is False
    assert result["status"] == 403


def test_admin_group_membership_allows_personal_sid(tmp_path) -> None:
    from cana_engine.pipe import SID_ADMINS

    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM, SID_ADMINS}, persist=False)
    server = InProcessPipeServer(handler)
    personal = "S-1-5-21-111-222-333-1001"
    denied = server.request(personal, "status", is_admin=False)
    assert denied["ok"] is False
    assert denied["status"] == 403
    allowed = server.request(personal, "status", is_admin=True)
    assert allowed["ok"] is True


def test_windows_connected_client_identity_uses_group_membership() -> None:
    from types import SimpleNamespace

    from cana_engine.pipe import _windows_connected_client_identity

    class FakeWin32:
        TokenUser = 1

        def ImpersonateNamedPipeClient(self, handle):
            return None

        def OpenThreadToken(self, thread, access, open_as_self):
            assert open_as_self is False
            return "token"

        def GetTokenInformation(self, token, info):
            return ("sid-obj",)

        def ConvertSidToStringSid(self, sid):
            return "S-1-5-21-111-222-333-1001"

        def ConvertStringSidToSid(self, sid):
            return "admins-sid"

        def CheckTokenMembership(self, token, sid):
            assert token == "token"
            assert sid == "admins-sid"
            return True

        def RevertToSelf(self):
            return None

        def GetCurrentThread(self):
            return "thread"

    fake = FakeWin32()
    sid, is_admin = _windows_connected_client_identity(
        "pipe-handle", fake, fake, fake, SimpleNamespace(TOKEN_QUERY=8)
    )
    assert sid == "S-1-5-21-111-222-333-1001"
    assert is_admin is True


def test_pipe_client_requests_impersonation() -> None:
    from types import SimpleNamespace

    from cana_engine.pipe import _pipe_client_security_flags

    flags = _pipe_client_security_flags(SimpleNamespace())
    assert flags & 0x00100000  # SECURITY_SQOS_PRESENT
    assert flags & 0x00020000  # SECURITY_IMPERSONATION


def test_windows_pipe_request_uses_security_flags() -> None:
    import inspect

    from cana_engine.pipe import _windows_pipe_request

    source = inspect.getsource(_windows_pipe_request)
    assert "_pipe_client_security_flags" in source


def test_read_pipe_message_rejects_error_more_data() -> None:
    from cana_engine.pipe import PipeProtocolError, _read_pipe_message

    class FakeError(Exception):
        pass

    class FakePywin:
        error = FakeError

    class FakeFile:
        ERROR_MORE_DATA = 234

        def ReadFile(self, handle, size):
            raise FakeError(234, "more data")

    with pytest.raises(PipeProtocolError) as caught:
        _read_pipe_message(FakeFile(), FakePywin(), "handle")
    assert caught.value.status == 413


def test_token_is_admin_requires_enabled_group() -> None:
    from cana_engine.pipe import SID_ADMINS, _token_is_admin

    class FakeWin32:
        TokenGroups = 2
        SE_GROUP_ENABLED = 0x00000004

        def ConvertStringSidToSid(self, sid):
            assert sid == SID_ADMINS
            return "admins-sid"

        def CheckTokenMembership(self, token, sid):
            raise OSError("CheckTokenMembership unavailable")

        def GetTokenInformation(self, token, info):
            assert info == self.TokenGroups
            return [
                ("admins-sid", 0),
            ]

        def ConvertSidToStringSid(self, sid):
            return SID_ADMINS

    assert _token_is_admin(FakeWin32(), "token") is False


def test_token_is_admin_accepts_enabled_group_fallback() -> None:
    from cana_engine.pipe import SID_ADMINS, _token_is_admin

    class FakeWin32:
        TokenGroups = 2
        SE_GROUP_ENABLED = 0x00000004

        def ConvertStringSidToSid(self, sid):
            return "admins-sid"

        def CheckTokenMembership(self, token, sid):
            raise OSError("CheckTokenMembership unavailable")

        def GetTokenInformation(self, token, info):
            return [("admins-sid", 0x00000004)]

        def ConvertSidToStringSid(self, sid):
            return SID_ADMINS

    assert _token_is_admin(FakeWin32(), "token") is True


def test_oversized_request_rejected_before_handle(tmp_path) -> None:
    from cana_engine.pipe import PIPE_MAX_MESSAGE_BYTES, PipeProtocolError, _decode_pipe_body

    raw = b"{" + (b"a" * (PIPE_MAX_MESSAGE_BYTES + 1))
    try:
        _decode_pipe_body(raw)
        assert False, "oversized body must be rejected"
    except PipeProtocolError as exc:
        assert exc.status == 413


def test_pipe_response_is_capped(tmp_path) -> None:
    from cana_engine.pipe import PIPE_MAX_MESSAGE_BYTES, encode_pipe_response

    payload = {"ok": True, "data": "x" * (PIPE_MAX_MESSAGE_BYTES * 2)}
    encoded = encode_pipe_response(payload)
    assert len(encoded) <= PIPE_MAX_MESSAGE_BYTES
    import json

    body = json.loads(encoded.decode("utf-8"))
    assert body["ok"] is False
    assert body["status"] == 413


def test_apply_config_updates_windows_startup_type(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    calls = []

    def fake_startup(automatic: bool) -> None:
        calls.append(automatic)

    monkeypatch.setattr("cana_engine.pipe._apply_windows_startup_type", fake_startup)
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"automatic_startup": False}}
    )
    assert result["ok"] is True
    assert engine.config.automatic_startup is False
    assert calls == [False]


def test_apply_config_automatic_startup_does_not_start_monitoring(tmp_path, monkeypatch) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=True,
        automatic_startup=True,
        packet_filter="ALL",
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    monkeypatch.setattr("cana_engine.pipe._apply_windows_startup_type", lambda automatic: None)
    assert engine.status().running is False
    result = server.request(
        SID_SYSTEM, "apply_config", {"config": {"automatic_startup": False}}
    )
    assert result["ok"] is True
    assert engine.config.automatic_startup is False
    assert engine.config.monitoring_enabled is True
    assert engine.status().running is False


def test_apply_windows_startup_type_uses_registered_service_name(monkeypatch) -> None:
    from cana_engine.pipe import _apply_windows_startup_type
    from cana_service.constants import SERVICE_NAME

    calls = {}

    class Result:
        returncode = 0
        stdout = "SUCCESS"
        stderr = ""

    def fake_run(*args, **kwargs):
        calls["args"] = args[0]
        return Result()

    monkeypatch.setattr("cana_engine.pipe.os.name", "nt")
    monkeypatch.setattr("subprocess.run", fake_run)
    _apply_windows_startup_type(False)
    assert calls["args"][0] == "sc.exe"
    assert calls["args"][1] == "config"
    assert calls["args"][2] == SERVICE_NAME
    assert "demand" in calls["args"]


def test_impersonate_named_pipe_client_prefers_win32security() -> None:
    import inspect

    from cana_engine.pipe import _impersonate_named_pipe_client, _windows_connected_client_identity

    identity = inspect.getsource(_windows_connected_client_identity)
    helper = inspect.getsource(_impersonate_named_pipe_client)
    assert "_impersonate_named_pipe_client" in identity
    assert "win32security" in helper
    assert "ImpersonateNamedPipeClient" in helper


def test_impersonate_named_pipe_client_uses_security_module() -> None:
    from cana_engine.pipe import _impersonate_named_pipe_client

    calls = []

    class Pipe:
        def ImpersonateNamedPipeClient(self, handle):
            calls.append(("pipe", handle))

    class Security:
        def ImpersonateNamedPipeClient(self, handle):
            calls.append(("security", handle))

    _impersonate_named_pipe_client("handle", Security(), Pipe())
    assert calls == [("security", "handle")]


def test_impersonate_falls_back_to_win32pipe_if_security_lacks_api() -> None:
    from cana_engine.pipe import _impersonate_named_pipe_client

    calls = []

    class Pipe:
        def ImpersonateNamedPipeClient(self, handle):
            calls.append(("pipe", handle))

    class Security:
        pass

    _impersonate_named_pipe_client("handle", Security(), Pipe())
    assert calls == [("pipe", "handle")]


def test_impersonation_failure_is_not_reported_as_forbidden() -> None:
    import inspect

    from cana_engine.pipe import NamedPipeServer

    source = inspect.getsource(NamedPipeServer._serve)
    fail_at = source.index("PIPE_IMPERSONATION_FAILED")
    chunk = source[fail_at : fail_at + 280]
    assert '"forbidden"' not in chunk
    assert "could not identify caller" in chunk


def test_pipe_server_disconnects_client_after_response() -> None:
    import inspect

    from cana_engine.pipe import NamedPipeServer, _release_pipe_client

    source = inspect.getsource(NamedPipeServer._serve)
    helper = inspect.getsource(_release_pipe_client)
    assert "_release_pipe_client" in source
    assert "DisconnectNamedPipe" in helper
    assert "FlushFileBuffers" not in helper


def test_denied_sid_is_forbidden_not_impersonation_failure(tmp_path) -> None:
    from cana_engine.pipe import PipeProtocolError

    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    with pytest.raises(PipeProtocolError) as caught:
        handler.handle("S-1-5-21-other", "status")
    assert caught.value.status == 403
    assert "forbidden" in str(caught.value).lower()


def test_empty_caller_sid_is_forbidden(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    with pytest.raises(Exception) as caught:
        handler.handle("", "status")
    assert "forbidden" in str(caught.value).lower()


def test_classify_pipe_io_error_does_not_call_busy_forbidden() -> None:
    from cana_engine.ipc import (
        PIPE_RECONNECT,
        SERVICE_UNAVAILABLE,
        classify_pipe_io_error,
    )

    busy = OSError(231, "All pipe instances are busy")
    busy.winerror = 231
    mapped = classify_pipe_io_error(busy)
    assert str(mapped) == PIPE_RECONNECT
    assert mapped.status == 503
    assert "forbidden" not in str(mapped).lower()

    missing = OSError(2, "The system cannot find the file specified")
    missing.winerror = 2
    mapped = classify_pipe_io_error(missing)
    assert str(mapped) == SERVICE_UNAVAILABLE

    denied = OSError(5, "Access is denied")
    denied.winerror = 5
    mapped = classify_pipe_io_error(denied)
    assert "permission" in str(mapped).lower()
    assert mapped.status == 403

    mapped = classify_pipe_io_error(BrokenPipeError())
    assert str(mapped) == PIPE_RECONNECT

    not_connected = OSError(233, "No process is on the other end of the pipe")
    not_connected.winerror = 233
    mapped = classify_pipe_io_error(not_connected)
    assert str(mapped) == PIPE_RECONNECT

    no_data = OSError(232, "The pipe is being closed")
    no_data.winerror = 232
    mapped = classify_pipe_io_error(no_data)
    assert str(mapped) == PIPE_RECONNECT


def test_pipe_server_has_start_stop_join(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    server.start()
    server.stop()
    server.join(timeout=0.1)


def test_windows_connected_client_sid_reverts_when_impersonation_fails() -> None:
    from types import SimpleNamespace

    from cana_engine.pipe import _windows_connected_client_sid

    calls = []

    class FakeWin32:
        def ImpersonateNamedPipeClient(self, handle):
            calls.append("impersonate")
            raise OSError("impersonation denied")

        def RevertToSelf(self):
            calls.append("revert")

        def GetCurrentThread(self):
            return "thread"

    fake = FakeWin32()
    with pytest.raises(OSError):
        _windows_connected_client_sid(
            "pipe-handle", fake, fake, fake, SimpleNamespace(TOKEN_QUERY=8)
        )
    assert calls == ["impersonate", "revert"]


def test_snapshot_includes_correlated_list(tmp_path) -> None:
    engine = _engine(tmp_path)
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    result = server.request(SID_SYSTEM, "snapshot")
    assert result["ok"] is True
    assert isinstance(result.get("correlated"), list)


def test_pipe_start_after_stop_recreates_worker(tmp_path) -> None:
    """Stop then Start over the pipe must actually start a new session."""

    started: list = []

    def runner(settings, stop_event=None, engine_out=None, **kwargs):
        started.append(settings)
        class Fake:
            def stop(self):
                if stop_event is not None:
                    stop_event.set()

            def is_running(self):
                return stop_event is None or not stop_event.is_set()

            stats = type("S", (), {"packets_dropped_queue_full": 0})()

        if engine_out is not None:
            engine_out["engine"] = Fake()
        if stop_event is not None:
            stop_event.wait(3)
        return []

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
        packet_filter="ALL",
    )
    engine = CANAEngine(
        config,
        capture_runner=runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    try:
        first = server.request(SID_SYSTEM, "start")
        assert first["ok"] is True
        deadline = time.time() + 3
        while not engine.status().capture_active and time.time() < deadline:
            time.sleep(0.05)
        assert engine.status().running is True
        assert engine.health().selected_interface == "Ethernet"

        stopped = server.request(SID_SYSTEM, "stop")
        assert stopped["ok"] is True
        assert engine.status().running is False

        second = server.request(SID_SYSTEM, "start")
        assert second["ok"] is True
        deadline = time.time() + 3
        while len(started) < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert len(started) == 2
        deadline = time.time() + 3
        while not engine.status().capture_active and time.time() < deadline:
            time.sleep(0.05)
        assert engine.status().running is True
        assert engine.status().capture_active is True
        assert engine.health().selected_interface == "Ethernet"
    finally:
        engine.stop()
