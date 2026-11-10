"""Native UI controller tests. The UI is a client of the service pipe."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from packet_capture.interface import NetworkInterface
from cana_engine.client import ControlClient
from cana_engine.config import CANAConfig
from cana_engine.engine import CANAEngine
from cana_engine.ipc import PipeClient, SID_SYSTEM
from cana_engine.pipe import InProcessPipeServer, PipeCommandHandler
from cana_service.constants import SERVICE_NAME
from cana_ui.controller import (
    UIController,
    _run_sc,
    classify_scm_state,
    display_state_for,
    header_status,
    query_windows_service,
    query_windows_service_state,
    request_windows_service_install,
    runtime_states,
    try_start_windows_service,
)
from cana_ui.traffic import SessionTrafficStore
from cana_ui.window import (
    CANAWindow,
    alert_meta,
    alert_sentence,
    alerts_source_caption,
    apps_source_caption,
    apps_source_subtitle,
    history_source_caption,
    home_actions,
    home_headline,
    status_bar_text,
    tray_status_text,
)


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


def _controller(engine: CANAEngine) -> tuple[UIController, CANAEngine]:
    handler = PipeCommandHandler(engine, {SID_SYSTEM}, persist=False)
    server = InProcessPipeServer(handler)
    pipe = PipeClient(
        transport=lambda command, payload: server.request(SID_SYSTEM, command, payload)
    )
    client = ControlClient(pipe_client=pipe)
    return UIController(client), engine


def test_control_client_preserves_pipe_protocol_message() -> None:
    from cana_engine.client import ControlClient, ControlClientError
    from cana_engine.ipc import PipeProtocolError

    class ForbiddenPipe:
        def request(self, command, payload=None):
            raise PipeProtocolError("forbidden", 403)

    client = ControlClient(pipe_client=ForbiddenPipe())  # type: ignore[arg-type]
    with pytest.raises(ControlClientError) as caught:
        client.snapshot()
    assert "forbidden" in str(caught.value).lower()


def test_user_facing_error_hides_raw_windows_exceptions() -> None:
    from cana_ui.controller import user_facing_error

    assert "pywintypes" not in user_facing_error("pywintypes.error: (5, 'CreateFile', 'Access is denied.')").lower()
    assert "traceback" not in user_facing_error("Traceback (most recent call last)").lower()
    assert "1056" not in user_facing_error("WinError 1056")
    permission = user_facing_error("forbidden")
    assert "permission" in permission.lower()
    reconnect = user_facing_error("could not identify caller")
    assert "reconnect" in reconnect.lower() or "unavailable" in reconnect.lower()
    assert user_facing_error("CANA couldn't start monitoring.").startswith("CANA")


def test_snapshot_keeps_running_service_when_pipe_drops(monkeypatch) -> None:
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "RUNNING"
    )

    class Flaky:
        def snapshot(self):
            from cana_engine.client import ControlClientError

            raise ControlClientError("CANA service connection was temporarily unavailable. Reconnecting...")

    ui = UIController(Flaky())  # type: ignore[arg-type]
    ui.last_payload = {
        "ok": True,
        "state": "protected",
        "scm_state": "RUNNING",
        "service_unavailable": False,
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
        "service_health": {"service_alive": True, "engine_alive": True, "capture_alive": True},
    }
    payload = ui.snapshot()
    assert payload["service_unavailable"] is False
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "running"
    assert "reconnect" in str(payload["last_error"]).lower() or "unavailable" in str(payload["last_error"]).lower()
    assert display_state_for(payload) != "Service Not Running"


def test_ui_close_does_not_stop_service_or_monitoring() -> None:
    import inspect

    destroy = inspect.getsource(CANAWindow.destroy)
    hide = inspect.getsource(CANAWindow.hide)
    for source in (destroy, hide):
        assert "stop_monitoring" not in source
        assert "try_stop" not in source
        assert "sc.exe" not in source
        assert "StopService" not in source
    from cana_ui.app import run_ui, _start_tray

    run_source = inspect.getsource(run_ui)
    tray = inspect.getsource(_start_tray)
    assert "stop_monitoring" not in run_source
    exit_start = tray.index("def exit_ui")
    exit_end = tray.index("menu = pystray.Menu")
    assert "stop_monitoring" not in tray[exit_start:exit_end]


def test_tray_actions_are_marshalled_onto_the_ui_thread() -> None:
    import inspect

    from cana_ui.app import _start_tray

    source = inspect.getsource(_start_tray)
    assert "after(0" in source
    assert "def _on_ui" in source
    open_at = source.index("def open_cana")
    marshal_prefix = source[source.index("def _on_ui"):open_at]
    assert "after(0" in marshal_prefix


def test_ui_client_modules_do_not_import_engine() -> None:
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "cana_ui"
    banned = (
        "cana_engine.engine",
        "cana_engine.pipe",
        "CANAEngine",
        "cana_service.service",
        "anomaly_detection.logger",
        "risk_scoring.correlator",
        "packet_capture.capture",
    )
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in banned, path.name
                assert not node.module.startswith("cana_engine.engine")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in banned


def test_ui_handles_service_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "UNKNOWN"
    )

    class DeadClient:
        def snapshot(self):
            from cana_engine.client import ControlClientError

            raise ControlClientError("CANA service is not running.")

    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.snapshot()
    assert payload["service_unavailable"] is True
    assert payload.get("service_not_installed") is not True
    assert display_state_for(payload) == "Service Not Running"
    header = header_status(payload)
    assert header["service"] == "Not running"
    assert header["capture"] == "Unavailable"


def test_ui_displays_real_service_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    payload = ui.snapshot()
    assert payload.get("service_unavailable") is False
    assert "display_state" in payload
    header = header_status(payload)
    assert header["badge"]


def test_ui_start_stop_goes_through_pipe(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "UNKNOWN"
    )
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    started = ui.start_monitoring()
    assert started.get("ok") is not False
    assert started.get("monitoring_start_failed") is not True
    assert engine.config.monitoring_enabled is True
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    assert engine.status().running is True
    stopped = ui.stop_monitoring()
    assert engine.status().running is False
    assert engine.config.monitoring_enabled is False
    assert stopped.get("service_unavailable") is not True


def test_closing_ui_does_not_stop_engine(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    ui.start_monitoring()
    assert engine.config.monitoring_enabled is True
    del ui
    assert engine.status().running or engine.config.monitoring_enabled is True
    engine.stop()


def test_ui_settings_valid_and_invalid(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    accepted = ui.apply_config({"packet_filter": "TCP"})
    assert accepted.get("ok") is True
    assert engine.config.packet_filter == "TCP"
    try:
        ui.apply_config({"packet_filter": "FTP"})
        assert False, "invalid config must be rejected"
    except Exception:
        pass
    assert engine.config.packet_filter == "TCP"


def test_try_start_windows_service_uses_runner() -> None:
    calls = []

    def runner():
        calls.append("start")

    assert try_start_windows_service(runner) == ""
    assert calls == ["start"]


def test_request_windows_service_install_accepts_elevation(monkeypatch) -> None:
    monkeypatch.setattr("cana_ui.controller.sys.frozen", True, raising=False)
    calls = []

    def launcher(executable: str, parameters: str) -> int:
        calls.append((executable, parameters))
        return 0

    assert request_windows_service_install(launcher, is_windows=True) == ""
    assert calls
    assert "--install-service" in calls[0][1]


def test_control_client_does_not_fall_back_to_http() -> None:
    from cana_engine.client import ControlClientError
    from cana_engine.ipc import PipeProtocolError

    class DeadPipe:
        def request(self, command, payload=None):
            raise PipeProtocolError("no pipe")

    client = ControlClient(pipe_client=DeadPipe())  # type: ignore[arg-type]
    try:
        client.status()
        assert False, "pipe failure must not fall back to HTTP"
    except ControlClientError:
        pass
    try:
        client.snapshot()
        assert False, "pipe failure must not fall back to HTTP"
    except ControlClientError:
        pass


def test_native_window_uses_native_menubar() -> None:
    import inspect

    from cana_ui.window import _MENUS

    source = inspect.getsource(CANAWindow._build_menu_bar)
    assert "root.config(menu=" in source
    assert "tk.Label" not in source
    assert list(_MENUS) == ["File", "View", "Tools", "Help"]
    file_labels = [row[0] for row in _MENUS["File"]]
    assert "Start service" in file_labels
    assert "Start monitoring" in file_labels
    assert "Stop monitoring" in file_labels
    assert "Exit" in file_labels
    help_labels = [row[0] for row in _MENUS["Help"]]
    assert "View technical details" in help_labels
    assert hasattr(CANAWindow, "_sync_menu_state")
    assert not hasattr(CANAWindow, "_post_menu")


def test_tray_uses_cana_mark_not_generic_circle() -> None:
    import inspect

    from cana_ui.app import _tray_image

    source = inspect.getsource(_tray_image)
    assert "cana_ui.brand" in source
    assert "ellipse" not in source


def test_brand_icon_assets_are_real_images() -> None:
    from cana_ui.brand import ICON_ICO, ICON_PNG, render_mark

    assert ICON_PNG.is_file()
    assert ICON_ICO.is_file()
    assert ICON_PNG.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert ICON_ICO.read_bytes()[:4] == b"\x00\x00\x01\x00"
    pixels = render_mark(32)
    assert len(pixels) == 32 * 32 * 4
    assert any(pixels[i + 3] for i in range(0, len(pixels), 4))


def test_brand_assets_are_the_blue_feather() -> None:
    import struct

    from cana_ui.brand import ICON_ICO, ICON_PNG, _decode_png_rgba

    width, height, pixels = _decode_png_rgba(ICON_PNG.read_bytes())
    assert (width, height) == (256, 256)

    def rgba(x: int, y: int) -> tuple:
        index = (y * width + x) * 4
        return pixels[index], pixels[index + 1], pixels[index + 2], pixels[index + 3]

    # Transparent background at the corners, blue feather in the middle.
    assert rgba(0, 0)[3] == 0
    assert rgba(width - 1, 0)[3] == 0
    assert rgba(0, height - 1)[3] == 0
    assert rgba(width - 1, height - 1)[3] == 0
    blue = 0
    for i in range(0, len(pixels), 4):
        r, g, b, a = pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3]
        if a > 128 and b > r and b > g and b > 80:
            blue += 1
    assert blue > 500

    assert ICON_ICO.read_bytes()[:4] == b"\x00\x00\x01\x00"
    count = struct.unpack("<H", ICON_ICO.read_bytes()[4:6])[0]
    assert count >= 4
    ico = ICON_ICO.read_bytes()
    sizes = set()
    for i in range(count):
        entry = 6 + i * 16
        sizes.add(ico[entry] or 256)
    assert {16, 32, 48, 256} <= sizes


def test_brand_module_no_longer_draws_the_old_shield() -> None:
    import inspect

    from cana_ui import brand

    source = inspect.getsource(brand).lower()
    assert "shield" not in source
    assert "_fill_poly" not in source
    assert "cana-source.png" in source


def test_header_shows_the_feather_mark() -> None:
    import inspect

    from cana_ui.window import CANAWindow

    source = inspect.getsource(CANAWindow._build_header)
    assert "header_photo" in source


def test_chart_autoscales_empty_single_and_large_values() -> None:
    from cana_ui.widgets import nice_peak, series_points

    assert nice_peak([]) == 1.0
    assert nice_peak([0, 0]) == 1.0
    assert nice_peak([1]) == 1.0
    assert nice_peak([3]) == 5.0
    assert nice_peak([999]) == 1000.0
    assert series_points([], 1, 0, 0, 100, 50) == []
    single = series_points([10], 10, 0, 0, 100, 50)
    assert single == [0, 0.0, 100, 0.0]
    tiny = series_points([1], 1000, 0, 0, 100, 50)
    assert tiny[1] == 50 - 0.05
    wide = series_points([0, 50, 100], 100, 10, 0, 80, 40)
    assert wide[0] == 10
    assert wide[-2] == 90
    assert wide[-1] == 0.0


def test_native_window_class_exists() -> None:
    assert CANAWindow is not None
    assert hasattr(CANAWindow, "create")
    assert hasattr(CANAWindow, "hide")
    assert hasattr(CANAWindow, "destroy")
    assert hasattr(CANAWindow, "_run_off_thread")


def test_native_window_is_status_control_not_dashboard() -> None:
    import inspect

    source = inspect.getsource(CANAWindow)
    assert "Dashboard" not in source
    assert "_build_dashboard" not in source
    assert "_show_dashboard" not in source
    assert "nav_dash" not in source
    assert hasattr(CANAWindow, "_build_status")
    assert hasattr(CANAWindow, "_show_status")
    assert hasattr(CANAWindow, "_open_settings")
    assert hasattr(CANAWindow, "_build_history")
    assert hasattr(CANAWindow, "_render_history")
    assert not hasattr(CANAWindow, "_build_dashboard")
    assert not hasattr(CANAWindow, "_show_dashboard")
    from cana_ui.window import _NAV_ITEMS

    assert ("history", "History") in _NAV_ITEMS


def test_header_status_includes_monitoring_and_detection() -> None:
    payload = {
        "state": "protected",
        "display_state": "Protected",
        "running": True,
        "capture_active": True,
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "database_available": True,
            "monitoring_enabled": True,
        },
    }
    header = header_status(payload)
    assert header["badge"] == "Protected"
    assert header["service"] == "Running"
    assert header["monitoring"] == "Active"
    assert header["detection"] == "Active"
    assert header["capture"] == "Active"


def test_header_status_stopped_is_not_protected() -> None:
    payload = {
        "state": "stopped",
        "running": False,
        "capture_active": False,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "database_available": True,
            "monitoring_enabled": False,
        },
    }
    header = header_status(payload)
    assert header["badge"] == "Stopped"
    assert header["monitoring"] == "Stopped"
    assert header["detection"] == "Inactive"
    assert header["capture"] == "Stopped"


def test_try_start_windows_service_sets_timeout(monkeypatch) -> None:
    calls = []
    queries = {"n": 0}

    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        argv = args[0]
        if argv[1] == "query":
            queries["n"] += 1
            if queries["n"] == 1:
                return Result(0, stdout="STATE              : 1  STOPPED")
            return Result(0, stdout="STATE              : 4  RUNNING")
        return Result(0, stdout="STATE              : 2  START_PENDING")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert try_start_windows_service() == ""
    start = [item for item in calls if item["args"][0][1] == "start"]
    assert start
    kwargs = start[0]["kwargs"]
    assert kwargs.get("timeout") is not None
    assert kwargs["timeout"] > 0
    assert start[0]["args"][0][0] == "sc.exe"
    assert start[0]["args"][0][2] == SERVICE_NAME
    assert all(item["kwargs"].get("timeout") for item in calls)


def test_run_sc_isolates_stdin_and_suppresses_window(monkeypatch) -> None:
    import os
    import subprocess

    captured = {}

    class Result:
        returncode = 0
        stdout = "STATE              : 4  RUNNING"
        stderr = ""

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return Result()

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setattr(subprocess, "run", fake_run)
    _run_sc("query", SERVICE_NAME)
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["creationflags"] == getattr(
        subprocess, "CREATE_NO_WINDOW", 0x08000000
    )
    assert captured["args"][0] == ["sc.exe", "query", SERVICE_NAME]


def test_run_sc_posix_omits_creationflags(monkeypatch) -> None:
    import os
    import subprocess

    captured = {}

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(*args, **kwargs):
        captured["kwargs"] = kwargs
        return Result()

    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(subprocess, "run", fake_run)
    _run_sc("query", SERVICE_NAME)
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["creationflags"] == 0


def test_try_start_windows_service_empty_stdout_is_unknown(monkeypatch) -> None:
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(*args, **kwargs):
        calls.append(args[0])
        return Result()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    message = try_start_windows_service()
    assert "unknown" in message.lower()
    assert all(item[1] != "start" for item in calls)


def test_try_start_windows_service_treats_1056_as_success(monkeypatch) -> None:
    class Result:
        def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(*args, **kwargs):
        argv = args[0]
        if argv[1] == "query":
            return Result(0, stdout="STATE              : 1  STOPPED")
        return Result(1056, stdout="[SC] StartService FAILED 1056")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert try_start_windows_service() == "already_running"


def test_try_start_windows_service_skips_start_when_running(monkeypatch) -> None:
    calls = []

    class Result:
        returncode = 0
        stdout = "STATE              : 4  RUNNING"
        stderr = ""

    def fake_run(*args, **kwargs):
        calls.append(args[0])
        return Result()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert try_start_windows_service() == "already_running"
    assert all(item[1] != "start" for item in calls)


def test_try_start_windows_service_reports_not_installed(monkeypatch) -> None:
    class Result:
        returncode = 1060
        stdout = "[SC] StartService FAILED 1060"
        stderr = ""

    def fake_run(*args, **kwargs):
        return Result()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    message = try_start_windows_service()
    assert message
    assert "not installed" in message.lower()


def test_snapshot_shows_running_when_scm_running_and_pipe_down(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    class DeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "RUNNING"
    )
    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.snapshot()
    assert payload["service_unavailable"] is False
    assert payload["health"]["service_alive"] is True
    assert display_state_for(payload) != "Service Not Running"
    header = header_status(payload)
    assert header["service"] == "Running"
    assert header["badge"] != "Service Not Running"
    info = home_headline(payload, header)
    assert info["title"] != "Service unavailable"


def test_control_client_times_out_when_pipe_hangs() -> None:
    import time

    from cana_engine.client import ControlClientError

    class HangPipe:
        def request(self, command, payload=None):
            time.sleep(5)
            return {"ok": True}

    client = ControlClient(timeout=0.2, pipe_client=HangPipe())  # type: ignore[arg-type]
    started = time.monotonic()
    with pytest.raises(ControlClientError):
        client.snapshot()
    assert time.monotonic() - started < 1.0


def test_control_client_maps_broken_pipe_to_reconnect() -> None:
    from cana_engine.client import ControlClientError
    from cana_engine.ipc import PIPE_RECONNECT, PipeProtocolError

    class Broken:
        def request(self, command, payload=None):
            raise BrokenPipeError()

    client = ControlClient(timeout=0.2, pipe_client=Broken())  # type: ignore[arg-type]
    with pytest.raises(ControlClientError) as caught:
        client.snapshot()
    assert str(caught.value) == PIPE_RECONNECT

    class ProtocolBusy:
        def request(self, command, payload=None):
            raise PipeProtocolError(PIPE_RECONNECT, 503)

    client = ControlClient(timeout=0.2, pipe_client=ProtocolBusy())  # type: ignore[arg-type]
    with pytest.raises(ControlClientError) as caught:
        client.snapshot()
    assert str(caught.value) == PIPE_RECONNECT
    assert "forbidden" not in str(caught.value).lower()


def test_settings_load_does_not_block_on_pipe() -> None:
    import inspect

    source = inspect.getsource(CANAWindow._load_settings)
    assert "get_config" not in source
    assert "snapshot" not in source
    open_source = inspect.getsource(CANAWindow._open_settings)
    assert "get_config()" not in open_source


def test_window_ipc_actions_run_off_thread() -> None:
    import inspect

    for name in ("_on_start", "_on_stop", "_on_start_service", "_on_apply_settings"):
        source = inspect.getsource(getattr(CANAWindow, name))
        assert "_run_off_thread" in source
        assert "force=True" in source
    refresh = inspect.getsource(CANAWindow.refresh)
    assert "_run_off_thread" in refresh
    assert "force=True" not in refresh
    settings = inspect.getsource(CANAWindow._open_settings)
    assert "force=True" in settings


def test_tray_menu_does_not_stop_service_on_exit() -> None:
    import inspect

    from cana_ui.app import _start_tray, run_ui

    source = inspect.getsource(_start_tray)
    assert "Open CANA" in source
    assert "Start Monitoring" in source
    assert "Stop Monitoring" in source
    assert "Settings" in source
    assert "Exit" in source
    exit_start = source.index("def exit_ui")
    exit_end = source.index("menu = pystray.Menu")
    exit_fn = source[exit_start:exit_end]
    assert "stop_monitoring" not in exit_fn
    run_source = inspect.getsource(run_ui)
    assert "stop_monitoring" not in run_source


def test_run_ui_does_not_open_a_browser() -> None:
    import inspect

    from cana_ui.app import run_ui

    source = inspect.getsource(run_ui)
    assert "open_browser" not in source
    assert "webbrowser" not in source


def test_configure_ui_logging_writes_a_log_file(tmp_path) -> None:
    import logging

    import cana_ui.app as app_module

    app_module._ui_handler = None
    logger = app_module.configure_ui_logging(tmp_path)
    logger.info("hello-from-test")
    for handler in logger.handlers:
        handler.flush()
    assert (tmp_path / "cana_ui.log").read_text(encoding="utf-8").strip()
    app_module._ui_handler = None
    logger.handlers.clear()


def test_configure_ui_logging_never_raises_on_bad_dir(tmp_path) -> None:
    import cana_ui.app as app_module

    app_module._ui_handler = None
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    logger = app_module.configure_ui_logging(blocker)
    assert logger is not None
    app_module._ui_handler = None
    logger.handlers.clear()


def test_run_ui_installs_excepthook_and_logger() -> None:
    import inspect

    from cana_ui.app import run_ui

    source = inspect.getsource(run_ui)
    assert "configure_ui_logging" in source
    assert "_install_ui_excepthook" in source
    assert "_install_tk_exception_logger" in source


def test_tk_exception_logger_routes_to_log(tmp_path) -> None:
    import logging

    import cana_ui.app as app_module

    app_module._ui_handler = None
    logger = app_module.configure_ui_logging(tmp_path)
    for handler in logger.handlers:
        handler.flush()

    class FakeRoot:
        def __init__(self) -> None:
            self.report_callback_exception = None

    class FakeWindow:
        _root = FakeRoot()

    app_module._install_tk_exception_logger(FakeWindow(), logger)
    assert callable(FakeWindow._root.report_callback_exception)
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        FakeWindow._root.report_callback_exception(*sys.exc_info())
    for handler in logger.handlers:
        handler.flush()
    text = (tmp_path / "cana_ui.log").read_text(encoding="utf-8")
    assert "UI_CALLBACK_EXCEPTION" in text
    assert "boom" in text
    app_module._ui_handler = None
    logger.handlers.clear()


def test_tk_exception_logger_no_root_is_safe() -> None:
    import logging

    import cana_ui.app as app_module

    class FakeWindow:
        _root = None

    app_module._install_tk_exception_logger(FakeWindow(), logging.getLogger("cana.ui"))
    assert FakeWindow._root is None


class _StubController:
    last_payload: dict = {}
    last_error = ""

    def snapshot(self):
        return dict(self.last_payload)


def _session_store_with_traffic(tmp_path: Path, now: float) -> SessionTrafficStore:
    recent = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 4 * 3600))
    older = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 2 * 86400))
    (tmp_path / "session_recent.json").write_text(
        json.dumps(
            {
                "packets": [
                    {
                        "application_name": "chrome.exe",
                        "packet_size": 400,
                        "direction": "OUTGOING",
                        "timestamp": recent,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "session_older.json").write_text(
        json.dumps(
            {
                "packets": [
                    {
                        "application_name": "Unknown",
                        "packet_size": 900,
                        "direction": "INCOMING",
                        "timestamp": older,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return SessionTrafficStore(tmp_path, ttl_seconds=0.0)


def test_collect_stamps_apps_range_and_real_totals(tmp_path: Path) -> None:
    now = time.time()
    window = CANAWindow(_StubController())
    window._traffic = _session_store_with_traffic(tmp_path, now)
    window._apps_range = "Month"
    bundle = window._collect()
    assert bundle["apps_range"] == "Month"
    names = {app.name: app.total_bytes for app in bundle["apps"]}
    assert names["chrome.exe"] == 400
    assert names["Unknown"] == 900
    history = bundle["history"]
    assert len(history) == 2
    assert {row["packet_count"] for row in history} == {1}


def test_apps_refresh_schedules_tk_after_on_ui_thread(tmp_path: Path) -> None:
    """Tk after() is not thread-safe; the UI thread must register the apply."""

    now = time.time()
    window = CANAWindow(_StubController())
    window._traffic = _session_store_with_traffic(tmp_path, now)
    window._closed = False
    window._apps_range = "24 Hours"
    window._selected_app = None
    rendered: list = []

    def capture(apps, series) -> None:
        rendered.append(
            (
                window._apps_range,
                [(app.name, app.total_bytes) for app in apps],
                bool(series) and not series.is_empty,
            )
        )

    window._render_apps = capture  # type: ignore[method-assign]
    ui_thread = threading.get_ident()

    class FakeRoot:
        def __init__(self) -> None:
            self.fns: list = []
            self.after_threads: list = []

        def after(self, _ms, fn):
            self.after_threads.append(threading.get_ident())
            self.fns.append(fn)

    root = FakeRoot()
    window._root = root  # type: ignore[assignment]
    window._refresh_apps_off_thread()
    assert root.after_threads, "apply must be scheduled from the UI thread"
    assert all(tid == ui_thread for tid in root.after_threads)

    deadline = time.time() + 3
    while time.time() < deadline and not rendered:
        fns = list(root.fns)
        root.fns.clear()
        for fn in fns:
            fn()
        time.sleep(0.02)
    assert rendered, "Apps results must reach _render_apps"
    assert rendered[-1][0] == "24 Hours"
    assert ("chrome.exe", 400) in rendered[-1][1]
    assert rendered[-1][2] is True

    window._on_range_change("Month")
    rendered.clear()
    deadline = time.time() + 3
    while time.time() < deadline and not rendered:
        fns = list(root.fns)
        root.fns.clear()
        for fn in fns:
            fn()
        time.sleep(0.02)
    assert rendered[-1][0] == "Month"
    names = dict(rendered[-1][1])
    assert names["chrome.exe"] == 400
    assert names["Unknown"] == 900

    window._on_range_change("3 Hours")
    rendered.clear()
    deadline = time.time() + 3
    while time.time() < deadline and not rendered:
        fns = list(root.fns)
        root.fns.clear()
        for fn in fns:
            fn()
        time.sleep(0.02)
    assert rendered[-1][0] == "3 Hours"
    assert rendered[-1][1] == []
    assert rendered[-1][2] is False


def test_ui_client_modules_do_not_load_engine_or_anomaly_logger() -> None:
    import importlib
    import sys

    blocked = {
        "cana_engine.engine",
        "cana_engine.pipe",
        "cana_engine.control",
        "cana_service.service",
        "cana_service.install",
        "risk_scoring.correlator",
        "anomaly_detection.rules",
        "anomaly_detection.logger",
    }
    saved = {
        name: module
        for name, module in sys.modules.items()
        if name in blocked
        or name.startswith(("cana_ui", "cana_engine.client", "cana_engine.ipc"))
    }
    for name in list(saved):
        sys.modules.pop(name, None)
    try:
        importlib.import_module("cana_engine.client")
        importlib.import_module("cana_ui.controller")
        importlib.import_module("cana_ui.app")
        loaded = set(sys.modules)
        for name in blocked:
            assert name not in loaded, name
    finally:
        for name in list(sys.modules):
            if name in saved or name.startswith(("cana_ui", "cana_engine.client", "cana_engine.ipc")):
                sys.modules.pop(name, None)
        sys.modules.update(saved)


def test_runtime_states_service_running_does_not_imply_monitoring() -> None:
    payload = {
        "state": "stopped",
        "running": False,
        "capture_active": False,
        "scm_state": "RUNNING",
        "has_session_data": True,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "database_available": True,
            "monitoring_enabled": False,
        },
    }
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "stopped"
    assert runtime["capture"] == "stopped"
    assert runtime["data_source"] == "historical"
    header = header_status(payload)
    assert header["service"] == "Running"
    assert header["monitoring"] == "Stopped"
    assert header["detection"] == "Inactive"
    assert header["badge"] == "Stopped"
    assert status_bar_text(payload) == "Monitoring stopped"
    assert apps_source_caption(payload, True) == "Historical application traffic"
    assert "previous CANA sessions" in apps_source_subtitle(payload, True)
    info = home_headline(payload, header)
    assert info["title"] == "Monitoring stopped"


def test_runtime_states_live_capture() -> None:
    payload = {
        "state": "protected",
        "running": True,
        "capture_active": True,
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
    }
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "running"
    assert runtime["capture"] == "running"
    assert runtime["data_source"] == "live"
    assert status_bar_text(payload) == "Capture running"
    assert apps_source_caption(payload, True) == "Live application traffic"
    assert apps_source_subtitle(payload, False).startswith("Live application traffic")


def test_runtime_states_not_installed() -> None:
    payload = {
        "service_not_installed": True,
        "service_unavailable": True,
        "scm_state": "1060",
        "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
    }
    runtime = runtime_states(payload)
    assert runtime["service"] == "not_installed"
    assert display_state_for(payload) == "Service Not Installed"
    assert status_bar_text(payload) == "Service not installed"
    info = home_headline(payload, header_status(payload))
    assert "not installed" in info["title"].lower()


def test_snapshot_not_installed_when_scm_1060(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    class DeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "1060"
    )
    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.snapshot()
    assert payload["service_not_installed"] is True
    assert display_state_for(payload) == "Service Not Installed"
    assert status_bar_text(payload) == "Service not installed"


def test_start_monitoring_requires_running_service(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "STOPPED"
    )

    class DeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

        def start_monitoring(self):
            raise AssertionError("must not start monitoring when service is down")

    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.start_monitoring()
    assert payload["ok"] is False
    assert payload.get("monitoring_start_failed") is True
    assert payload.get("service_not_installed") is not True
    assert "start the cana windows service" in payload["last_error"].lower()
    assert "not installed" not in payload["last_error"].lower()
    assert runtime_states(payload)["monitoring"] == "start_failed"


def test_start_service_does_not_leave_requested_message() -> None:
    import inspect

    source = inspect.getsource(CANAWindow._on_start_service)
    assert "Service start requested." not in source
    assert "Service starting..." in source
    start_source = inspect.getsource(CANAWindow._on_start)
    assert "Monitoring starting..." in start_source
    assert "display_state_for" not in start_source


def test_start_monitoring_distinguishes_capture_unavailable() -> None:
    """Start must not claim success when monitoring runs without capture."""
    import inspect

    source = inspect.getsource(CANAWindow._on_start)
    assert 'runtime["capture"] == "running"' in source
    assert "Packet capture is unavailable." in source
    assert 'runtime["monitoring"] == "start_failed"' in source
    assert "self.refresh()" in source


def test_classify_scm_state_empty_is_unknown_not_stopped() -> None:
    assert classify_scm_state("") == "unknown"
    assert classify_scm_state("UNKNOWN") == "unknown"
    assert classify_scm_state("RUNNING") == "running"
    assert classify_scm_state("STOPPED") == "stopped"
    assert classify_scm_state("START_PENDING") == "starting"
    assert classify_scm_state("1060") == "not_installed"
    empty = runtime_states(
        {
            "scm_state": "",
            "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
        }
    )
    assert empty["service"] == "unknown"
    assert empty["service"] != "stopped"


def test_pipe_snapshot_preserves_service_alive_when_scm_unknown() -> None:
    payload = {
        "state": "stopped",
        "scm_state": "UNKNOWN",
        "service_unavailable": False,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
        },
    }
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "stopped"
    header = header_status(payload)
    assert header["service"] == "Running"
    assert header["badge"] == "Stopped"


def test_snapshot_linux_unknown_scm_keeps_pipe_runtime(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "UNKNOWN"
    )
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    payload = ui.snapshot()
    assert payload.get("service_unavailable") is False
    assert payload.get("scm_state") in {"UNKNOWN", ""}
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "stopped"
    assert classify_scm_state(payload.get("scm_state") or "") == "unknown"


def test_inprocess_client_ignores_scm_not_installed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "1060"
    )
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    payload = ui.snapshot()
    assert payload.get("service_unavailable") is False
    assert payload.get("service_not_installed") is not True
    runtime = runtime_states(payload)
    assert runtime["service"] == "running"
    assert display_state_for(payload) != "Service Not Installed"
    started = ui.start_monitoring()
    assert started.get("ok") is not False
    assert started.get("monitoring_start_failed") is not True
    assert engine.config.monitoring_enabled is True
    engine.stop()


def test_generic_pipe_error_is_not_labelled_uninstalled(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "UNKNOWN"
    )

    class DeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.snapshot()
    assert payload["service_unavailable"] is True
    assert payload.get("service_not_installed") is not True
    assert display_state_for(payload) == "Service Not Running"
    assert "not installed" not in str(payload.get("last_error") or "").lower()


def test_production_client_honors_confirmed_scm_not_installed(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "1060"
    )

    class ProductionDeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

    ui = UIController(ProductionDeadClient())  # type: ignore[arg-type]
    payload = ui.snapshot()
    assert payload["service_not_installed"] is True
    assert payload["service_unavailable"] is True
    assert display_state_for(payload) == "Service Not Installed"
    assert "not installed" in str(payload.get("last_error") or "").lower()


def test_start_monitoring_not_installed_is_actionable(monkeypatch) -> None:
    from cana_engine.client import ControlClientError

    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "1060"
    )

    class DeadClient:
        def snapshot(self):
            raise ControlClientError("CANA service is not running.")

        def start_monitoring(self):
            raise AssertionError("must not start monitoring when service is missing")

    ui = UIController(DeadClient())  # type: ignore[arg-type]
    payload = ui.start_monitoring()
    assert payload["ok"] is False
    assert payload.get("service_not_installed") is True
    assert "not installed" in payload["last_error"].lower()
    assert display_state_for(payload) == "Service Not Installed"


def test_query_windows_service_without_scm_is_unknown() -> None:
    import os

    if os.name == "nt":
        pytest.skip("live Windows SCM query is environment-specific")
    token, kind = query_windows_service()
    assert token == "UNKNOWN"
    assert kind == "unknown"
    assert query_windows_service_state() == "UNKNOWN"
    assert classify_scm_state(query_windows_service_state()) == "unknown"


def test_home_headlines_match_independent_states() -> None:
    not_installed = {
        "service_not_installed": True,
        "scm_state": "1060",
        "health": {"service_alive": False},
    }
    assert home_headline(not_installed, header_status(not_installed))["title"] == (
        "CANA service is not installed"
    )
    stopped = {
        "scm_state": "STOPPED",
        "service_unavailable": True,
        "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
    }
    info = home_headline(stopped, header_status(stopped))
    assert info["title"] == "Service stopped"
    assert info["subtitle"] == "Start the CANA service to begin monitoring."
    assert status_bar_text(stopped) == "Service stopped"

    starting = {"scm_state": "START_PENDING", "health": {"service_alive": False}}
    assert home_headline(starting, header_status(starting))["title"] == "Service starting"

    failed = {
        "service_start_failed": True,
        "last_error": "sc start failed",
        "health": {"service_alive": False},
    }
    assert home_headline(failed, header_status(failed))["title"] == "Service start failed"
    assert status_bar_text(failed) == "Service start failed"

    running_stopped = {
        "state": "stopped",
        "scm_state": "RUNNING",
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
        },
    }
    info = home_headline(running_stopped, header_status(running_stopped))
    assert info["title"] == "Monitoring stopped"
    assert info["subtitle"] == "Start monitoring to begin capturing traffic."
    assert status_bar_text(running_stopped) == "Monitoring stopped"

    capture_down = {
        "state": "capture_unavailable",
        "scm_state": "RUNNING",
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": False,
            "monitoring_enabled": True,
            "capture_error": "Npcap is not available.",
        },
    }
    info = home_headline(capture_down, header_status(capture_down))
    assert info["title"] == "Capture unavailable"
    assert info["subtitle"] == "Packet capture is unavailable."
    assert status_bar_text(capture_down) == "Capture unavailable"
    runtime = runtime_states(capture_down)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "running"
    assert runtime["capture"] == "failed"

    live = {
        "state": "protected",
        "scm_state": "RUNNING",
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
    }
    info = home_headline(live, header_status(live))
    assert info["title"] == "Monitoring active"
    assert info["subtitle"] == "3 alert rules enabled: TCP port probes and unusual TCP flags."
    assert status_bar_text(live) == "Capture running"


def test_try_start_windows_service_reports_start_failed(monkeypatch) -> None:
    class Result:
        def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(*args, **kwargs):
        argv = args[0]
        if argv[1] == "query":
            return Result(0, stdout="STATE              : 1  STOPPED")
        return Result(0, stdout="STATE              : 1  STOPPED")

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert try_start_windows_service() == "CANA service start failed."


def test_apps_empty_state_is_historical_not_live() -> None:
    payload = {
        "state": "stopped",
        "scm_state": "RUNNING",
        "has_session_data": False,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
        },
    }
    assert apps_source_caption(payload, False) == "No stored session traffic"
    assert apps_source_subtitle(payload, False) == "No stored session traffic in this range."
    assert status_bar_text(payload) == "Monitoring stopped"
    assert runtime_states(payload)["data_source"] == "none"


def test_stop_monitoring_leaves_service_running(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "RUNNING"
    )
    engine = _engine(tmp_path)
    ui, engine = _controller(engine)
    ui.start_monitoring()
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    assert engine.status().running is True
    stopped = ui.stop_monitoring()
    assert engine.status().running is False
    assert engine.config.monitoring_enabled is False
    runtime = runtime_states(stopped)
    assert runtime["service"] == "running"
    assert runtime["monitoring"] == "stopped"


class _Label:
    def __init__(self) -> None:
        self.text = ""
        self.fg = None
        self.calls = 0

    def configure(self, **kwargs) -> None:
        self.calls += 1
        if "text" in kwargs:
            self.text = kwargs["text"]
        if "fg" in kwargs:
            self.fg = kwargs["fg"]


class _BoomList:
    def winfo_children(self):
        raise AssertionError("list widgets must not be rebuilt")

    def clear(self) -> None:
        raise AssertionError("list widgets must not be rebuilt")

    inner = None


def test_single_poll_timer_is_replaced_not_stacked() -> None:
    window = CANAWindow(_StubController())

    class FakeRoot:
        def __init__(self) -> None:
            self.scheduled: list = []
            self.cancelled: list = []
            self._n = 0

        def after(self, ms, fn):
            self._n += 1
            self.scheduled.append((ms, fn, self._n))
            return self._n

        def after_cancel(self, ident) -> None:
            self.cancelled.append(ident)

    root = FakeRoot()
    window._root = root  # type: ignore[assignment]
    window._closed = False
    window._schedule_poll()
    window._schedule_poll()
    assert len(root.scheduled) == 2
    assert root.cancelled == [1]
    assert window._poll_after_id == 2

    window._poll_after_id = None
    window.refresh = lambda: None  # type: ignore[method-assign]
    window._poll()
    assert len(root.scheduled) == 3
    assert window._poll_after_id == 3


def test_navigation_does_not_start_a_poll_timer() -> None:
    import inspect

    source = inspect.getsource(CANAWindow._show_page)
    assert "_schedule_poll" not in source
    assert "self._poll" not in source
    assert "poll_ms" not in source


def test_show_page_does_not_bind_new_refresh_workers() -> None:
    import inspect

    source = inspect.getsource(CANAWindow._show_page)
    assert "_run_off_thread" not in source
    assert "Thread(" not in source


def test_activity_list_is_not_rebuilt_when_alerts_are_unchanged() -> None:
    from cana_ui.window import activity_list_signature

    alerts = [
        {
            "severity": "HIGH",
            "reason": "Port scan",
            "source_ip": "10.0.0.2",
            "triggered_at_epoch": 1_700_000_000,
        }
    ]
    window = CANAWindow(_StubController())
    window._widgets["activity_list"] = _BoomList()
    window._list_signatures["activity"] = activity_list_signature(alerts)
    window._render_activity(alerts)


def test_apps_list_is_not_rebuilt_when_rows_are_unchanged() -> None:
    from cana_ui.traffic import AppTraffic
    from cana_ui.window import apps_list_signature

    apps = [AppTraffic(name="chrome.exe", down_bytes=10, up_bytes=4)]
    window = CANAWindow(_StubController())
    window._apps_data = list(apps)
    window._payload = {"health": {"monitoring_enabled": False, "service_alive": True}}
    window._widgets.update(
        {
            "apps_list": _BoomList(),
            "apps_total": _Label(),
            "apps_caption": _Label(),
            "apps_subtitle": _Label(),
            "apps_chart": type(
                "Chart",
                (),
                {"set_series": staticmethod(lambda *a, **k: None)},
            )(),
        }
    )
    window._list_signatures["apps"] = apps_list_signature(
        apps, "", None, window._apps_range
    )
    window._render_apps(apps, None)


def test_alerts_and_history_lists_are_not_rebuilt_when_unchanged() -> None:
    from cana_ui.incidents import Incident
    from cana_ui.window import alerts_list_signature, history_list_signature

    window = CANAWindow(_StubController())
    window._kpi_cards = []
    window._kpis = []
    window._alert_incidents = [
        Incident(
            key="a1",
            name="Port scan",
            severity="High",
            status="Active",
            first_seen_epoch=1_700_000_000,
            tags=["TCP"],
        )
    ]
    window._widgets.update(
        {
            "sev_chip": type("Chip", (), {"label": _Label()})(),
            "status_chip": type("Chip", (), {"label": _Label()})(),
            "alerts_count": _Label(),
            "alerts_list": _BoomList(),
            "history_list": _BoomList(),
            "history_count": _Label(),
        }
    )
    window._list_signatures["alerts"] = alerts_list_signature(
        window._alert_incidents, "All", "All", ""
    )
    window._render_alerts()

    window._history_rows = [
        {
            "session_id": "s1",
            "interface": "eth0",
            "packet_count": 4,
            "started_at_epoch": 1_700_000_000,
            "size_bytes": 128,
        }
    ]
    window._list_signatures["history"] = history_list_signature(window._history_rows)
    window._render_history()


def test_traffic_chart_redraws_only_when_series_changes() -> None:
    from cana_ui.widgets import AreaChart, TrafficChart

    chart = TrafficChart.__new__(TrafficChart)
    chart._values = [1.0, 2.0]
    chart._running = True
    redraws: list = []
    chart._redraw = lambda: redraws.append("home")  # type: ignore[method-assign]
    chart.set_series([1.0, 2.0], running=True)
    assert redraws == []
    chart.set_series([1.0, 3.0], running=True)
    assert redraws == ["home"]

    area = AreaChart.__new__(AreaChart)
    area._down = [1, 2]
    area._up = [0, 1]
    area._labels = ["a", "b"]
    area._redraw = lambda: redraws.append("apps")  # type: ignore[method-assign]
    area.set_series([1, 2], [0, 1], ["a", "b"])
    assert redraws == ["home"]
    area.set_series([1, 2], [0, 2], ["a", "b"])
    assert redraws == ["home", "apps"]


def test_home_graph_widget_is_not_recreated_on_refresh() -> None:
    import inspect

    build = inspect.getsource(CANAWindow._build_status)
    render = inspect.getsource(CANAWindow._render_traffic)
    apply = inspect.getsource(CANAWindow._apply_bundle)
    assert "TrafficChart(" in build
    assert "TrafficChart(" not in render
    assert "TrafficChart(" not in apply
    assert "set_series" in render
    assert "destroy(" not in render


def test_pill_button_and_icon_skip_identical_repaint() -> None:
    from cana_ui.widgets import IconCanvas, PillButton, StatusBar, StatusTile

    button = PillButton.__new__(PillButton)
    button.text = "Start service"
    button._enabled = True
    button.icon = None
    button._font = type("F", (), {"measure": staticmethod(lambda t: 10)})()
    button._pad = 14
    button.canvas = type("C", (), {"configure": staticmethod(lambda **k: None)})()
    paints: list = []
    button._render = lambda: paints.append("btn")  # type: ignore[method-assign]
    button.configure(text="Start service", enabled=True)
    assert paints == []
    button.configure(text="Stop monitoring", enabled=True)
    assert paints == ["btn"]

    icon = IconCanvas.__new__(IconCanvas)
    icon.name = "stop"
    icon.color = "#A32D2D"
    icon.size = 24
    icon._width = 1.5
    icon.canvas = type("C", (), {"delete": staticmethod(lambda *a: paints.append("icon"))})()
    icon.set("stop", "#A32D2D")
    assert paints == ["btn"]

    tile = StatusTile.__new__(StatusTile)
    tile.value = _Label()
    tile._text = "Stopped"
    tile._color = "#A32D2D"
    tile.set("Stopped", "#A32D2D")
    assert tile.value.calls == 0
    tile.set("Running", "#2E7D5B")
    assert tile.value.calls == 1

    bar = StatusBar.__new__(StatusBar)
    bar._dot_color = "#A32D2D"
    bar._state = "Service stopped"
    bar._detail = "eth0 · 0 pkt/s"
    bar.state = _Label()
    bar.detail = _Label()
    bar._draw_dot = lambda: paints.append("dot")  # type: ignore[method-assign]
    bar.set("Service stopped", "#A32D2D", "eth0 · 0 pkt/s")
    assert paints == ["btn"]
    bar.set("Capture running", "#2E7D5B", "eth0 · 12 pkt/s")
    assert paints[-1] == "dot"


def test_apply_bundle_does_not_rebuild_hidden_page_lists() -> None:
    window = CANAWindow(_StubController())
    window._current_page = "home"
    window._widgets.update(
        {
            "apps_list": _BoomList(),
            "alerts_list": _BoomList(),
            "history_list": _BoomList(),
        }
    )
    window._render_home = lambda *a, **k: None  # type: ignore[method-assign]
    window._render_status_bar = lambda *a, **k: None  # type: ignore[method-assign]
    window._sync_menu_state = lambda *a, **k: None  # type: ignore[method-assign]
    window._apply_bundle(
        {
            "payload": {"alerts": [], "health": {}},
            "apps": [],
            "series": None,
            "correlated": [],
            "history": [
                {
                    "session_id": "s1",
                    "interface": "eth0",
                    "packet_count": 1,
                    "started_at_epoch": 1,
                    "size_bytes": 10,
                }
            ],
            "apps_range": window._apps_range,
        }
    )
    assert window._history_rows[0]["session_id"] == "s1"


def test_idle_traffic_sampler_does_not_grow_while_stopped() -> None:
    window = CANAWindow(_StubController())
    window._last_packets = 0
    window._last_sample_at = 0.0
    window._traffic_samples = []
    window._widgets["chart"] = type(
        "Chart",
        (),
        {
            "set_series": staticmethod(lambda *a, **k: None),
            "set_caption": staticmethod(lambda *a, **k: None),
        },
    )()
    payload = {
        "state": "stopped",
        "scm_state": "STOPPED",
        "health": {
            "service_alive": False,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
            "packets_processed": 0,
        },
        "packets_processed": 0,
    }
    header = {"monitoring": "Stopped", "capture": "Stopped"}
    window._render_traffic(payload, header)
    window._render_traffic(payload, header)
    assert window._traffic_samples == []


def test_home_does_not_show_monitoring_stopped_while_protected() -> None:
    payload = {
        "ok": True,
        "state": "protected",
        "scm_state": "RUNNING",
        "last_error": "",
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
    }
    header = header_status(payload)
    info = home_headline(payload, header)
    assert info["title"] == "Monitoring active"
    assert "stopped" not in info["subtitle"].lower()
    assert header["monitoring"] == "Active"
    assert header["detection"] == "Active"
    assert header["capture"] == "Active"
    assert status_bar_text(payload) == "Capture running"


def test_home_reconnect_does_not_claim_service_stopped() -> None:
    payload = {
        "ok": False,
        "state": "protected",
        "scm_state": "RUNNING",
        "service_unavailable": False,
        "last_error": "CANA service connection was temporarily unavailable. Reconnecting...",
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
    }
    header = header_status(payload)
    info = home_headline(payload, header)
    assert info["title"] == "Reconnecting"
    assert "reconnect" in info["subtitle"].lower()
    assert header["service"] == "Running"
    assert status_bar_text(payload) == "Reconnecting"


def test_alert_sentence_hides_statistical_jargon() -> None:
    alert = {
        "rule_name": "packet_size_anomaly",
        "severity": "LOW",
        "reason": "Packet size 342B is a statistical outlier for this hour (baseline mean=100B, std_dev=63B).",
        "application_name": "chrome.exe",
        "source_ip": "10.0.0.8",
    }
    sentence = alert_sentence(alert)
    assert "statistical" not in sentence.lower()
    assert "std_dev" not in sentence.lower()
    assert "baseline mean" not in sentence.lower()
    assert sentence == "Chrome: Packet size exceeded the learned range"
    meta = alert_meta(alert)
    assert "10.0.0.8" not in meta
    assert "chrome" in meta.lower()


def test_valid_ui_states_are_internally_consistent() -> None:
    cases = (
        (
            {
                "service_not_installed": True,
                "scm_state": "1060",
                "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
            },
            "CANA service is not installed",
            "Service not installed",
                "Install service",
                True,
        ),
        (
            {
                "scm_state": "STOPPED",
                "service_unavailable": True,
                "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
            },
            "Service stopped",
            "Service stopped",
            "Start service",
            True,
        ),
        (
            {"scm_state": "START_PENDING", "health": {"service_alive": False}},
            "Service starting",
            "Service starting",
            "Service starting",
            False,
        ),
        (
            {
                "state": "stopped",
                "scm_state": "RUNNING",
                "health": {
                    "service_alive": True,
                    "engine_alive": False,
                    "capture_alive": False,
                    "monitoring_enabled": False,
                },
            },
            "Monitoring stopped",
            "Monitoring stopped",
            "Service running",
            False,
        ),
        (
            {
                "state": "starting",
                "scm_state": "RUNNING",
                "health": {
                    "service_alive": True,
                    "engine_alive": False,
                    "capture_alive": False,
                    "monitoring_enabled": True,
                },
            },
            "Monitoring starting",
            "Monitoring starting",
            "Stop monitoring",
            False,
        ),
        (
            {
                "state": "protected",
                "scm_state": "RUNNING",
                "health": {
                    "service_alive": True,
                    "engine_alive": True,
                    "capture_alive": True,
                    "monitoring_enabled": True,
                },
            },
            "Monitoring active",
            "Capture running",
            "Stop monitoring",
            True,
        ),
        (
            {
                "scm_state": "STOP_PENDING",
                "health": {"service_alive": True, "engine_alive": False, "capture_alive": False},
            },
            "Service stopping",
            "Service stopping",
            "Service stopping",
            False,
        ),
        (
            {
                "state": "service_error",
                "last_error": "The CANA Windows service reported an error.",
                "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
            },
            "Service error",
            "Service error",
            "Start service",
            True,
        ),
        (
            {
                "scm_state": "RUNNING",
                "connection_lost": True,
                "service_unavailable": True,
                "health": {
                    "service_alive": True,
                    "engine_alive": False,
                    "capture_alive": False,
                    "monitoring_enabled": False,
                },
            },
            "Connection lost",
            "Connection lost",
            "Service running",
            False,
        ),
        (
            {
                "state": "protected",
                "scm_state": "RUNNING",
                "last_error": "CANA service connection was temporarily unavailable. Reconnecting...",
                "health": {
                    "service_alive": True,
                    "engine_alive": True,
                    "capture_alive": True,
                    "monitoring_enabled": True,
                },
            },
            "Reconnecting",
            "Reconnecting",
            "Stop monitoring",
            True,
        ),
    )
    for payload, title, bar, primary, primary_enabled in cases:
        header = header_status(payload)
        info = home_headline(payload, header)
        actions = home_actions(payload)
        assert info["title"] == title
        assert status_bar_text(payload) == bar
        assert actions["primary"] == primary
        assert actions["primary_enabled"] is primary_enabled
        if title == "Monitoring active":
            assert "stopped" not in info["subtitle"].lower()
            assert header["monitoring"] == "Active"
            assert header["detection"] == "Active"
            assert header["capture"] == "Active"


def test_pages_and_tray_agree_on_live_versus_historical() -> None:
    live = {
        "state": "protected",
        "scm_state": "RUNNING",
        "has_session_data": True,
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
    }
    assert home_headline(live, header_status(live))["title"] == "Monitoring active"
    assert status_bar_text(live) == "Capture running"
    assert apps_source_caption(live, True) == "Live application traffic"
    assert alerts_source_caption(live) == "Current monitoring alerts"
    assert "Current session" in history_source_caption(live, True)
    assert tray_status_text(live) == "CANA - Protected"

    historical = {
        "state": "stopped",
        "scm_state": "RUNNING",
        "has_session_data": True,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
        },
    }
    assert home_headline(historical, header_status(historical))["title"] == "Monitoring stopped"
    assert status_bar_text(historical) == "Monitoring stopped"
    assert apps_source_caption(historical, True) == "Historical application traffic"
    assert alerts_source_caption(historical) == "Historical alerts"
    assert history_source_caption(historical, True).startswith("Capture sessions")
    assert tray_status_text(historical) == "CANA - Stopped"


def test_snapshot_reconnects_after_transient_pipe_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "cana_ui.controller.query_windows_service_state", lambda: "RUNNING"
    )

    class Bounce:
        def __init__(self) -> None:
            self.calls = 0

        def snapshot(self):
            from cana_engine.client import ControlClientError

            self.calls += 1
            if self.calls == 1:
                raise ControlClientError(
                    "CANA service connection was temporarily unavailable. Reconnecting..."
                )
            return {
                "ok": True,
                "state": "protected",
                "scm_state": "RUNNING",
                "health": {
                    "service_alive": True,
                    "engine_alive": True,
                    "capture_alive": True,
                    "monitoring_enabled": True,
                },
            }

    bounce = Bounce()
    ui = UIController(bounce)  # type: ignore[arg-type]
    ui.last_payload = {
        "ok": True,
        "state": "protected",
        "scm_state": "RUNNING",
        "service_unavailable": False,
        "health": {
            "service_alive": True,
            "engine_alive": True,
            "capture_alive": True,
            "monitoring_enabled": True,
        },
        "service_health": {"service_alive": True},
    }
    dropped = ui.snapshot()
    assert runtime_states(dropped)["connection"] == "reconnecting"
    assert runtime_states(dropped)["monitoring"] == "running"
    restored = ui.snapshot()
    assert restored["ok"] is True
    assert runtime_states(restored)["connection"] == "connected"
    assert home_headline(restored, header_status(restored))["title"] == "Monitoring active"


def test_service_stop_failed_state_and_headline() -> None:
    payload = {
        "service_stop_failed": True,
        "last_error": "sc stop failed",
        "health": {"service_alive": False, "engine_alive": False, "capture_alive": False},
    }
    runtime = runtime_states(payload)
    assert runtime["service"] == "stop_failed"
    assert runtime["service_label"] == "Stop failed"
    assert display_state_for(payload) == "Service Stop Failed"
    header = header_status(payload)
    assert header["service"] == "Stop failed"
    assert home_headline(payload, header)["title"] == "Service stop failed"
    assert status_bar_text(payload) == "Service stop failed"


def test_connection_connecting_and_disconnected_vocabulary() -> None:
    unknown = {"scm_state": "", "health": {"service_alive": False}}
    runtime = runtime_states(unknown)
    assert runtime["connection"] == "connecting"
    assert runtime["connection_label"] == "Connecting"
    assert runtime["monitoring"] == "unknown"
    assert runtime["monitoring"] != "stopped"
    assert display_state_for(unknown) == "Connecting..."
    assert status_bar_text(unknown) == "Connecting..."

    lost = {
        "scm_state": "RUNNING",
        "connection_lost": True,
        "service_unavailable": True,
        "health": {
            "service_alive": True,
            "engine_alive": False,
            "capture_alive": False,
            "monitoring_enabled": False,
        },
    }
    runtime = runtime_states(lost)
    assert runtime["connection"] == "disconnected"
    assert runtime["connection_label"] == "Disconnected"
    assert display_state_for(lost) == "Connection Lost"
    assert home_headline(lost, header_status(lost))["title"] == "Connection lost"


def test_validate_settings_rejects_unknown_values() -> None:
    from cana_ui.window import validate_settings

    assert validate_settings(
        {"packet_filter": "TCP", "logging_level": "INFO"}
    ) is None
    assert "packet filter" in str(
        validate_settings({"packet_filter": "BOGUS", "logging_level": "INFO"})
    ).lower()
    assert "logging level" in str(
        validate_settings({"packet_filter": "ALL", "logging_level": "LOUD"})
    ).lower()


def test_ui_source_never_imports_capture_or_engine_logger() -> None:
    import inspect

    import cana_ui.app as app_module
    import cana_ui.window as window_module

    for module in (window_module, app_module):
        source = inspect.getsource(module)
        assert "from packet_capture" not in source
        assert "import packet_capture" not in source
        assert "from cana_engine.logging_setup" not in source
        assert "cana_service.service" not in source
