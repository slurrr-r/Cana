"""Regression tests for CANAEngine start/stop/health/watchdog."""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

import pytest

from packet_capture.config import CaptureSettings
from packet_capture.interface import NetworkInterface
from cana_engine.config import CANAConfig
from cana_engine import engine as engine_mod
from cana_engine.engine import CANAEngine
from cana_engine.capture_lock import release_capture_lock


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


class _FakeCapture:
    def __init__(self, stop_event: Optional[threading.Event]) -> None:
        self._stop = stop_event or threading.Event()
        self.stats = type("S", (), {"packets_dropped_queue_full": 0})()

    def stop(self) -> None:
        self._stop.set()

    def is_running(self) -> bool:
        return not self._stop.is_set()


def _runner_factory(started: list, active: list):
    def runner(
        settings: CaptureSettings,
        stop_event: Optional[threading.Event] = None,
        engine_out: Optional[dict] = None,
        **kwargs: Any,
    ) -> list:
        started.append(settings)
        fake = _FakeCapture(stop_event)
        if engine_out is not None:
            engine_out["engine"] = fake
        active.append(fake)
        if stop_event is not None:
            stop_event.wait(3)
        return []

    return runner


def test_engine_starts_and_stops(tmp_path) -> None:
    started: list = []
    active: list = []
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        database_path=str(tmp_path / "baseline.db"),
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory(started, active),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while not started and time.time() < deadline:
        time.sleep(0.05)
    status = engine.status()
    assert status.running is True
    engine.stop()
    assert engine.status().running is False
    assert started


def test_repeated_start_stop_is_safe(tmp_path) -> None:
    started: list = []
    active: list = []
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory(started, active),
        interface_detector=_iface,
        print_alerts=False,
    )
    for _ in range(3):
        engine.start()
        deadline = time.time() + 3
        while not engine.status().running and time.time() < deadline:
            time.sleep(0.05)
        engine.stop()
        assert engine.status().running is False


def test_stop_while_interface_is_silent(tmp_path) -> None:
    """Shutdown must not wait for a packet."""

    def silent_runner(
        settings,
        stop_event=None,
        engine_out=None,
        **kwargs,
    ):
        fake = _FakeCapture(stop_event)
        if engine_out is not None:
            engine_out["engine"] = fake
        start = time.time()
        if stop_event is not None:
            stop_event.wait(10)
        assert time.time() - start < 5
        return []

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=silent_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    time.sleep(0.2)
    began = time.time()
    engine.stop()
    assert time.time() - began < 5
    assert not engine.status().running


def test_no_duplicate_capture_workers(tmp_path) -> None:
    current = {"n": 0, "max": 0}
    lock = threading.Lock()

    def runner(settings, stop_event=None, engine_out=None, **kwargs):
        with lock:
            current["n"] += 1
            current["max"] = max(current["max"], current["n"])
        try:
            fake = _FakeCapture(stop_event)
            if engine_out is not None:
                engine_out["engine"] = fake
            if stop_event is not None:
                stop_event.wait(2)
            return []
        finally:
            with lock:
                current["n"] -= 1

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    engine.start()
    time.sleep(0.3)
    engine.stop()
    assert current["max"] <= 1


def test_capture_failure_is_reported(tmp_path) -> None:
    def failing_detect():
        from packet_capture.interface import InterfaceDetectionError

        raise InterfaceDetectionError("Npcap is not installed")

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=failing_detect,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while not engine.health().last_error and time.time() < deadline:
        time.sleep(0.05)
    health = engine.health()
    assert "Npcap" in health.last_error or "npcap" in health.last_error.lower()
    assert health.ui_state in {"capture_unavailable", "service_error", "starting"}
    engine.stop()


def test_state_survives_restart(tmp_path) -> None:
    db = tmp_path / "baseline.db"
    config = CANAConfig(
        persist=True,
        print_summaries=False,
        database_path=str(db),
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    started: list = []
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory(started, []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while not started and time.time() < deadline:
        time.sleep(0.05)
    engine.stop()
    assert db.parent.exists()
    engine2 = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine2.start()
    time.sleep(0.2)
    engine2.stop()
    health = engine2.health()
    assert health.database_available in {True, False}


def test_watchdog_refuses_restart_loop(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_RESTART_DELAY_SECONDS", 0.05)
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_MAX_RAPID_RESTARTS", 3)
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_RAPID_WINDOW_SECONDS", 10.0)

    def dying_runner(settings, stop_event=None, engine_out=None, **kwargs):
        raise RuntimeError("capture boom")

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=dying_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            if "watchdog" in engine.health().last_error.lower():
                break
            time.sleep(0.05)
        assert "watchdog" in engine.health().last_error.lower()
    finally:
        engine.stop()


def test_status_reports_health_fields(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        monitoring_enabled=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    time.sleep(0.2)
    status = engine.status()
    assert status.capture_active is False
    health = engine.health()
    assert health.monitoring_enabled is False
    engine.stop()
    assert engine.status().running is False


def test_watchdog_stops_with_engine(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    watchdog = engine._watchdog
    assert watchdog is not None and watchdog.is_alive()
    engine.stop()
    assert engine._watchdog is None or not engine._watchdog.is_alive()


def test_npcap_failure_parks_without_watchdog_restart(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr("cana_engine.engine.WATCHDOG_RESTART_DELAY_SECONDS", 0.05)

    def failing_detect():
        from packet_capture.interface import InterfaceDetectionError

        raise InterfaceDetectionError("Npcap is not installed")

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=failing_detect,
        print_alerts=False,
    )
    engine.start()
    try:
        deadline = time.time() + 3
        while not engine.health().capture_error and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.3)
        assert engine._dependency_parked is True
        assert engine._restart_times == []
        assert engine.health().ui_state == "capture_unavailable"
    finally:
        engine.stop()


def test_lock_failure_parks_without_restart_loop(tmp_path, monkeypatch) -> None:
    """A terminal singleton-lock failure must not trigger watchdog restarts.

    Reproduces the Windows ``CreateMutex`` access-denied symptom at the
    engine boundary: the failure must surface as a clear lock message and
    park the engine, not as "unexpected engine termination".
    """

    def denied(*args, **kwargs):
        from cana_engine.capture_lock import CaptureLockError

        raise CaptureLockError("another CANA capture engine is already running")

    monkeypatch.setattr(engine_mod, "acquire_capture_lock", denied)
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=True,
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    try:
        deadline = time.time() + 3
        while not engine.health().last_error and time.time() < deadline:
            time.sleep(0.05)
        error = engine.health().last_error.lower()
        assert "already running" in error
        assert "unexpected engine termination" not in error
        assert engine._dependency_parked is True
        assert engine._restart_times == []
    finally:
        engine.stop()


def test_capture_lock_refuses_second_engine(tmp_path) -> None:
    started: list = []
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    first = CANAEngine(
        config,
        capture_runner=_runner_factory(started, []),
        interface_detector=_iface,
        print_alerts=False,
    )
    second = CANAEngine(
        CANAConfig(
            persist=False,
            print_summaries=False,
            sessions_dir=str(tmp_path / "sessions"),
            logs_dir=str(tmp_path / "logs"),
        ),
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    first.start()
    deadline = time.time() + 3
    while not first.status().running and time.time() < deadline:
        time.sleep(0.05)
    second.start()
    deadline = time.time() + 7
    while not second.health().last_error and time.time() < deadline:
        time.sleep(0.05)
    error = second.health().last_error.lower()
    assert "already running" in error or "duplicate" in error
    first.stop()
    second.stop()


def test_apply_config_update_can_wait(tmp_path) -> None:
    started: list = []
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        packet_filter="ALL",
        monitoring_enabled=True,
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory(started, []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    engine.apply_config_update({"packet_filter": "TCP"}, wait=True)
    assert engine.config.packet_filter == "TCP"
    engine.stop()


def test_apply_config_invalid_does_not_mutate(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        packet_filter="ALL",
        monitoring_enabled=False,
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory([], []),
        interface_detector=_iface,
        print_alerts=False,
    )
    with pytest.raises(ValueError):
        engine.apply_config_update({"packet_filter": "FTP"}, wait=True)
    assert engine.config.packet_filter == "ALL"
    assert engine.config.monitoring_enabled is False


def test_apply_config_monitoring_enabled_starts_capture(tmp_path) -> None:
    started: list = []
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
    )
    engine = CANAEngine(
        config,
        capture_runner=_runner_factory(started, []),
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.apply_config_update({"monitoring_enabled": True}, wait=True)
    deadline = time.time() + 3
    while not engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    assert engine.status().running
    engine.stop()


def test_start_replaces_leftover_worker_after_timed_out_stop(tmp_path) -> None:
    """A worker still alive after Stop must not make the next Start a no-op."""

    started: list = []

    def lingering_runner(
        settings: CaptureSettings,
        stop_event: Optional[threading.Event] = None,
        engine_out: Optional[dict] = None,
        **kwargs: Any,
    ) -> list:
        started.append(settings)
        fake = _FakeCapture(stop_event)
        if engine_out is not None:
            engine_out["engine"] = fake
        if stop_event is not None:
            stop_event.wait(10)
            time.sleep(0.6)
        return []

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
    )
    engine = CANAEngine(
        config,
        capture_runner=lingering_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    engine.start()
    deadline = time.time() + 3
    while engine.health().selected_interface != "Ethernet" and time.time() < deadline:
        time.sleep(0.05)
    assert engine.status().running
    leftover = engine._worker
    assert leftover is not None and leftover.is_alive()
    assert engine.health().selected_interface == "Ethernet"

    try:
        with engine._lock:
            engine._want_running = False
            engine._stopping = False
            engine._stop_event.set()
        time.sleep(0.05)
        assert leftover.is_alive()

        engine.start()
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
        assert engine._stop_event.is_set() is False
    finally:
        engine.stop()


def test_second_start_reacquires_interface_after_hung_capture(tmp_path) -> None:
    """Second Start must create a new session and set the capture interface."""

    started: list = []
    sessions = {"n": 0}

    def runner(
        settings: CaptureSettings,
        stop_event: Optional[threading.Event] = None,
        engine_out: Optional[dict] = None,
        **kwargs: Any,
    ) -> list:
        sessions["n"] += 1
        started.append(settings.interface_name)
        fake = _FakeCapture(stop_event)
        if engine_out is not None:
            engine_out["engine"] = fake
        if stop_event is not None:
            stop_event.wait(3)
        return []

    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        capture_interface="Ethernet",
    )
    engine = CANAEngine(
        config,
        capture_runner=runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    try:
        engine.start()
        deadline = time.time() + 3
        while sessions["n"] < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert sessions["n"] == 1
        engine.stop()
        assert engine.status().running is False

        engine.start()
        deadline = time.time() + 3
        while sessions["n"] < 2 and time.time() < deadline:
            time.sleep(0.05)
        assert sessions["n"] == 2
        deadline = time.time() + 3
        while not engine.status().capture_active and time.time() < deadline:
            time.sleep(0.05)
        assert engine.status().running is True
        assert engine.health().selected_interface == "Ethernet"
        assert started[-1] == "eth0"
    finally:
        engine.stop()
