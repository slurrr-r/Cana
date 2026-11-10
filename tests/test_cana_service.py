"""Tests for the CANA service runtime."""

from __future__ import annotations

import time

from packet_capture.interface import NetworkInterface
from cana_engine.config import CANAConfig
from cana_engine.engine import CANAEngine
from cana_service.service import CANAServiceRuntime

import pytest


@pytest.fixture(autouse=True)
def _disable_activity_tracker(monkeypatch) -> None:
    monkeypatch.setattr(CANAEngine, "_start_activity_tracker", lambda self: None)
    from cana_engine.pipe import InProcessPipeServer

    def start_test_pipe(handler, **_kwargs):
        server = InProcessPipeServer(handler)
        server.start()
        return server

    # Real Windows pipe lifecycle is covered by the live acceptance suite.
    monkeypatch.setattr('cana_engine.pipe.run_pipe_server', start_test_pipe)


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


def test_service_starts_and_stops_engine(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=True,
    )
    runtime = CANAServiceRuntime(config)
    runtime.engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    runtime.start()
    deadline = time.time() + 3
    while not runtime.engine.status().running and time.time() < deadline:
        time.sleep(0.05)
    assert runtime.engine.status().running
    runtime.stop()
    assert not runtime.engine.status().running


def test_service_reports_correct_state(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
    )
    runtime = CANAServiceRuntime(config)
    runtime.engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    runtime.start()
    time.sleep(0.2)
    status = runtime.engine.status()
    assert status.capture_active is False
    runtime.stop()


def test_production_service_starts_pipe_only(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
    )
    runtime = CANAServiceRuntime(config)
    runtime.engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    runtime.start()
    try:
        assert runtime.pipe_server is not None
        assert not hasattr(runtime, "control_server") or getattr(
            runtime, "control_server", None
        ) is None
    finally:
        runtime.stop()


def test_engine_start_failure_does_not_abort_service(tmp_path, monkeypatch) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=True,
    )
    runtime = CANAServiceRuntime(config)
    runtime.engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("capture init failed")

    monkeypatch.setattr(runtime.engine, "start", boom)
    runtime.start()
    try:
        assert runtime.pipe_server is not None
        assert runtime.engine.status().running is False
    finally:
        runtime.stop()


def test_service_stop_is_idempotent(tmp_path) -> None:
    config = CANAConfig(
        persist=False,
        print_summaries=False,
        sessions_dir=str(tmp_path / "sessions"),
        logs_dir=str(tmp_path / "logs"),
        monitoring_enabled=False,
    )
    runtime = CANAServiceRuntime(config)
    runtime.engine = CANAEngine(
        config,
        capture_runner=_runner,
        interface_detector=_iface,
        print_alerts=False,
    )
    runtime.start()
    runtime.stop()
    runtime.stop()
    assert not runtime.engine.status().running
