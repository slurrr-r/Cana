"""Capture stop must work on a silent interface."""

from __future__ import annotations

import time
from typing import Any, Optional

from packet_capture.capture import PacketCaptureEngine, create_packet_queue
from packet_capture.config import CaptureSettings


def test_engine_stop_does_not_wait_for_packet(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_sniff(**kwargs: Any) -> None:
        calls["n"] += 1
        timeout = kwargs.get("timeout") or 0.2
        time.sleep(min(float(timeout), 0.2))

    monkeypatch.setattr("scapy.all.sniff", fake_sniff)
    engine = PacketCaptureEngine(
        CaptureSettings(interface_name="eth0", display_name="Ethernet"),
        create_packet_queue(),
    )
    engine.start()
    time.sleep(0.15)
    began = time.time()
    engine.stop()
    engine.join(timeout=3)
    assert time.time() - began < 3
    assert not engine.is_running()
    assert calls["n"] >= 1
