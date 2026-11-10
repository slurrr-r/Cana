"""
Unit tests for packet_capture.capture.

None of these tests perform real network sniffing (no live NIC/Npcap in
this environment). Scapy's ``sniff()`` is mocked/monkeypatched so the
engine's threading, queueing, filter-translation, and error-handling
logic can be verified deterministically and quickly.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable, List, Optional

import pytest

from packet_capture.capture import (
    CaptureEngineError,
    PacketCaptureEngine,
    build_bpf_filter,
    create_packet_queue,
)
from packet_capture.config import CaptureSettings


class TestBuildBpfFilter:
    def test_all_returns_none(self) -> None:
        assert build_bpf_filter("ALL") is None

    def test_tcp_filter(self) -> None:
        assert build_bpf_filter("TCP") == "tcp"

    def test_case_insensitive(self) -> None:
        assert build_bpf_filter("tcp") == "tcp"

    def test_https_filter(self) -> None:
        assert "443" in build_bpf_filter("HTTPS")

    def test_unknown_filter_raises(self) -> None:
        with pytest.raises(CaptureEngineError):
            build_bpf_filter("FTP")


class TestCreatePacketQueue:
    def test_returns_bounded_queue(self) -> None:
        q = create_packet_queue()
        assert isinstance(q, queue.Queue)
        assert q.maxsize > 0


def _settings(packet_filter: str = "ALL") -> CaptureSettings:
    return CaptureSettings(
        interface_name="eth0", display_name="Ethernet", packet_filter=packet_filter
    )


class _FakeSniffController:
    """
    Simulates Scapy's sniff() by synchronously invoking prn() a fixed
    number of times, honoring stop_filter the same way real Scapy does
    (checked after each packet), without touching any real network
    interface.
    """

    def __init__(self, packets_to_deliver: int = 5) -> None:
        self.packets_to_deliver = packets_to_deliver
        self.received_kwargs: dict = {}
        self._calls = 0

    def __call__(self, **kwargs: Any) -> None:
        self.received_kwargs = kwargs
        self._calls += 1
        if self._calls > 1:
            timeout = kwargs.get("timeout") or 0.05
            time.sleep(min(float(timeout), 0.05))
            return
        prn: Callable[[Any], None] = kwargs["prn"]
        stop_filter: Optional[Callable[[Any], bool]] = kwargs.get("stop_filter")

        for i in range(self.packets_to_deliver):
            fake_packet = f"fake_packet_{i}"
            prn(fake_packet)
            if stop_filter and stop_filter(fake_packet):
                break


class TestPacketCaptureEngine:
    def test_start_populates_queue(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(), pkt_queue)
        engine.start()
        deadline = time.time() + 2
        while pkt_queue.qsize() < 3 and time.time() < deadline:
            time.sleep(0.01)
        engine.stop()
        engine.join(timeout=2)

        assert pkt_queue.qsize() == 3
        assert engine.stats.packets_captured == 3

    def test_stop_sets_event_and_thread_terminates(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=100)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(), pkt_queue)
        engine.start()
        engine.stop()
        engine.join(timeout=2)

        assert not engine.is_running()

    def test_filter_is_translated_to_bpf(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(packet_filter="TCP"), pkt_queue)
        engine.start()
        deadline = time.time() + 2
        while not fake_sniff.received_kwargs and time.time() < deadline:
            time.sleep(0.01)
        engine.stop()
        engine.join(timeout=2)

        assert fake_sniff.received_kwargs["filter"] == "tcp"

    def test_queue_full_increments_dropped_counter(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=5)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        tiny_queue: "queue.Queue[Any]" = queue.Queue(maxsize=2)
        engine = PacketCaptureEngine(_settings(), tiny_queue)
        engine.start()
        deadline = time.time() + 2
        while (
            engine.stats.packets_captured + engine.stats.packets_dropped_queue_full < 5
            and time.time() < deadline
        ):
            time.sleep(0.01)
        engine.stop()
        engine.join(timeout=2)

        assert engine.stats.packets_dropped_queue_full == 3
        assert engine.stats.packets_captured == 2

    def test_permission_error_invokes_on_error_callback(self, monkeypatch) -> None:
        def raising_sniff(**kwargs: Any) -> None:
            raise PermissionError("simulated permission denied")

        monkeypatch.setattr("scapy.all.sniff", raising_sniff)

        errors: List[Exception] = []
        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(
            _settings(), pkt_queue, on_error=lambda exc: errors.append(exc)
        )
        engine.start()
        engine.join(timeout=2)

        assert len(errors) == 1
        assert isinstance(errors[0], PermissionError)

    def test_os_error_invokes_on_error_callback(self, monkeypatch) -> None:
        def raising_sniff(**kwargs: Any) -> None:
            raise OSError("simulated missing Npcap driver")

        monkeypatch.setattr("scapy.all.sniff", raising_sniff)

        errors: List[Exception] = []
        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(
            _settings(), pkt_queue, on_error=lambda exc: errors.append(exc)
        )
        engine.start()
        engine.join(timeout=2)

        assert len(errors) == 1
        assert isinstance(errors[0], OSError)

    def test_double_start_is_idempotent_safe(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(), pkt_queue)
        engine.start()
        engine.start()  # should not raise or spawn a second thread
        engine.stop()
        engine.join(timeout=2)
        assert not engine.is_running()

    def test_stats_start_and_end_time_recorded(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(packets_to_deliver=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(), pkt_queue)
        engine.start()
        deadline = time.time() + 2
        while engine.stats.start_time is None and time.time() < deadline:
            time.sleep(0.01)
        engine.stop()
        engine.join(timeout=2)

        assert engine.stats.start_time is not None
        assert engine.stats.end_time is not None
        assert engine.stats.end_time >= engine.stats.start_time

    def test_stop_interrupts_hung_sniff(self, monkeypatch) -> None:
        """Npcap can ignore sniff timeout; stop() must still release the adapter."""

        class HungAsyncSniffer:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.args = args
                self.kwargs = kwargs
                self.running = False
                self.thread: Optional[threading.Thread] = None
                self._stopped = threading.Event()
                self.stop_cb_calls = 0

            def start(self) -> None:
                self.running = True

                def _hold() -> None:
                    self._stopped.wait()
                    self.running = False

                self.thread = threading.Thread(
                    target=_hold, name="HungAsyncSniffer", daemon=True
                )
                self.thread.start()

            def stop(self, join: bool = True) -> None:
                self.stop_cb_calls += 1
                self.stop_cb()
                if join and self.thread is not None:
                    self.thread.join(timeout=2)

            def stop_cb(self) -> None:
                self._stopped.set()
                self.running = False

            def join(self, timeout: Optional[float] = None) -> None:
                if self.thread is not None:
                    self.thread.join(timeout=timeout)

        monkeypatch.setattr("scapy.all.AsyncSniffer", HungAsyncSniffer)
        pkt_queue: "queue.Queue[Any]" = create_packet_queue()
        engine = PacketCaptureEngine(_settings(), pkt_queue)
        engine.start()
        deadline = time.time() + 2
        while not engine.is_running() and time.time() < deadline:
            time.sleep(0.01)
        assert engine.is_running()
        began = time.time()
        engine.stop()
        engine.join(timeout=2)
        assert time.time() - began < 2
        assert not engine.is_running()
