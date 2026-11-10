"""
Integration-style tests for packet_capture.capture.start_packet_capture.

Scapy's sniff() is mocked so these tests run deterministically without
a real NIC, exercising the full pipeline: capture -> parse -> validate
-> classify -> stats -> session save -> return list.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from packet_capture.capture import start_packet_capture
from packet_capture.config import CaptureSettings


def _tcp_packet() -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="93.184.216.34", ttl=64)
        / TCP(sport=52345, dport=443, flags="S")
    )


class _FakeSniffController:
    """Delivers a fixed number of synthetic packets via prn(), honoring stop_filter."""

    def __init__(self, packet_factory: Callable[[], object], count: int) -> None:
        self._packet_factory = packet_factory
        self._count = count
        self._calls = 0

    def __call__(self, **kwargs: Any) -> None:
        self._calls += 1
        if self._calls > 1:
            timeout = kwargs.get("timeout") or 0.05
            time.sleep(min(float(timeout), 0.05))
            return
        prn = kwargs["prn"]
        stop_filter: Optional[Callable[[Any], bool]] = kwargs.get("stop_filter")
        for _ in range(self._count):
            prn(self._packet_factory())
            if stop_filter and stop_filter(None):
                break


class TestStartPacketCapture:
    def test_returns_list_of_classified_packets(self, monkeypatch, tmp_path: Path) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=5)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr(
            "packet_capture.config.SESSIONS_DIR", tmp_path, raising=False
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            max_packets=5,
        )

        assert len(packets) == 5
        assert all(p["protocol"] == "TCP" for p in packets)
        assert all(p["direction"] == "OUTGOING" for p in packets)

    def test_max_packets_stops_capture_early(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=100)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            max_packets=3,
            print_summaries=False,
        )

        assert len(packets) == 3

    def test_max_packets_stops_capture_even_when_below_retention_cap(
        self, monkeypatch
    ) -> None:
        """
        Regression test for P2 Bug #4 (max_packets vs processed
        packets): before the fix, the stop condition compared
        max_packets against the RETAINED packet list, not the true
        processed count. With a retention cap smaller than
        max_packets, that meant the retained list could never reach
        max_packets, so capture would never stop. Here max_packets=7
        with a retention cap of 3: capture must still stop at 7
        processed packets, retaining only 3 of them.
        """
        fake_sniff = _FakeSniffController(_tcp_packet, count=100)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr("packet_capture.config.MAX_RETAINED_PACKETS", 3)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            max_packets=7,
            print_summaries=False,
        )

        # Only 3 packets are retained in memory (the retention cap)...
        assert len(packets) == 3

    def test_processed_count_is_accurate_even_when_retention_caps_the_list(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        """
        Companion to the test above: the true processed-packet count
        (reported via the session's ``total_packets``) must reflect
        every packet that was actually processed, not just the number
        retained in memory.
        """
        fake_sniff = _FakeSniffController(_tcp_packet, count=100)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr("packet_capture.config.MAX_RETAINED_PACKETS", 3)
        monkeypatch.setattr(
            "packet_capture.session.SESSIONS_DIR", tmp_path, raising=False
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            max_packets=7,
            print_summaries=False,
        )

        session_files = list(tmp_path.glob("*.json"))
        assert len(session_files) == 1
        session_data = json.loads(session_files[0].read_text())
        assert session_data["total_packets"] == 7

    def test_permission_error_returns_empty_list_not_crash(self, monkeypatch) -> None:
        def raising_sniff(**kwargs: Any) -> None:
            raise PermissionError("simulated permission denied")

        monkeypatch.setattr("scapy.all.sniff", raising_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(settings, print_summaries=False)

        assert packets == []

    def test_session_file_created(self, monkeypatch, tmp_path: Path) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr(
            "packet_capture.session.SESSIONS_DIR", tmp_path, raising=False
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        start_packet_capture(settings, print_summaries=False, max_packets=2)

        saved_files = list(tmp_path.glob("session_*.json"))
        assert len(saved_files) == 1

    def test_session_file_contains_full_packet_data(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr(
            "packet_capture.session.SESSIONS_DIR", tmp_path, raising=False
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            max_packets=3,
        )

        saved_file = next(tmp_path.glob("session_*.json"))
        with open(saved_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        assert len(data["packets"]) == 3
        assert data["packets"] == packets
        assert data["total_packets"] == 3
        assert any("Capture stopped" in a for a in data["actions"])

    def test_error_sink_receives_fatal_errors(self, monkeypatch) -> None:
        def raising_sniff(**kwargs: Any) -> None:
            raise OSError(
                "Sniffing and sending packets is not available at layer 2: "
                "winpcap is not installed."
            )

        monkeypatch.setattr("scapy.all.sniff", raising_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        errors: list = []
        packets = start_packet_capture(
            settings, print_summaries=False, error_sink=errors
        )

        assert packets == []
        assert len(errors) == 1
        assert "winpcap" in str(errors[0]).lower()

    def test_error_sink_stays_empty_on_success(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        errors: list = []
        start_packet_capture(
            settings, print_summaries=False, error_sink=errors, max_packets=2
        )

        assert errors == []

    def test_error_sink_none_does_not_break_capture(self, monkeypatch) -> None:
        """Default behavior (error_sink=None) must remain fully backward compatible."""
        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings, print_summaries=False, max_packets=2
        )
        assert len(packets) == 2

    def test_icmp_traffic_flows_correctly_through_full_pipeline(
        self, monkeypatch
    ) -> None:
        """
        ICMP has legitimate security-analysis value for a network
        behavior analyzer (ping sweeps, ICMP flooding, ICMP tunneling
        are all real attack patterns) and is kept in scope. This
        proves it flows correctly end-to-end: captured, parsed,
        validated, classified with a real direction, and counted in
        the final statistics - even though it has no owning
        application (which is expected, not a bug).
        """
        from scapy.layers.inet import ICMP

        def _icmp_packet() -> object:
            return Ether() / IP(src="192.168.1.5", dst="192.168.1.1", ttl=64) / ICMP()

        fake_sniff = _FakeSniffController(_icmp_packet, count=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        from packet_capture.statistics import StatisticsManager

        stats_manager = StatisticsManager()
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            stats_manager=stats_manager,
            max_packets=3,
        )

        assert len(packets) == 3
        assert all(p["protocol"] == "ICMP" for p in packets)
        assert all(p["direction"] == "OUTGOING" for p in packets)
        snapshot = stats_manager.snapshot()
        assert snapshot.icmp_count == 3


class TestStartPacketCaptureWithAppMapper:
    """
    Tests for live, per-packet application mapping during capture -
    packets returned from start_packet_capture() should already carry
    application_name/process_id/executable_path when an ApplicationMapper
    is supplied, without needing a separate post-capture mapping pass.
    """

    def test_packets_enriched_live_during_capture(self, monkeypatch) -> None:
        import socket
        from types import SimpleNamespace

        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        fake_sniff = _FakeSniffController(_tcp_packet, count=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        fake_conn = SimpleNamespace(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.5", port=52345),
            raddr=SimpleNamespace(ip="93.184.216.34", port=443),
            status="ESTABLISHED",
            pid=4242,
        )
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [fake_conn])
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: SimpleNamespace(
                name=lambda: "chrome.exe", exe=lambda: r"C:\chrome.exe"
            ),
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        mapper = ApplicationMapper()
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            app_mapper=mapper,
            max_packets=3,
        )

        assert len(packets) == 3
        assert all(p["application_name"] == "chrome.exe" for p in packets)
        assert all(p["process_id"] == 4242 for p in packets)

    def test_no_app_mapper_means_no_application_fields(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings, print_summaries=False, max_packets=2
        )

        assert "application_name" not in packets[0]

    def test_session_actions_log_live_mapping_enabled(self, monkeypatch) -> None:
        from packet_capture.app_mapper import ApplicationMapper
        from packet_capture.session import SessionManager

        fake_sniff = _FakeSniffController(_tcp_packet, count=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        import psutil

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        session_manager = SessionManager()
        mapper = ApplicationMapper()
        start_packet_capture(
            settings,
            print_summaries=False,
            session_manager=session_manager,
            app_mapper=mapper,
            max_packets=1,
        )

        actions = session_manager.current_session.actions
        assert any("Live application mapping enabled" in a for a in actions)

    def test_unmatched_connection_still_returns_unknown_gracefully(
        self, monkeypatch
    ) -> None:
        """Packets with no matching connection must not crash capture -
        they should simply come back with UNKNOWN application fields."""
        import psutil

        from packet_capture.app_mapper import ApplicationMapper, UNKNOWN_APPLICATION

        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        mapper = ApplicationMapper()
        packets = start_packet_capture(
            settings,
            print_summaries=False,
            app_mapper=mapper,
            max_packets=2,
        )

        assert len(packets) == 2
        assert all(p["application_name"] == UNKNOWN_APPLICATION for p in packets)

    def test_ipv6_packet_correctly_mapped_when_both_local_ips_given(
        self, monkeypatch
    ) -> None:
        """
        Reproduces and proves the fix for the real-world bug: a
        dual-stack interface's IPv6 traffic used to always come back
        UNKNOWN because only the IPv4 local address was passed in.
        Passing both (as main.py now does via all_local_ips) fixes it.
        """
        import socket

        from scapy.layers.inet6 import IPv6
        from scapy.layers.inet import TCP
        from scapy.layers.l2 import Ether
        import psutil
        from types import SimpleNamespace

        from packet_capture.app_mapper import ApplicationMapper

        def _ipv6_packet() -> object:
            return (
                Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                / IPv6(src="2401:4900::1", dst="2600:140f::1")
                / TCP(sport=30507, dport=80, flags="S")
            )

        fake_sniff = _FakeSniffController(_ipv6_packet, count=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        fake_conn = SimpleNamespace(
            fd=1,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="2401:4900::1", port=30507),
            raddr=SimpleNamespace(ip="2600:140f::1", port=80),
            status="ESTABLISHED",
            pid=9999,
        )
        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [fake_conn])
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: SimpleNamespace(name=lambda: "chrome.exe", exe=lambda: "p"),
        )

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        mapper = ApplicationMapper()
        packets = start_packet_capture(
            settings,
            local_ip=["10.81.61.39", "2401:4900::1"],  # both v4 and v6
            print_summaries=False,
            app_mapper=mapper,
            max_packets=1,
        )

        assert len(packets) == 1
        assert packets[0]["direction"] == "OUTGOING"
        assert packets[0]["application_name"] == "chrome.exe"

    def test_miss_triggers_immediate_refresh_and_catches_new_connection(
        self, monkeypatch
    ) -> None:
        """
        Simulates a connection that doesn't exist yet at the mapper's
        initial refresh (e.g. a short-lived UDP/QUIC flow that opens
        mid-capture) - proves the on-miss immediate refresh catches it
        rather than waiting for the next scheduled periodic refresh.
        """
        import socket
        from types import SimpleNamespace

        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        # First call (initial refresh): connection table is empty.
        # Second call (triggered by the miss): the connection now exists.
        call_count = {"n": 0}
        fake_conn = SimpleNamespace(
            fd=1,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
            laddr=SimpleNamespace(ip="192.168.1.5", port=52345),
            raddr=SimpleNamespace(ip="93.184.216.34", port=443),
            status="ESTABLISHED",
            pid=4242,
        )

        def fake_net_connections(kind: str = "inet"):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return []
            return [fake_conn]

        monkeypatch.setattr(psutil, "net_connections", fake_net_connections)
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: SimpleNamespace(name=lambda: "chrome.exe", exe=lambda: "p"),
        )
        # Force the miss-triggered refresh cooldown to zero so the retry
        # fires deterministically regardless of real wall-clock timing
        # between the initial refresh and the packet arriving.
        monkeypatch.setattr(
            "packet_capture.config.APP_MAPPER_MISS_REFRESH_COOLDOWN_SECONDS", 0.0
        )

        fake_sniff = _FakeSniffController(_tcp_packet, count=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        mapper = ApplicationMapper()
        packets = start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            app_mapper=mapper,
            max_packets=1,
        )

        assert len(packets) == 1
        # Miss-triggered refresh should have caught the newly-appeared
        # connection within the same packet's processing.
        assert packets[0]["application_name"] == "chrome.exe"
        assert call_count["n"] >= 2


class TestStartPacketCaptureOnPacketCallback:
    def test_callback_invoked_once_per_packet(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        received = []
        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        start_packet_capture(
            settings,
            print_summaries=False,
            on_packet=received.append,
            max_packets=3,
        )

        assert len(received) == 3
        assert all(p["protocol"] == "TCP" for p in received)

    def test_callback_receives_fully_processed_packet(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=1)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        received = []
        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        start_packet_capture(
            settings,
            local_ip="192.168.1.5",
            print_summaries=False,
            on_packet=received.append,
            max_packets=1,
        )

        assert "direction" in received[0]  # classification already applied

    def test_callback_exception_does_not_break_capture(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=3)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        def raising_callback(packet):
            raise RuntimeError("simulated bug in a callback")

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings,
            print_summaries=False,
            on_packet=raising_callback,
            max_packets=3,
        )

        # Capture must complete normally despite the callback failing.
        assert len(packets) == 3

    def test_none_callback_is_a_safe_default(self, monkeypatch) -> None:
        fake_sniff = _FakeSniffController(_tcp_packet, count=2)
        monkeypatch.setattr("scapy.all.sniff", fake_sniff)

        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="ALL"
        )
        packets = start_packet_capture(
            settings, print_summaries=False, max_packets=2
        )
        assert len(packets) == 2
