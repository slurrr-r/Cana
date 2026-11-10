"""Unit tests for packet_capture.statistics."""

from __future__ import annotations

import time
from typing import Any, Dict

from packet_capture.statistics import StatisticsManager, StatisticsSnapshot


def _packet(
    protocol: str, direction: str, size: int, application_protocol: str = None
) -> Dict[str, Any]:
    return {
        "protocol": protocol,
        "direction": direction,
        "packet_size": size,
        "application_protocol": application_protocol,
    }


class TestStatisticsManagerEmptyState:
    def test_snapshot_before_any_update(self) -> None:
        stats = StatisticsManager()
        snapshot = stats.snapshot()
        assert snapshot.total_packets == 0
        assert snapshot.average_packet_size == 0.0
        assert snapshot.smallest_packet is None
        assert snapshot.largest_packet == 0


class TestStatisticsManagerUpdates:
    def test_total_packet_count_increments(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100))
        stats.update(_packet("UDP", "INCOMING", 200))
        snapshot = stats.snapshot()
        assert snapshot.total_packets == 2

    def test_direction_counts(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100))
        stats.update(_packet("TCP", "INCOMING", 100))
        stats.update(_packet("TCP", "INCOMING", 100))
        snapshot = stats.snapshot()
        assert snapshot.outgoing_packets == 1
        assert snapshot.incoming_packets == 2

    def test_protocol_counts(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100))
        # DNS is an application-layer label (application_protocol),
        # not a transport protocol - it rides over UDP here, and the
        # transport count (udp_count) and the DNS count are both
        # incremented for the same packet (P2 Bug #3 regression).
        stats.update(_packet("UDP", "OUTGOING", 100, application_protocol="DNS"))
        stats.update(_packet("ICMP", "OUTGOING", 100))
        stats.update(_packet("ARP", "OUTGOING", 100))
        snapshot = stats.snapshot()
        assert snapshot.tcp_count == 1
        assert snapshot.udp_count == 1
        assert snapshot.icmp_count == 1
        assert snapshot.dns_count == 1
        assert snapshot.other_protocol_count == 1

    def test_dns_over_tcp_counts_as_both_tcp_and_dns(self) -> None:
        """
        Regression test for P2 Bug #3: DNS-over-TCP must be counted
        as TCP traffic (transport) AND as DNS (application layer) -
        the two counts are independent, not mutually exclusive.
        """
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100, application_protocol="DNS"))
        snapshot = stats.snapshot()
        assert snapshot.tcp_count == 1
        assert snapshot.dns_count == 1

    def test_average_packet_size(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100))
        stats.update(_packet("TCP", "OUTGOING", 200))
        snapshot = stats.snapshot()
        assert snapshot.average_packet_size == 150.0

    def test_largest_and_smallest_packet(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 500))
        stats.update(_packet("TCP", "OUTGOING", 60))
        stats.update(_packet("TCP", "OUTGOING", 1500))
        snapshot = stats.snapshot()
        assert snapshot.largest_packet == 1500
        assert snapshot.smallest_packet == 60

    def test_missing_packet_size_treated_as_zero(self) -> None:
        stats = StatisticsManager()
        stats.update({"protocol": "TCP", "direction": "OUTGOING"})
        snapshot = stats.snapshot()
        assert snapshot.total_packets == 1
        assert snapshot.smallest_packet == 0

    def test_unknown_direction_not_counted_either_way(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "UNKNOWN", 100))
        snapshot = stats.snapshot()
        assert snapshot.incoming_packets == 0
        assert snapshot.outgoing_packets == 0
        assert snapshot.total_packets == 1


class TestStatisticsManagerDurationAndPps:
    def test_duration_and_pps_after_start(self) -> None:
        stats = StatisticsManager()
        stats.start()
        stats.update(_packet("TCP", "OUTGOING", 100))
        time.sleep(0.05)
        snapshot = stats.snapshot()
        assert snapshot.capture_duration_seconds > 0
        assert snapshot.packets_per_second >= 0

    def test_duration_zero_without_start(self) -> None:
        stats = StatisticsManager()
        stats.update(_packet("TCP", "OUTGOING", 100))
        snapshot = stats.snapshot()
        assert snapshot.capture_duration_seconds == 0.0
        assert snapshot.packets_per_second == 0.0


class TestStatisticsManagerReset:
    def test_reset_clears_all_counters(self) -> None:
        stats = StatisticsManager()
        stats.start()
        stats.update(_packet("TCP", "OUTGOING", 100))
        stats.reset()
        snapshot = stats.snapshot()
        assert snapshot.total_packets == 0
        assert snapshot.capture_duration_seconds == 0.0


class TestStatisticsSnapshotIsPlainDataclass:
    def test_snapshot_fields_accessible(self) -> None:
        stats = StatisticsManager()
        snapshot = stats.snapshot()
        assert isinstance(snapshot, StatisticsSnapshot)
        assert hasattr(snapshot, "total_packets")
