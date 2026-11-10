"""
statistics.py
=============

Live packet statistics tracking.

Uses running aggregates (running sum/count/min/max) updated
incrementally per packet, rather than recomputing over the full
packet history on every update. This keeps per-packet update cost at
O(1) regardless of how many packets have been captured, which matters
for long-running, high-throughput capture sessions.

Thread-safety note: an internal lock guards all state mutation, since
in the full application statistics are updated from a consumer thread
reading off the capture queue while being read concurrently by a
console-refresh loop.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class StatisticsSnapshot:
    """An immutable point-in-time view of capture statistics."""

    total_packets: int
    incoming_packets: int
    outgoing_packets: int
    tcp_count: int
    udp_count: int
    icmp_count: int
    dns_count: int
    other_protocol_count: int
    average_packet_size: float
    largest_packet: int
    smallest_packet: Optional[int]
    packets_per_second: float
    capture_duration_seconds: float


class StatisticsManager:
    """
    Tracks live statistics over a stream of classified packet
    dictionaries.

    Typical usage::

        stats = StatisticsManager()
        stats.start()
        for packet in incoming_packets:
            stats.update(packet)
        snapshot = stats.snapshot()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_packets = 0
        self._incoming_packets = 0
        self._outgoing_packets = 0
        self._protocol_counts: Counter = Counter()
        # Tracked separately from _protocol_counts: DNS is an
        # application-layer label (classify_packet's
        # ``application_protocol`` field), not a transport protocol -
        # ``_protocol_counts`` is keyed by transport protocol
        # ("TCP"/"UDP"/"ICMP") and never contains "DNS", so DNS
        # traffic must be counted from ``application_protocol``
        # instead (see Module 4 P2 fix: DNS is no longer written into
        # the ``protocol`` field by the parser).
        self._dns_count = 0
        self._size_sum = 0
        self._largest_packet = 0
        self._smallest_packet: Optional[int] = None
        self._start_time: Optional[float] = None

    def start(self) -> None:
        """Mark the beginning of a capture session for duration/PPS math."""
        with self._lock:
            self._start_time = time.time()

    def update(self, classified_packet: Dict[str, Any]) -> None:
        """
        Incrementally update running statistics with one classified
        packet.

        Args:
            classified_packet: A packet dictionary as produced by
                :func:`packet_capture.classifier.classify_packet`
                (must include at least ``packet_size``, ``protocol``,
                and ``direction``).
        """
        size = classified_packet.get("packet_size") or 0
        protocol = (classified_packet.get("protocol") or "OTHER").upper()
        application_protocol = classified_packet.get("application_protocol")
        direction = (classified_packet.get("direction") or "").upper()

        with self._lock:
            self._total_packets += 1
            self._size_sum += size

            if size > self._largest_packet:
                self._largest_packet = size
            if self._smallest_packet is None or size < self._smallest_packet:
                self._smallest_packet = size

            if direction == "INCOMING":
                self._incoming_packets += 1
            elif direction == "OUTGOING":
                self._outgoing_packets += 1

            # Transport-layer count (TCP/UDP/ICMP/...) and
            # application-layer DNS count are independent, not
            # mutually exclusive - a DNS packet is BOTH counted as
            # UDP/TCP here AND as DNS below.
            self._protocol_counts[protocol] += 1
            if application_protocol == "DNS":
                self._dns_count += 1

    def snapshot(self) -> StatisticsSnapshot:
        """
        Return a consistent, point-in-time snapshot of all tracked
        statistics.

        Returns:
            A :class:`StatisticsSnapshot`. All counts are ``0`` and
            averages are ``0.0`` if no packets have been processed yet.
        """
        with self._lock:
            duration = (
                time.time() - self._start_time if self._start_time else 0.0
            )
            duration = max(duration, 0.0)
            average_size = (
                self._size_sum / self._total_packets
                if self._total_packets > 0
                else 0.0
            )
            pps = self._total_packets / duration if duration > 0 else 0.0

            known = {"TCP", "UDP", "ICMP"}
            other_count = sum(
                count
                for proto, count in self._protocol_counts.items()
                if proto not in known
            )

            return StatisticsSnapshot(
                total_packets=self._total_packets,
                incoming_packets=self._incoming_packets,
                outgoing_packets=self._outgoing_packets,
                tcp_count=self._protocol_counts.get("TCP", 0),
                udp_count=self._protocol_counts.get("UDP", 0),
                icmp_count=self._protocol_counts.get("ICMP", 0),
                dns_count=self._dns_count,
                other_protocol_count=other_count,
                average_packet_size=round(average_size, 2),
                largest_packet=self._largest_packet,
                smallest_packet=self._smallest_packet,
                packets_per_second=round(pps, 2),
                capture_duration_seconds=round(duration, 2),
            )

    def reset(self) -> None:
        """Reset all counters back to their initial state."""
        with self._lock:
            self._total_packets = 0
            self._incoming_packets = 0
            self._outgoing_packets = 0
            self._protocol_counts = Counter()
            self._dns_count = 0
            self._size_sum = 0
            self._largest_packet = 0
            self._smallest_packet = None
            self._start_time = None
