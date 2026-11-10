"""
utils.py
========

Small, stateless helper functions shared across the package -
primarily console formatting, so display logic doesn't get duplicated
between ``main.py`` and any future entry point.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from packet_capture.statistics import StatisticsSnapshot

_DIRECTION_ARROWS = {"INCOMING": "\u2193", "OUTGOING": "\u2191", "UNKNOWN": "?"}


def format_packet_summary(classified_packet: Dict[str, Any]) -> str:
    """
    Build a clean, single-line console summary for one packet.

    Example output::

        [10:42:18] TCP  192.168.1.5 -> 93.184.216.34  Port 52345->443  Len 1514B

    Used when no application mapping is available for this run. When
    application mapping is enabled, :func:`format_packet_block` is
    used instead so the owning application is shown.

    Args:
        classified_packet: A fully parsed + classified packet
            dictionary.

    Returns:
        A formatted, human-readable summary line.
    """
    timestamp = classified_packet.get("timestamp", "")
    # Keep only the time portion if a full "YYYY-MM-DD HH:MM:SS" string.
    time_part = timestamp.split(" ")[-1] if timestamp else "--:--:--"

    protocol = classified_packet.get("protocol", "UNKNOWN")
    src_ip = classified_packet.get("source_ip") or "?"
    dst_ip = classified_packet.get("destination_ip") or "?"
    direction = (classified_packet.get("direction") or "UNKNOWN").upper()
    arrow = _DIRECTION_ARROWS.get(direction, "?")

    src_port = classified_packet.get("source_port")
    dst_port = classified_packet.get("destination_port")
    port_part = f"  Port {src_port}->{dst_port}" if src_port and dst_port else ""

    size = classified_packet.get("packet_size", 0)

    return (
        f"[{time_part}] {protocol:<5} {src_ip} {arrow} {dst_ip}"
        f"{port_part}  Len {size}B"
    )


_DIRECTION_LABELS = {
    "INCOMING": "Incoming",
    "OUTGOING": "Outgoing",
    "UNKNOWN": "Direction unknown",
}


def format_packet_block(packet: Dict[str, Any]) -> str:
    """
    Build a multi-line console block for one packet, showing which
    application generated it and whether it's incoming or outgoing -
    used when live application mapping is enabled during capture.

    Example output::

        [12:17:41]
        chrome.exe
        TCP (Outgoing)
        10.48.1.5 -> 142.250.1.1
        Port 41807 -> 443

    Args:
        packet: A fully parsed + classified + application-mapped
            packet dictionary (must include ``application_name`` -
            see :meth:`packet_capture.app_mapper.ApplicationMapper.enrich_packet`,
            and ``direction`` - see
            :func:`packet_capture.classifier.classify_packet`).

    Returns:
        A formatted, multi-line, human-readable block.
    """
    timestamp = packet.get("timestamp", "")
    time_part = timestamp.split(" ")[-1] if timestamp else "--:--:--"

    application_name = packet.get("application_name") or "UNKNOWN"
    protocol = packet.get("protocol", "UNKNOWN")
    direction = (packet.get("direction") or "UNKNOWN").upper()
    direction_label = _DIRECTION_LABELS.get(direction, "Direction unknown")
    src_ip = packet.get("source_ip") or "?"
    dst_ip = packet.get("destination_ip") or "?"

    lines = [
        f"[{time_part}]",
        application_name,
        f"{protocol} ({direction_label})",
        f"{src_ip} \u2192 {dst_ip}",
    ]

    src_port = packet.get("source_port")
    dst_port = packet.get("destination_port")
    if src_port and dst_port:
        lines.append(f"Port {src_port} \u2192 {dst_port}")

    return "\n".join(lines)


def format_statistics_line(snapshot: StatisticsSnapshot) -> str:
    """
    Build a compact, single-line live statistics summary suitable for
    periodic console refresh.

    Args:
        snapshot: A statistics snapshot from
            :class:`packet_capture.statistics.StatisticsManager`.

    Returns:
        A formatted statistics summary line.
    """
    return (
        f"Total: {snapshot.total_packets} | "
        f"In: {snapshot.incoming_packets} Out: {snapshot.outgoing_packets} | "
        f"TCP: {snapshot.tcp_count} UDP: {snapshot.udp_count} "
        f"ICMP: {snapshot.icmp_count} DNS: {snapshot.dns_count} | "
        f"Avg: {snapshot.average_packet_size}B | "
        f"Max: {snapshot.largest_packet}B Min: {snapshot.smallest_packet or 0}B | "
        f"PPS: {snapshot.packets_per_second} | "
        f"Duration: {snapshot.capture_duration_seconds}s"
    )


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds as ``HH:MM:SS``.

    Args:
        seconds: Elapsed time in seconds.

    Returns:
        A zero-padded ``HH:MM:SS`` string.
    """
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class LiveConsolePrinter:
    """
    Stateful console printer for live per-packet display, addressing
    two real usability problems with printing one raw block per packet:

    1. **Repeat spam**: the same active connection (e.g. an editor's
       long-lived HTTPS connection) generates many packets back and
       forth. Printing a full multi-line block for every single one
       makes the console unreadable. This tracks the previously
       printed connection and, when the *same* connection repeats,
       prints a throttled, plain running-count line instead of a full
       block each time.
    2. **Low-value noise**: packets with no resolved application (most
       commonly OS-level ICMPv6 control traffic, which has no owning
       process by nature) can dominate the live view without adding
       much value to watch scroll by. These are hidden from the
       console by default - but never dropped from the data itself;
       every packet is still fully recorded in the returned packet
       list and the session JSON regardless of what's shown here.

    Design note: an earlier version of this class overwrote the
    repeat-count line in place using a carriage-return (``\\r``) trick
    for a slicker live-terminal effect. That was removed after real
    usage showed it garbles badly the moment output is copied,
    redirected to a file, piped through a logger, or shared for
    debugging (exactly the kind of sharing this project does often) -
    old and new text collide into unreadable mashed-together lines.
    Every line this class prints now is a complete, independent,
    plain-text line - always safe to copy, log, or paste, at the small
    cost of a few more lines on screen during a very long-lived
    repeated conversation.

    Usage::

        printer = LiveConsolePrinter(suppress_unmapped=True)
        for packet in packets:
            printer.display(packet)
        printer.finalize()  # call once after the loop ends
    """

    # Minimum time between repeat-count lines for the SAME ongoing
    # conversation, so a fast burst doesn't print a new count line for
    # every single repeated packet - throttled, not spammy, but always
    # a plain new line rather than an in-place overwrite.
    _REPEAT_SUMMARY_INTERVAL_SECONDS: float = 1.0

    def __init__(self, suppress_unmapped: bool = True) -> None:
        """
        Args:
            suppress_unmapped: If True (default), packets whose
                ``application_name`` is ``UNKNOWN`` (or missing, e.g.
                no app mapper in use) are not printed to the console.
                They are still returned/saved normally - this only
                affects what's displayed live.
        """
        self._suppress_unmapped = suppress_unmapped
        self._last_key: Any = None
        self._last_sample: Dict[str, Any] = {}
        self._repeat_count: int = 0
        self._last_summary_time: float = 0.0

    @staticmethod
    def _connection_key(packet: Dict[str, Any]) -> Any:
        """
        Build a key identifying "the same conversation" for collapsing
        purposes - based on which two IPs are talking (regardless of
        direction) and which app/protocol, but deliberately NOT on
        exact port numbers.

        This matters in practice: a single logical conversation (e.g.
        a browser or background service repeatedly polling the same
        server) commonly cycles through several different ephemeral
        source ports in quick succession. Keying on the exact port
        pair would treat each new port as a "different" conversation
        and defeat collapsing exactly when it matters most - during
        a real burst of many packets between the same two endpoints.
        """
        endpoints = frozenset(
            {packet.get("source_ip"), packet.get("destination_ip")}
        )
        return (
            packet.get("application_name"),
            packet.get("protocol"),
            endpoints,
        )

    @staticmethod
    def _format_repeat_summary(packet: Dict[str, Any], count: int) -> str:
        """Build one plain, complete repeat-count line - never overwritten."""
        return (
            f"{packet.get('application_name') or 'UNKNOWN'}  "
            f"{packet.get('protocol', 'UNKNOWN')}  "
            f"{packet.get('source_ip') or '?'} \u2194 "
            f"{packet.get('destination_ip') or '?'}  "
            f"({count} packets exchanged)"
        )

    def display(self, packet: Dict[str, Any]) -> None:
        """
        Display one packet, applying suppression and repeat-collapsing
        as configured. Safe to call once per packet in a tight loop.
        """
        application_name = packet.get("application_name")
        is_unmapped = not application_name or application_name == "UNKNOWN"

        if self._suppress_unmapped and is_unmapped:
            return

        key = self._connection_key(packet)

        if key == self._last_key:
            self._repeat_count += 1
            self._last_sample = packet
            now = time.time()
            if now - self._last_summary_time >= self._REPEAT_SUMMARY_INTERVAL_SECONDS:
                print(self._format_repeat_summary(packet, self._repeat_count))
                self._last_summary_time = now
            return

        # Switching to a new conversation - if the previous one had
        # repeats beyond what the last throttled line showed, print
        # its true final tally now so the count is never left stale.
        if self._last_key is not None and self._repeat_count > 1:
            print(self._format_repeat_summary(self._last_sample, self._repeat_count))

        print(format_packet_block(packet))
        print()
        self._last_key = key
        self._last_sample = packet
        self._repeat_count = 1
        self._last_summary_time = time.time()

    def finalize(self) -> None:
        """
        Call once after the capture loop ends, to print the final,
        accurate tally for whatever conversation was still repeating
        when capture stopped (the periodic throttle may have last
        shown a lower, now-stale count).
        """
        if self._last_key is not None and self._repeat_count > 1:
            print(self._format_repeat_summary(self._last_sample, self._repeat_count))
