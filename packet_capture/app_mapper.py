"""
app_mapper.py
=============

Module 2 - Application/Process Mapping.

Given packets already captured, parsed, and classified by Module 1,
this module identifies *which running process* generated each packet
by correlating the packet's local IP:port against the OS-level
connection table (``psutil.net_connections``), then resolving the
owning PID to a process name and executable path.

Scope boundary (per project plan): this module only maps packets to
applications. It does NOT implement user idle/active detection,
context records, anomaly detection, alerts, or any storage/UI -
those remain out of scope for later modules.

Important, honest caveats about this kind of correlation:
    * ``psutil.net_connections()`` is a **snapshot** of the connection
      table at the instant it is called. Short-lived connections
      (e.g. a quick DNS lookup or a fast HTTP request) may already be
      closed and gone from that table by the time this module checks
      it, even if you check immediately after capture. This makes
      matching inherently best-effort, not guaranteed.
    * On Windows (and most platforms), listing *other users' or
      system* processes' connections with full detail typically
      requires elevated (Administrator) privileges. Without them,
      some entries may have a PID of ``0``/``None`` or raise
      ``psutil.AccessDenied`` when resolving process details.
    * A local port is only an unambiguous process identifier when a
      single PID owns it. Multiple PIDs can legitimately share one
      local port (e.g. ``SO_REUSEPORT`` listeners such as multiple
      server worker processes, or different daemons bound to distinct
      local IPs), in which case the port-only fallback cannot tell
      which process a packet belongs to. Such ports are treated as
      ambiguous and resolve to ``UNKNOWN`` rather than guessing a
      PID - attributing traffic to the wrong process is worse than
      admitting the mapping is indeterminate.
    * Process identities (name/executable) are resolved against the
      connection snapshot at refresh time and cached. This binds each
      PID to the process that owned its connection at capture time, so
      a PID that is recycled to a *different* process later is never
      mistaken for the original one; the change is detected via the
      process start time on the next refresh.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from packet_capture.logger import get_logger, log_module_event

logger = get_logger(__name__)

UNKNOWN_APPLICATION = "UNKNOWN"


class ProcessResolutionError(Exception):
    """Raised for unrecoverable errors while resolving process info."""


@dataclass(frozen=True)
class ProcessInfo:
    """Resolved identity of the process owning a connection."""

    pid: Optional[int]
    name: str
    executable_path: Optional[str]
    create_time: Optional[float] = None


@dataclass(frozen=True)
class ConnectionRecord:
    """
    A single OS-level network connection, as reported by psutil,
    normalized into the fields this module needs for matching.
    """

    protocol: str  # "TCP" or "UDP"
    local_ip: Optional[str]
    local_port: Optional[int]
    remote_ip: Optional[str]
    remote_port: Optional[int]
    pid: Optional[int]


def _protocol_from_socket_type(sock_type: int) -> Optional[str]:
    """Map a psutil connection's socket type to our protocol names."""
    if sock_type == socket.SOCK_STREAM:
        return "TCP"
    if sock_type == socket.SOCK_DGRAM:
        return "UDP"
    return None


def get_active_connections() -> List[ConnectionRecord]:
    """
    Snapshot the current OS-level TCP/UDP connection table.

    Returns:
        A list of :class:`ConnectionRecord`. Returns an empty list
        (rather than raising) if permission is denied, logging a
        warning instead - the caller should still function, just with
        reduced mapping accuracy.
    """
    try:
        import psutil
    except ImportError as exc:
        raise ProcessResolutionError(
            "psutil is not installed or failed to import."
        ) from exc

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        logger.warning(
            "Permission denied listing system connections. Run as "
            "Administrator for full application-mapping accuracy."
        )
        return []
    except Exception as exc:  # noqa: BLE001 - psutil raises varied platform errors
        logger.error("Failed to list active connections: %s", exc)
        return []

    records: List[ConnectionRecord] = []
    for conn in raw_connections:
        protocol = _protocol_from_socket_type(conn.type)
        if protocol is None:
            continue

        local_ip, local_port = (None, None)
        if conn.laddr:
            local_ip, local_port = conn.laddr.ip, conn.laddr.port

        remote_ip, remote_port = (None, None)
        if conn.raddr:
            remote_ip, remote_port = conn.raddr.ip, conn.raddr.port

        records.append(
            ConnectionRecord(
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                pid=conn.pid,
            )
        )

    return records


def _build_lookup_tables(
    connections: List[ConnectionRecord],
) -> Tuple[Dict[Tuple[str, str, int, str, int], int], Dict[Tuple[str, int], int]]:
    """
    Build two lookup dictionaries from connection records for fast
    matching: an exact 4-tuple+protocol match, and a fallback
    protocol+local-port-only match (useful when a listening socket's
    local IP is ``0.0.0.0``/``::`` but the packet has a concrete IP).

    The port-only fallback is only meaningful while a local port maps
    to exactly one owning PID. When several *distinct* PIDs share a
    local port (e.g. ``SO_REUSEPORT`` server workers, or separate
    daemons bound to different local IPs), the port is ambiguous: no
    packet can be attributed to one of those processes with any
    confidence, so the key is deliberately omitted from the fallback
    table and the packet resolves to ``UNKNOWN`` instead of silently
    guessing whichever PID ``psutil`` happened to report first.

    Returns:
        ``(exact_lookup, port_only_lookup)``, both mapping to a PID.
        ``port_only_lookup`` only ever contains keys owned by a
        single distinct PID.
    """
    exact_lookup: Dict[Tuple[str, str, int, str, int], int] = {}
    port_owners: Dict[Tuple[str, int], set] = {}

    for conn in connections:
        if conn.pid is None:
            continue
        if conn.local_ip is None or conn.local_port is None:
            continue

        port_owners.setdefault((conn.protocol, conn.local_port), set()).add(
            conn.pid
        )

        if conn.remote_ip is not None and conn.remote_port is not None:
            key = (
                conn.protocol,
                conn.local_ip,
                conn.local_port,
                conn.remote_ip,
                conn.remote_port,
            )
            exact_lookup[key] = conn.pid

    port_only_lookup: Dict[Tuple[str, int], int] = {}
    for port_key, owners in port_owners.items():
        if len(owners) == 1:
            port_only_lookup[port_key] = next(iter(owners))

    return exact_lookup, port_only_lookup


def _determine_local_side(
    packet: Dict[str, Any]
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int]]:
    """
    Determine which side of a classified packet (source or
    destination) represents the local machine, using the ``direction``
    field set by Module 1's classifier.

    Returns:
        ``(local_ip, local_port, remote_ip, remote_port)``, all
        ``None`` if direction is unknown/unavailable.
    """
    direction = (packet.get("direction") or "").upper()

    if direction == "OUTGOING":
        return (
            packet.get("source_ip"),
            packet.get("source_port"),
            packet.get("destination_ip"),
            packet.get("destination_port"),
        )
    if direction == "INCOMING":
        return (
            packet.get("destination_ip"),
            packet.get("destination_port"),
            packet.get("source_ip"),
            packet.get("source_port"),
        )
    return (None, None, None, None)


class ApplicationMapper:
    """
    Maps classified packets to the application/process that generated
    them, using a snapshot of the OS connection table.

    Typical usage::

        mapper = ApplicationMapper()
        mapper.refresh()
        enriched_packets = [mapper.enrich_packet(p) for p in packets]

    The connection table is only refreshed when :meth:`refresh` is
    called explicitly (or on first use), rather than on every packet,
    since ``psutil.net_connections()`` is relatively expensive to call
    and connections don't change fast enough to justify a per-packet
    refresh in practice.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._exact_lookup: Dict[Tuple[str, str, int, str, int], int] = {}
        self._port_only_lookup: Dict[Tuple[str, int], int] = {}
        self._process_cache: Dict[int, ProcessInfo] = {}
        self._refreshed = False
        self._last_refresh_time: float = 0.0

    def refresh(self) -> int:
        """
        Re-snapshot the OS connection table and rebuild lookup indices.

        Process identities (name/executable) are resolved here, against
        the freshly captured snapshot, and cached keyed by PID. PIDs
        that appeared in the *previous* snapshot are first checked for
        process continuity via their start time: an unchanged process
        reuses its cached identity (no redundant re-resolution), while
        a PID whose start time changed was recycled by the OS and is
        re-resolved as whatever process owns it now.

        Returns:
            The number of connection records captured in this refresh.
        """
        with self._lock:
            connections = get_active_connections()
            self._exact_lookup, self._port_only_lookup = _build_lookup_tables(
                connections
            )
            snapshot_pids = {
                conn.pid for conn in connections if conn.pid is not None
            }
            self._rebuild_process_cache(snapshot_pids)
            self._refreshed = True
            self._last_refresh_time = time.time()
        log_module_event(
            logger, "CONNECTION_TABLE_REFRESHED", detail=f"count={len(connections)}"
        )
        return len(connections)

    def refresh_if_stale(self, min_interval_seconds: float) -> bool:
        """
        Refresh the connection table only if at least
        ``min_interval_seconds`` have passed since the last refresh.

        Intended for "refresh on cache miss" use: when a packet fails
        to match against the current snapshot, it may simply be a
        very recently-opened connection (common for short-lived UDP/
        QUIC flows) that the last periodic refresh missed. Refreshing
        immediately on every single miss would hammer
        ``psutil.net_connections()`` under bursty traffic, so this is
        cooldown-gated rather than unconditional.

        Args:
            min_interval_seconds: Minimum time that must have elapsed
                since the last refresh for this call to actually
                trigger a new one.

        Returns:
            True if a refresh was actually performed, False if the
            cooldown was still active.
        """
        if time.time() - self._last_refresh_time >= min_interval_seconds:
            self.refresh()
            return True
        return False

    @staticmethod
    def _probe_create_time(pid: int) -> Optional[float]:
        """
        Read a PID's current process start time, or ``None`` if it
        cannot be determined (process already gone, permission denied,
        psutil unavailable, ...). Used to detect PID reuse between
        refreshes.
        """
        try:
            import psutil

            return psutil.Process(pid).create_time()
        except Exception:  # noqa: BLE001 - NoSuchProcess/AccessDenied/ImportError/etc.
            return None

    def _resolve_process_identity(self, pid: int) -> ProcessInfo:
        """
        Resolve a PID to its process identity *now*, capturing the
        start time as an identity anchor so a later PID reuse can be
        detected. On any resolution failure the process degrades to
        ``UNKNOWN`` rather than raising, mirroring prior behavior.
        """
        try:
            import psutil

            proc = psutil.Process(pid)
            name = proc.name()
            try:
                exe_path: Optional[str] = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe_path = None

            create_time: Optional[float] = None
            try:
                create_time = proc.create_time()
            except Exception:  # noqa: BLE001 - fakes/mocks may omit it
                create_time = None

            return ProcessInfo(
                pid=pid,
                name=name,
                executable_path=exe_path,
                create_time=create_time,
            )
        except Exception as exc:  # noqa: BLE001 - psutil.NoSuchProcess/AccessDenied/etc.
            logger.warning("Could not resolve process for PID %s: %s", pid, exc)
            return ProcessInfo(pid=pid, name=UNKNOWN_APPLICATION, executable_path=None)

    def _rebuild_process_cache(self, snapshot_pids: set) -> None:
        """
        Rebuild the process cache to describe exactly the PIDs present
        in the latest connection snapshot.

        Each PID is resolved against the snapshot's instant, so an
        enrich later in this snapshot's lifetime can never mistake a
        recycled PID for the process that owned the connection at
        capture time. A PID seen in the previous snapshot is reused
        without re-resolution when its start time is unchanged; when
        the start time differs the PID was recycled and the entry is
        re-resolved (and the reuse logged).

        Args:
            snapshot_pids: The distinct PIDs owning connections in the
                snapshot just captured.
        """
        new_cache: Dict[int, ProcessInfo] = {}
        for pid in snapshot_pids:
            previous = self._process_cache.get(pid)
            if previous is None:
                new_cache[pid] = self._resolve_process_identity(pid)
                continue

            current_start = self._probe_create_time(pid)
            if (
                previous.create_time is not None
                and current_start is not None
                and abs(current_start - previous.create_time) < 1e-3
            ):
                new_cache[pid] = previous
                continue

            if previous.create_time is not None and current_start is not None:
                logger.warning(
                    "PID %s was recycled by the OS (start time %.3f -> "
                    "%.3f); resolving its new process identity.",
                    pid,
                    previous.create_time,
                    current_start,
                )
            new_cache[pid] = self._resolve_process_identity(pid)

        self._process_cache = new_cache

    def _resolve_process(self, pid: int) -> ProcessInfo:
        """
        Look up a PID in the snapshot-bound process cache.

        Every PID :meth:`match_pid` can return is resolved during the
        refresh that built the lookup tables, so this is a pure cache
        read. It deliberately never queries the *current* process table
        on a miss: doing so could attribute a packet to a recycled
        process that no longer corresponds to the connection snapshot.
        """
        cached = self._process_cache.get(pid)
        if cached is not None:
            return cached
        logger.debug(
            "PID %s not found in the snapshot-bound process cache; "
            "treating it as UNKNOWN.",
            pid,
        )
        return ProcessInfo(pid=pid, name=UNKNOWN_APPLICATION, executable_path=None)

    def match_pid(self, packet: Dict[str, Any]) -> Optional[int]:
        """
        Find the PID owning the connection a packet belongs to, if any.

        Args:
            packet: A classified packet dictionary (must include
                ``direction``, ``protocol``, and IP/port fields).

        Returns:
            The matching PID, or ``None`` if no match was found. A
            ``None`` from the port-only fallback also covers local
            ports shared by multiple distinct PIDs, which are never
            guessed (see :func:`_build_lookup_tables`).
        """
        protocol = (packet.get("protocol") or "").upper()
        if protocol not in ("TCP", "UDP"):
            return None

        local_ip, local_port, remote_ip, remote_port = _determine_local_side(packet)
        if local_ip is None or local_port is None:
            return None

        if remote_ip is not None and remote_port is not None:
            exact_key = (protocol, local_ip, local_port, remote_ip, remote_port)
            pid = self._exact_lookup.get(exact_key)
            if pid is not None:
                return pid

        return self._port_only_lookup.get((protocol, local_port))

    def enrich_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return a new packet dictionary enriched with application
        mapping fields: ``application_name``, ``process_id``,
        ``executable_path``.

        If the connection table has never been refreshed, this
        refreshes it once automatically (with a warning logged),
        since mapping without any data would be silently useless.

        Args:
            packet: A classified packet dictionary from Module 1.

        Returns:
            A new dictionary equal to ``packet`` plus the three
            application-mapping fields. Values are ``None``/
            ``UNKNOWN`` when no match could be made.
        """
        if not self._refreshed:
            logger.warning(
                "ApplicationMapper.enrich_packet called before refresh(); "
                "refreshing automatically."
            )
            self.refresh()

        enriched = dict(packet)
        pid = self.match_pid(packet)

        if pid is None:
            enriched["application_name"] = UNKNOWN_APPLICATION
            enriched["process_id"] = None
            enriched["executable_path"] = None
            return enriched

        process_info = self._resolve_process(pid)
        enriched["application_name"] = process_info.name
        enriched["process_id"] = process_info.pid
        enriched["executable_path"] = process_info.executable_path
        return enriched


def map_packets_to_applications(
    packets: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Convenience function: map a full list of classified packets to
    their originating applications in one call.

    This is the primary public entry point for Module 2, mirroring
    Module 1's ``start_packet_capture()`` contract::

        from packet_capture.capture import start_packet_capture
        from packet_capture.app_mapper import map_packets_to_applications

        packets = start_packet_capture(settings)
        enriched_packets = map_packets_to_applications(packets)

    Args:
        packets: Classified packet dictionaries from Module 1.

    Returns:
        A new list of dictionaries, each enriched with
        ``application_name``, ``process_id``, and ``executable_path``.
    """
    mapper = ApplicationMapper()
    mapper.refresh()
    return [mapper.enrich_packet(packet) for packet in packets]
