"""
traffic.py
==========

Read-only per-application traffic aggregation for the Apps page.

CANA's existing pipeline already persists application-mapped packets to
session JSON files (``application_name``, ``packet_size``, ``direction``,
``timestamp``). This module only *reads* those files and sums them; it
never captures packets, never touches the database, and never invents
numbers. If there is no session data for a range, the range is simply
empty and the UI shows an empty state.

Timestamps in session files are written by
``packet_capture.parser._extract_timestamp`` via ``time.localtime``, so
they are naive *local* times; they are parsed as local here to match.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ranges offered by the Apps page, in display order (per the mockup).
RANGE_ORDER: Tuple[str, ...] = ("Month", "Week", "24 Hours", "3 Hours")
DEFAULT_RANGE = "24 Hours"


@dataclass(frozen=True)
class RangeSpec:
    key: str
    seconds: int
    buckets: int
    label_format: str


RANGE_SPECS: Dict[str, RangeSpec] = {
    "Month": RangeSpec("Month", 30 * 86400, 30, "%b %d"),
    "Week": RangeSpec("Week", 7 * 86400, 7, "%b %d"),
    "24 Hours": RangeSpec("24 Hours", 24 * 3600, 24, "%H:%M"),
    "3 Hours": RangeSpec("3 Hours", 3 * 3600, 12, "%I:%M %p"),
}

UNKNOWN_APP = "Unknown"

_FINE_BUCKET_SECONDS = 60


@dataclass
class AppTraffic:
    """Per-app byte totals for one time range."""

    name: str
    down_bytes: int = 0
    up_bytes: int = 0

    @property
    def total_bytes(self) -> int:
        return self.down_bytes + self.up_bytes


@dataclass
class TrafficSeries:
    """Bucketed series for one app (or all apps combined)."""

    labels: List[str] = field(default_factory=list)
    down: List[int] = field(default_factory=list)
    up: List[int] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.labels or max(self.down + self.up) <= 0


def parse_packet_epoch(value: Any) -> Optional[float]:
    """
    Parse a session packet timestamp into an epoch float.

    Handles the naive local ``"%Y-%m-%d %H:%M:%S"`` strings CANA writes,
    ISO-8601 strings (with or without offset), and raw epoch numbers.
    Returns ``None`` for anything unparseable rather than guessing.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    # ISO-8601 with an explicit offset -> convert to local wall clock.
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return moment.timestamp()
    except ValueError:
        pass
    # Naive local timestamp as written by the parser.
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return time.mktime(time.strptime(text, fmt))
        except ValueError:
            continue
    return None


def _normalize_app(name: Any) -> str:
    text = str(name or "").strip()
    if not text or text.upper() in {"UNKNOWN", "N/A", "NONE"}:
        return UNKNOWN_APP
    return text


class SessionTrafficStore:
    """
    Aggregates per-app traffic from session files, with a short cache.

    The cache is keyed on the directory signature (file names, sizes,
    mtimes) so a refresh is cheap when nothing changed, which matters
    because the UI polls on a timer.
    """

    def __init__(self, sessions_dir: Optional[Path] = None, ttl_seconds: float = 5.0) -> None:
        self._dir = Path(sessions_dir) if sessions_dir is not None else _default_sessions_dir()
        self._ttl = max(0.0, float(ttl_seconds))
        self._loaded_at = 0.0
        self._signature: Optional[Tuple] = None
        # app -> {fine_bucket_epoch: (down, up)}
        self._apps: Dict[str, Dict[int, Tuple[int, int]]] = {}
        self._files_read = 0

    # -- public API ------------------------------------------------------
    @property
    def sessions_dir(self) -> Path:
        return self._dir

    @property
    def files_read(self) -> int:
        return self._files_read

    def apps(self, range_key: str, now: Optional[float] = None) -> List[AppTraffic]:
        """Per-app totals inside ``range_key``, largest total first."""
        self._ensure_fresh(now)
        spec = RANGE_SPECS.get(range_key, RANGE_SPECS[DEFAULT_RANGE])
        moment = now if now is not None else time.time()
        start, end = _range_bounds(spec, moment)
        totals: List[AppTraffic] = []
        for name, buckets in self._apps.items():
            down = up = 0
            for epoch, (d, u) in buckets.items():
                if start <= epoch <= end:
                    down += d
                    up += u
            if down or up:
                totals.append(AppTraffic(name=name, down_bytes=down, up_bytes=up))
        totals.sort(key=lambda item: (-item.total_bytes, item.name.lower()))
        return totals

    def series(
        self, name: Optional[str], range_key: str, now: Optional[float] = None
    ) -> TrafficSeries:
        """
        Bucketed series for one app, or for every app when ``name`` is
        ``None``.
        """
        self._ensure_fresh(now)
        spec = RANGE_SPECS.get(range_key, RANGE_SPECS[DEFAULT_RANGE])
        moment = now if now is not None else time.time()
        start, end = _range_bounds(spec, moment)
        width = max(1, int((end - start) / spec.buckets))

        labels: List[str] = []
        down = [0] * spec.buckets
        up = [0] * spec.buckets

        if name is None:
            chosen = list(self._apps.values())
        else:
            buckets = self._apps.get(name)
            chosen = [buckets] if buckets else []

        for buckets in chosen:
            for epoch, (d, u) in buckets.items():
                if epoch < start or epoch > end:
                    continue
                index = int((epoch - start) // width)
                index = min(max(index, 0), spec.buckets - 1) if spec.buckets else 0
                down[index] += d
                up[index] += u

        for index in range(spec.buckets):
            bucket_epoch = start + index * width
            labels.append(time.strftime(spec.label_format, time.localtime(bucket_epoch)))
        return TrafficSeries(labels=labels, down=down, up=up)

    # -- loading ---------------------------------------------------------
    def _ensure_fresh(self, now: Optional[float] = None) -> None:
        moment = now if now is not None else time.time()
        signature = self._directory_signature()
        if signature == self._signature and (moment - self._loaded_at) < self._ttl:
            return
        self._load(signature)
        self._loaded_at = moment

    def _directory_signature(self) -> Tuple:
        try:
            if not self._dir.is_dir():
                return (str(self._dir), None)
            entries = []
            for path in sorted(self._dir.glob("session_*.json")):
                try:
                    stat = path.stat()
                except OSError:
                    continue
                entries.append((path.name, stat.st_size, int(stat.st_mtime)))
            return (str(self._dir), tuple(entries))
        except OSError:
            return (str(self._dir), None)

    def _load(self, signature: Tuple) -> None:
        apps: Dict[str, Dict[int, Tuple[int, int]]] = {}
        files = 0
        entries = signature[1] if len(signature) > 1 else None
        if entries:
            for name, _size, _mtime in entries:
                packets = self._read_packets(self._dir / name)
                if packets is None:
                    continue
                files += 1
                for packet in packets:
                    epoch = parse_packet_epoch(packet.get("timestamp"))
                    if epoch is None:
                        continue
                    app = _normalize_app(packet.get("application_name"))
                    size = _as_int(packet.get("packet_size"))
                    if size <= 0:
                        continue
                    bucket = int(epoch // _FINE_BUCKET_SECONDS) * _FINE_BUCKET_SECONDS
                    direction = str(packet.get("direction") or "").upper()
                    down, up = apps.setdefault(app, {}).get(bucket, (0, 0))
                    if direction == "OUTGOING":
                        up += size
                    else:
                        # INCOMING, UNKNOWN, and unlabelled all count as
                        # received; direction is a capture-layer label and
                        # CANA does not always resolve it.
                        down += size
                    apps[app][bucket] = (down, up)
        self._apps = apps
        self._files_read = files
        self._signature = signature

    def sessions(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Read-only session records for History. Empty when none exist."""
        self._ensure_fresh()
        rows: List[Dict[str, Any]] = []
        try:
            if not self._dir.is_dir():
                return []
            paths = sorted(
                self._dir.glob("session_*.json"),
                key=lambda path: path.stat().st_mtime if path.exists() else 0,
                reverse=True,
            )
        except OSError:
            return []
        for path in paths[: max(0, int(limit))]:
            record = self._read_session_record(path)
            if record is not None:
                rows.append(record)
        return rows

    @staticmethod
    def _read_packets(path: Path) -> Optional[List[Dict[str, Any]]]:
        data = SessionTrafficStore._read_session_json(path)
        if data is None:
            return None
        packets = data.get("packets")
        return packets if isinstance(packets, list) else []

    @staticmethod
    def _read_session_json(path: Path) -> Optional[Dict[str, Any]]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _read_session_record(path: Path) -> Optional[Dict[str, Any]]:
        data = SessionTrafficStore._read_session_json(path)
        if not isinstance(data, dict):
            return None
        try:
            stat = path.stat()
        except OSError:
            return None
        packets = data.get("packets")
        packet_count = 0
        if isinstance(data, dict) and isinstance(data.get("total_packets"), (int, float)):
            packet_count = int(data.get("total_packets") or 0)
        elif isinstance(packets, list):
            packet_count = len(packets)
        started = ""
        interface = ""
        filter_name = ""
        session_id = path.stem.replace("session_", "", 1)
        if isinstance(data, dict):
            started = str(data.get("start_time") or data.get("started_at") or "")
            interface = str(
                data.get("interface_display_name")
                or data.get("interface")
                or ""
            )
            filter_name = str(data.get("applied_filter") or data.get("packet_filter") or "")
            if data.get("session_id"):
                session_id = str(data.get("session_id"))
        when = parse_packet_epoch(started)
        if when is None:
            when = float(stat.st_mtime)
        return {
            "session_id": session_id,
            "name": path.name,
            "interface": interface or "Unknown",
            "filter": filter_name or "ALL",
            "packet_count": packet_count,
            "size_bytes": int(stat.st_size),
            "started_at": started,
            "started_at_epoch": when,
        }


def _range_bounds(spec: RangeSpec, now: float) -> Tuple[float, float]:
    end = now
    start = now - spec.seconds
    return start, end


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _default_sessions_dir() -> Path:
    from packet_capture.config import SESSIONS_DIR

    return Path(SESSIONS_DIR)


def format_bytes(size: Any) -> str:
    """Compact byte size such as ``9.9 GB`` / ``4.5 KB`` / ``0 B``."""
    try:
        value = float(size or 0)
    except (TypeError, ValueError):
        return "0 B"
    value = max(0.0, value)
    if value < 1024:
        return f"{value:.0f} B"
    for unit in ("KB", "MB", "GB", "TB"):
        value /= 1024.0
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TB"


__all__ = [
    "AppTraffic",
    "DEFAULT_RANGE",
    "RANGE_ORDER",
    "RANGE_SPECS",
    "RangeSpec",
    "SessionTrafficStore",
    "TrafficSeries",
    "UNKNOWN_APP",
    "format_bytes",
    "parse_packet_epoch",
]
