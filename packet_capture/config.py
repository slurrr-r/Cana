"""
config.py
=========

Centralized configuration for Module 1 (Network Traffic Collection &
Packet Processing). Keeping all tunable values in one place avoids
"magic numbers/strings" scattered through the codebase and makes the
module easy to adapt without touching business logic.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, List


# --------------------------------------------------------------------------- #
# Filesystem locations
# --------------------------------------------------------------------------- #

BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent


def _runtime_root() -> Path:
    """Installed Windows uses ProgramData; developer trees stay local.

    Source checkouts must not write to an ACL-protected data folder left by
    an installed copy.  That made a direct UI launch fail before it could
    explain how to install the service.
    """
    installed = bool(getattr(sys, "frozen", False)) and not (
        os.environ.get("CANA_DEV") == "1" or os.environ.get("CANA_TEST") == "1"
    )
    if os.name == "nt" and installed:
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            return Path(programdata) / "CANA"
    return BASE_DIR


LOGS_DIR: Final[Path] = _runtime_root() / "logs"
SESSIONS_DIR: Final[Path] = _runtime_root() / "sessions"

# NOTE: Packet export (CSV/JSON) has been intentionally removed from the
# scope of this project per explicit product decision. No "captures" or
# "exports" directories are created or written to by this module.


def ensure_runtime_directories() -> None:
    """
    Ensure all directories the module writes to at runtime exist.

    This is idempotent and safe to call multiple times (e.g. once at
    import time and again at application startup).
    """
    for directory in (LOGS_DIR, SESSIONS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #

LOG_FILE_NAME: Final[str] = "packet_capture.log"
LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024  # 5 MB per log file
LOG_BACKUP_COUNT: Final[int] = 3


# --------------------------------------------------------------------------- #
# Capture engine configuration
# --------------------------------------------------------------------------- #

# Packets are handed from the capture thread to the rest of the
# application through a bounded queue. A bound prevents unbounded memory
# growth if consumers fall behind producers.
PACKET_QUEUE_MAX_SIZE: Final[int] = 50_000

# Scapy's sniff() is polled in short bursts so the capture thread can
# periodically check a stop_event without blocking indefinitely.
SNIFF_POLL_TIMEOUT_SECONDS: Final[float] = 1.0

# Supported packet filters, presented to the user before capture starts.
SUPPORTED_FILTERS: Final[List[str]] = [
    "ALL",
    "TCP",
    "UDP",
    "ICMP",
    "DNS",
    "HTTP",
    "HTTPS",
]

# Port-based inference used only for HTTP/HTTPS classification, since
# Scapy has no reliable native HTTP layer and HTTPS payloads are
# encrypted. This is documented as heuristic, metadata-only inference.
HTTP_PORTS: Final[frozenset] = frozenset({80, 8080})
HTTPS_PORTS: Final[frozenset] = frozenset({443, 8443})

# In-memory packet retention cap. This is a safety valve independent of
# the queue: it caps how many parsed packet dicts are retained for the
# final returned list, to bound memory on very long sessions. Set to 0
# for unbounded (only recommended for short/demo sessions).
MAX_RETAINED_PACKETS: Final[int] = 200_000

# When live application-mapping is enabled during capture (main.py's
# default flow), the OS connection table is re-snapshotted periodically
# rather than once per packet, since psutil.net_connections() is
# relatively expensive. This bounds how "stale" the mapping can get
# for newly-opened connections without adding per-packet overhead.
APP_MAPPER_REFRESH_INTERVAL_SECONDS: Final[float] = 2.0

# When a packet fails to match against the current connection-table
# snapshot, it's often simply a very recently-opened connection (short
# UDP/QUIC flows in particular can open and close faster than the
# periodic refresh interval above). Rather than waiting for the next
# scheduled refresh, an immediate refresh is triggered on a cache miss -
# but cooldown-gated by this value, so bursts of unmatched packets
# don't each trigger their own expensive psutil call.
APP_MAPPER_MISS_REFRESH_COOLDOWN_SECONDS: Final[float] = 0.5


# --------------------------------------------------------------------------- #
# Session configuration
# --------------------------------------------------------------------------- #

SESSION_FILE_PREFIX: Final[str] = "session_"

# Separate, smaller cap on how many packets get written into the
# on-disk session JSON file, distinct from MAX_RETAINED_PACKETS (which
# bounds the in-memory list). A high-volume capture (e.g. a burst of
# several thousand packets/sec during a large download) can otherwise
# produce a multi-hundred-thousand-packet, quite large JSON file even
# though MAX_RETAINED_PACKETS already caps memory - this keeps the
# saved file a reasonable size for review/demo purposes. The true
# total_packets count in the session metadata always reflects the
# real, untruncated total - only the stored "packets" list is capped.
SESSION_MAX_STORED_PACKETS: Final[int] = 20_000


@dataclass(frozen=True)
class CaptureSettings:
    """
    Immutable bundle of user-selected settings for a single capture run.

    Attributes:
        interface_name: The OS-level identifier of the selected NIC.
        display_name: A human-friendly label for the same interface.
        packet_filter: One of SUPPORTED_FILTERS.
    """

    interface_name: str
    display_name: str
    packet_filter: str = "ALL"

    def __post_init__(self) -> None:
        if self.packet_filter.upper() not in SUPPORTED_FILTERS:
            raise ValueError(
                f"Unsupported packet filter '{self.packet_filter}'. "
                f"Must be one of {SUPPORTED_FILTERS}."
            )
