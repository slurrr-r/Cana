"""
config.py
=========

Centralized configuration for Module 3 (User Activity Detection).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final

# --------------------------------------------------------------------------- #
# Filesystem locations
# --------------------------------------------------------------------------- #

# Shared with the rest of the project (packet_capture) so all module
# logs land in one place under the project root, without this package
# importing packet_capture directly (keeping it standalone).
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent


def _runtime_logs_dir() -> Path:
    installed = bool(getattr(sys, "frozen", False)) and not (
        os.environ.get("CANA_DEV") == "1" or os.environ.get("CANA_TEST") == "1"
    )
    if os.name == "nt" and installed:
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            return Path(programdata) / "CANA" / "logs"
    return BASE_DIR / "logs"


LOGS_DIR: Final[Path] = _runtime_logs_dir()


def ensure_runtime_directories() -> None:
    """Ensure directories this module writes to at runtime exist."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------- #
# Logging configuration
# --------------------------------------------------------------------------- #

LOG_FILE_NAME: Final[str] = "user_activity.log"
LOG_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
LOG_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
LOG_MAX_BYTES: Final[int] = 5 * 1024 * 1024  # 5 MB per log file
LOG_BACKUP_COUNT: Final[int] = 3

# --------------------------------------------------------------------------- #
# Activity detection configuration
# --------------------------------------------------------------------------- #

# Per the original project plan: no activity for 5 minutes => IDLE.
IDLE_THRESHOLD_SECONDS: Final[float] = 300.0

# How often get_status() polling loops (if used) should re-check status.
STATUS_POLL_INTERVAL_SECONDS: Final[float] = 1.0
