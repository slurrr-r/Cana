"""
correlated.py
=============

Read-only access to CANA's correlated-alert windows.

The Alerts page reports each incident as Window closed or Unknown by
matching it against the correlation windows the risk scorer already
persists. Those records are not part of the service's snapshot payload,
so the UI reads them straight from the anomaly database using SQLite's
read-only URI.

This is exactly the concurrent-read case the store documents for WAL
mode ("the native UI can read the baseline and alert history *while* a
capture is running and writing"). Nothing here writes to the database,
opens it read-write, or changes its schema; any failure degrades to an
empty window list so the page still renders, with statuses shown as
Unknown rather than guessed.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _default_db_path() -> Path:
    from anomaly_detection.config import BASELINE_DB_PATH

    return Path(BASELINE_DB_PATH)


def load_correlated(
    db_path: Optional[Path] = None, limit: int = 500
) -> List[Dict[str, Any]]:
    """
    Return recent ``correlated_alerts`` rows, newest first.

    Missing database, locked file, or absent table all yield ``[]`` so
    callers never have to special-case a not-yet-populated store.
    """
    path = Path(db_path) if db_path is not None else _default_db_path()
    if not path.exists():
        return []
    try:
        connection = sqlite3.connect(
            f"file:{path}?mode=ro", uri=True, timeout=2.0
        )
    except sqlite3.Error:
        return []
    try:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM correlated_alerts "
            "ORDER BY started_at_epoch DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


class CorrelatedStore:
    """Small TTL cache around :func:`load_correlated` for the UI poll."""

    def __init__(self, db_path: Optional[Path] = None, ttl_seconds: float = 5.0) -> None:
        self._db_path = Path(db_path) if db_path is not None else None
        self._ttl = max(0.0, float(ttl_seconds))
        self._loaded_at = 0.0
        self._rows: List[Dict[str, Any]] = []

    def rows(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        moment = now if now is not None else time.time()
        if (moment - self._loaded_at) < self._ttl:
            return self._rows
        self._rows = load_correlated(self._db_path)
        self._loaded_at = moment
        return self._rows


__all__ = ["CorrelatedStore", "load_correlated"]
