"""
queries.py
==========

Read-only snapshot data for the native UI via the named pipe.

These helpers consume persisted alerts, risk scores, baseline buckets,
and session files. They do not reimplement detection. Missing files or
tables yield empty defaults so the UI can render before the first write.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from anomaly_detection.config import BASELINE_DB_PATH, MIN_OBSERVATIONS_FOR_BASELINE
from anomaly_detection.store import BaselineStore
from packet_capture.config import SESSIONS_DIR
from risk_scoring.store import RiskStore

_BASELINE_ESTABLISHED_MIN = MIN_OBSERVATIONS_FOR_BASELINE


def _open_read(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def overview(
    db_path: Optional[Path] = None, sessions_dir: Optional[Path] = None
) -> Dict[str, Any]:
    db = Path(db_path) if db_path is not None else BASELINE_DB_PATH
    baseline = baseline_summary(db)
    baseline_row = {
        "metrics": baseline["metrics"],
        "established_buckets": baseline["established_buckets"],
        "observations": baseline["observations"],
    }
    if not db.exists():
        return {
            "db_exists": False,
            "total_alerts": 0,
            "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
            "correlated_total": 0,
            "risk_updated_at": None,
            "session_count": 0,
            **baseline_row,
        }

    alert_store = BaselineStore(db)
    risk_store = RiskStore(db)
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for alert in alert_store.recent_alerts(limit=5000):
        severity = alert.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1
    scores = risk_store.latest_risk_scores(limit=1)
    risk_updated_at = scores[0]["updated_at"] if scores else None
    return {
        "db_exists": True,
        "total_alerts": alert_store.alert_count(),
        "severity_counts": severity_counts,
        "correlated_total": risk_store.correlated_alert_count(),
        "risk_updated_at": risk_updated_at,
        "session_count": len(list_sessions(sessions_dir or SESSIONS_DIR)),
        **baseline_row,
    }


def recent_alerts(db_path: Optional[Path] = None, limit: int = 50) -> List[Dict[str, Any]]:
    db = Path(db_path) if db_path is not None else BASELINE_DB_PATH
    if not db.exists():
        return []
    return BaselineStore(db).recent_alerts(limit=limit)


def risk_leaderboard(
    db_path: Optional[Path] = None, kind: str = "application", top_n: int = 10
) -> List[Dict[str, Any]]:
    db = Path(db_path) if db_path is not None else BASELINE_DB_PATH
    if not db.exists():
        return []
    return RiskStore(db).latest_risk_scores(kind=kind, limit=top_n)


def baseline_summary(db_path: Optional[Path] = None) -> Dict[str, Any]:
    db = Path(db_path) if db_path is not None else BASELINE_DB_PATH
    empty = {"metrics": 0, "established_buckets": 0, "observations": 0}
    if not db.exists():
        return empty
    try:
        with _open_read(db) as connection:
            row = connection.execute(
                "SELECT COUNT(DISTINCT metric_name) AS metrics, "
                " COUNT(*) AS buckets, "
                " COALESCE(SUM(observation_count), 0) AS observations, "
                " SUM(CASE WHEN observation_count >= ? THEN 1 ELSE 0 END) "
                "   AS established "
                "FROM baseline_buckets",
                (_BASELINE_ESTABLISHED_MIN,),
            ).fetchone()
    except sqlite3.Error:
        return empty
    if row is None:
        return empty
    return {
        "metrics": int(row["metrics"]),
        "established_buckets": int(row["established"] or 0),
        "observations": int(row["observations"]),
    }


def recent_correlated(
    db_path: Optional[Path] = None, limit: int = 500
) -> List[Dict[str, Any]]:
    """Recent correlated-alert windows, so the UI reads them via the pipe."""
    db = Path(db_path) if db_path is not None else BASELINE_DB_PATH
    if not db.exists():
        return []
    try:
        return RiskStore(db).recent_correlated_alerts(limit=limit)
    except Exception:  # noqa: BLE001
        return []


def list_sessions(sessions_dir: Path, limit: int = 50) -> List[Dict[str, Any]]:
    directory = Path(sessions_dir)
    if not directory.is_dir():
        return []
    sessions = []
    for path in directory.glob("session_*.json"):
        try:
            stat = path.stat()
        except OSError:
            continue
        sessions.append(
            {
                "name": path.name,
                "size_bytes": stat.st_size,
                "modified_at": stat.st_mtime,
            }
        )
    sessions.sort(key=lambda item: item["modified_at"], reverse=True)
    return sessions[: max(0, int(limit))]


__all__ = [
    "overview",
    "recent_alerts",
    "recent_correlated",
    "risk_leaderboard",
    "baseline_summary",
    "list_sessions",
]
