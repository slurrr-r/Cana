"""
store.py
========

SQLite persistence for Module 5: risk scores and correlated alerts.

Why this module exists
----------------------

Risk scores are the one thing in the system that the user wants to come
back to later ("which application was causing trouble yesterday?") even
though the raw packets are gone. Persisting them keeps the risk picture
across runs, and persisting correlated alerts gives the native UI a
history of *incidents*, not just individual rule firings.

It shares the SAME database file as the baseline and alert history
(``data/baseline.db``) so the native UI reads everything from one place.
It only ADDS tables - it never touches ``baseline_buckets``,
``triggered_alerts``, or ``schema_meta``, which belong to
``anomaly_detection.store.BaselineStore``.

Failure policy mirrors ``anomaly_detection/store.py`` exactly: every
public method is best-effort and never raises; a corrupt or unwritable
database is logged once and degrades to "no persistence this run".
Losing risk history is a real cost, but a strictly smaller one than
killing a live capture over it.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from anomaly_detection.config import BASELINE_DB_PATH

from risk_scoring.config import (
    RECENT_CORRELATED_DEFAULT_LIMIT,
    RISK_HISTORY_DEFAULT_LIMIT,
)
from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.logger import get_logger, log_module_event
from risk_scoring.scorer import RiskSnapshot

logger = get_logger(__name__)

_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS risk_scores (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        kind             TEXT NOT NULL,
        name             TEXT NOT NULL,
        score            REAL NOT NULL,
        events           INTEGER NOT NULL,
        updated_at       TEXT NOT NULL,
        updated_at_epoch REAL,
        UNIQUE (kind, name)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_score_history (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        kind             TEXT NOT NULL,
        name             TEXT NOT NULL,
        score            REAL NOT NULL,
        events           INTEGER NOT NULL,
        recorded_at      TEXT NOT NULL,
        recorded_at_epoch REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS correlated_alerts (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id         TEXT NOT NULL,
        started_at       TEXT NOT NULL,
        started_at_epoch REAL NOT NULL,
        ended_at         TEXT NOT NULL,
        ended_at_epoch   REAL NOT NULL,
        application_name TEXT,
        destination_ip   TEXT,
        rule_names       TEXT NOT NULL,
        signal_count     INTEGER NOT NULL,
        severity         TEXT NOT NULL,
        score            REAL NOT NULL,
        confidence       REAL NOT NULL,
        reason           TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_correlated_epoch "
    "ON correlated_alerts(started_at_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_risk_history_lookup "
    "ON risk_score_history(kind, name, recorded_at_epoch)",
)


class RiskStore:
    """
    Reads and writes risk scores and correlated alerts.

    Every method degrades rather than raising (see module docstring), so
    callers can treat persistence as best-effort and never need to guard
    individual calls. :attr:`available` reports whether the store is
    currently usable.

    Connections are opened per operation rather than held open, for the
    same thread-affinity reason documented in
    ``anomaly_detection.store.BaselineStore``.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else BASELINE_DB_PATH
        self._available = True
        self._schema_ready = False

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def db_path(self) -> Path:
        """Filesystem path of the SQLite database this store uses."""
        return self._db_path

    @property
    def available(self) -> bool:
        """Whether persistence is currently working."""
        return self._available

    # ------------------------------------------------------------------ #
    # Connection handling
    # ------------------------------------------------------------------ #

    def _connect(self) -> sqlite3.Connection:
        """
        Open a connection, creating the parent directory and schema on
        first use.

        Raises:
            OSError, sqlite3.Error: Propagated to the calling public
                method, which is responsible for degrading gracefully.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(self._db_path, timeout=10.0)
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            if not self._schema_ready:
                self._initialize_schema(connection)
                self._schema_ready = True
        except BaseException:
            connection.close()
            raise

        return connection

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        """
        Create the risk tables if absent (never touches other tables),
        then migrate older risk_scores tables forward.
        """
        with connection:
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)

            # Pre-restore builds of risk_scores had no
            # updated_at_epoch column. Risk state restoration needs the
            # persisted timestamp to resume decay correctly, so bring
            # such tables up to the current schema in place rather than
            # discarding the risk data. Ignored if already present.
            try:
                connection.execute(
                    "ALTER TABLE risk_scores "
                    "ADD COLUMN updated_at_epoch REAL"
                )
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc).lower():
                    raise

    def _disable(self, operation: str, exc: BaseException) -> None:
        """Record that persistence has failed unrecoverably and log why."""
        if self._available:
            logger.warning(
                "Risk persistence disabled after %s failed (%s: %s). "
                "The current run continues without risk persistence.",
                operation,
                type(exc).__name__,
                exc,
            )
            log_module_event(logger, "RISK_PERSISTENCE_DISABLED", detail=f"operation={operation}")
        self._available = False

    # ------------------------------------------------------------------ #
    # Risk scores
    # ------------------------------------------------------------------ #

    def save_risk_snapshot(self, snapshot: RiskSnapshot) -> bool:
        """
        Persist a risk snapshot: UPSERT current scores and append history.

        Args:
            snapshot: A snapshot from :meth:`RiskScorer.snapshot`.

        Returns:
            ``True`` if the write succeeded, ``False`` otherwise.
        """
        if not self._available:
            return False

        entries = list(snapshot.applications) + list(snapshot.destinations)
        if not entries:
            return True

        recorded_at_iso = _epoch_to_iso(snapshot.generated_at)

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_risk_snapshot", exc)
            return False

        try:
            with connection:
                connection.executemany(
                    "INSERT INTO risk_scores "
                    "(kind, name, score, events, updated_at, updated_at_epoch) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(kind, name) DO UPDATE SET "
                    "  score = excluded.score, "
                    "  events = excluded.events, "
                    "  updated_at = excluded.updated_at, "
                    "  updated_at_epoch = excluded.updated_at_epoch",
                    [
                        (
                            e.kind,
                            e.name,
                            e.score,
                            e.events,
                            recorded_at_iso,
                            snapshot.generated_at,
                        )
                        for e in entries
                    ],
                )
                connection.executemany(
                    "INSERT INTO risk_score_history "
                    "(kind, name, score, events, recorded_at, recorded_at_epoch) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        (
                            e.kind,
                            e.name,
                            e.score,
                            e.events,
                            recorded_at_iso,
                            snapshot.generated_at,
                        )
                        for e in entries
                    ],
                )
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_risk_snapshot", exc)
            return False
        finally:
            connection.close()

        log_module_event(
            logger,
            "RISK_SNAPSHOT_SAVED",
            detail=f"entries={len(entries)} path={self._db_path}",
        )
        return True

    def latest_risk_scores(
        self, kind: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Return the current persisted risk scores, highest first.

        Args:
            kind: Restrict to "application" or "destination" if given.
            limit: Maximum rows to return.

        Returns:
            A list of plain dicts (one per entity), or an empty list if
            there is nothing stored or it can't be read.
        """
        if not self._db_path.exists():
            return []

        query = (
            "SELECT kind, name, score, events, updated_at, updated_at_epoch "
            "FROM risk_scores"
        )
        params: tuple = ()
        if kind is not None:
            query += " WHERE kind = ?"
            params = (kind,)
        query += " ORDER BY score DESC LIMIT ?"
        params = params + (max(0, int(limit)),)

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("latest_risk_scores", exc)
            return []

        try:
            with connection:
                rows = connection.execute(query, params).fetchall()
        except (OSError, sqlite3.Error) as exc:
            self._disable("latest_risk_scores", exc)
            return []
        finally:
            connection.close()

        return [dict(row) for row in rows]

    def load_risk_state(
        self, now: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Return the persisted risk state in the exact shape needed to
        restore a :class:`RiskScorer` across a restart.

        This is the other half of risk persistence: :meth:`RiskStore`
        already stored risk scores as *history*; this method makes them
        *restorable state* again. Each returned dict carries the epoch
        timestamp the score was current at, so a restored scorer can
        resume time-decay from that instant rather than from "now".

        Args:
            now: Epoch reference. Only used as the fallback when a
                stored timestamp cannot be parsed; the persisted epoch
                is authoritative whenever present.

        Returns:
            A list of dicts with keys ``kind``, ``name``, ``score``,
            ``events``, ``updated_at``, ``updated_at_epoch`` - or an
            empty list if nothing is stored or it cannot be read.
        """
        rows = self.latest_risk_scores()
        reference = time.time() if now is None else now
        for row in rows:
            epoch = row.get("updated_at_epoch")
            if not epoch:
                epoch = _iso_to_epoch(row.get("updated_at"), fallback=reference)
            row["updated_at_epoch"] = epoch
        return rows

    def risk_history(
        self, kind: str, name: str, limit: int = RISK_HISTORY_DEFAULT_LIMIT
    ) -> List[Dict[str, Any]]:
        """
        Return the recorded score history for one entity, newest first.

        Args:
            kind: "application" or "destination".
            name: The entity name.
            limit: Maximum rows to return.

        Returns:
            A list of plain dicts, or an empty list if unavailable.
        """
        if not self._db_path.exists():
            return []

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("risk_history", exc)
            return []

        try:
            with connection:
                rows = connection.execute(
                    "SELECT kind, name, score, events, recorded_at, recorded_at_epoch "
                    "FROM risk_score_history WHERE kind = ? AND name = ? "
                    "ORDER BY recorded_at_epoch DESC LIMIT ?",
                    (kind, name, max(0, int(limit))),
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            self._disable("risk_history", exc)
            return []
        finally:
            connection.close()

        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ #
    # Correlated alerts
    # ------------------------------------------------------------------ #

    def save_correlated_alert(self, alert: CorrelatedAlert) -> bool:
        """
        Append one correlated alert to the incident history.

        Args:
            alert: The correlated alert to persist.

        Returns:
            ``True`` if the row was written, ``False`` otherwise.
        """
        if not self._available:
            return False

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_correlated_alert", exc)
            return False

        try:
            with connection:
                connection.execute(
                    "INSERT INTO correlated_alerts ("
                    " alert_id, started_at, started_at_epoch, ended_at,"
                    " ended_at_epoch, application_name, destination_ip,"
                    " rule_names, signal_count, severity, score, confidence,"
                    " reason"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        alert.alert_id,
                        _epoch_to_iso(alert.started_at),
                        alert.started_at,
                        _epoch_to_iso(alert.ended_at),
                        alert.ended_at,
                        alert.application_name,
                        alert.destination_ip,
                        json.dumps(list(alert.rule_names)),
                        alert.signal_count,
                        alert.severity,
                        alert.score,
                        alert.confidence,
                        alert.reason,
                    ),
                )
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_correlated_alert", exc)
            return False
        finally:
            connection.close()

        return True

    def recent_correlated_alerts(
        self, limit: int = RECENT_CORRELATED_DEFAULT_LIMIT
    ) -> List[Dict[str, Any]]:
        """
        Return the most recent correlated alerts, newest first.

        ``rule_names`` is stored as JSON text and parsed back into a
        list of strings in the returned dicts.

        Args:
            limit: Maximum rows to return.

        Returns:
            A list of plain dicts, or an empty list if unavailable.
        """
        if not self._db_path.exists():
            return []

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("recent_correlated_alerts", exc)
            return []

        try:
            with connection:
                rows = connection.execute(
                    "SELECT alert_id, started_at, started_at_epoch, ended_at,"
                    " ended_at_epoch, application_name, destination_ip,"
                    " rule_names, signal_count, severity, score, confidence,"
                    " reason FROM correlated_alerts "
                    "ORDER BY ended_at_epoch DESC, id DESC LIMIT ?",
                    (max(0, int(limit)),),
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            self._disable("recent_correlated_alerts", exc)
            return []
        finally:
            connection.close()

        result = []
        for row in rows:
            record = dict(row)
            try:
                record["rule_names"] = json.loads(record["rule_names"])
            except (TypeError, ValueError):
                record["rule_names"] = []
            result.append(record)
        return result

    def correlated_alert_count(self) -> int:
        """Total number of correlated alerts recorded across all sessions."""
        if not self._db_path.exists():
            return 0

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("correlated_alert_count", exc)
            return 0

        try:
            with connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM correlated_alerts"
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            self._disable("correlated_alert_count", exc)
            return 0
        finally:
            connection.close()

        return int(row["total"]) if row is not None else 0


def _epoch_to_iso(epoch_seconds: float) -> str:
    """Convert an epoch timestamp to an ISO-8601 UTC string."""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def _iso_to_epoch(iso_text: Optional[str], fallback: float) -> float:
    """
    Parse an ISO-8601 UTC string back into an epoch timestamp.

    Written by :meth:`RiskStore._epoch_to_iso` as e.g.
    ``2026-09-05T10:00:00.123456+00:00``. Used when restoring risk
    state from a database written before ``updated_at_epoch`` existed.

    Args:
        iso_text: The stored timestamp string, or ``None``.
        fallback: Value to return if the string cannot be parsed.

    Returns:
        The epoch seconds, or ``fallback`` on any parse failure.
    """
    if not iso_text:
        return fallback
    try:
        parsed = datetime.fromisoformat(iso_text)
    except (TypeError, ValueError):
        return fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


__all__ = ["RiskStore"]
