"""
store.py
========

SQLite persistence for Module 4: the learned baseline and the history
of triggered alerts.

Why this module exists
----------------------

Without it, ``BaselineTracker`` is purely in-memory and every run
cold-starts. That isn't merely inconvenient - it structurally defeats
two of the four rules. ``packet_size_anomaly`` needs
``MIN_OBSERVATIONS_FOR_BASELINE`` samples and
``connection_rate_anomaly`` needs ``MIN_RATE_SAMPLES_FOR_BASELINE``
samples *per application, per hour bucket*, so within a short run both
spend their whole life reporting "baseline not yet established". The
project's central premise - "is this unusual for THIS machine at THIS
time of day" - only becomes true in practice once observations survive
across runs.

Why SQLite rather than a JSON dump
----------------------------------

* **Transactional writes.** A capture is stopped with Ctrl+C, so a save
  landing mid-write is a routine event, not an edge case. A truncated
  JSON file would be an unreadable baseline; a rolled-back transaction
  leaves the previous good state intact.
* **Concurrent reads (WAL).** The native UI can read the baseline and
  alert history *while* a capture is running and writing.
* **The data is genuinely relational.** The baseline is keyed
  (metric, hour-of-day), so "replace this one bucket's state" is exactly
  an UPSERT on a primary key.

Failure policy
--------------

Every public method here is non-fatal. A corrupt database, a locked
database, a full disk, a read-only directory - all are logged and
degrade to "no persistence this run", never propagate. Losing learned
history is a real cost, but it is strictly smaller than killing a live
capture over it, and it mirrors how ``main.py`` already treats Module 3
(``_start_activity_tracker``): an enhancement that fails does not take
the core down with it.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from anomaly_detection.baseline import BaselineSnapshot
from anomaly_detection.config import (
    BASELINE_DB_PATH,
    BASELINE_SCHEMA_VERSION,
    RECENT_ALERTS_DEFAULT_LIMIT,
    ensure_runtime_directories,
)
from anomaly_detection.logger import get_logger, log_module_event
from anomaly_detection.rules import RuleResult

logger = get_logger(__name__)

_SCHEMA_VERSION_KEY = "schema_version"

# Note on column naming: the bucket's observation count is stored as
# "observation_count" rather than "count" to avoid an identifier that
# reads as the SQL aggregate function in queries. Every other column
# mirrors a ContextRecord field name exactly (see context.py), so
# recording an alert is a direct field mapping and any future reader
# needs no translation layer.
_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS baseline_buckets (
        metric_name       TEXT    NOT NULL,
        hour_of_day       INTEGER NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
        observation_count INTEGER NOT NULL,
        mean              REAL    NOT NULL,
        m2                REAL    NOT NULL,
        updated_at        TEXT    NOT NULL,
        PRIMARY KEY (metric_name, hour_of_day)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS triggered_alerts (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id         TEXT,
        triggered_at       TEXT    NOT NULL,
        triggered_at_epoch REAL    NOT NULL,
        rule_name          TEXT    NOT NULL,
        severity           TEXT    NOT NULL,
        reason             TEXT    NOT NULL,
        application_name   TEXT    NOT NULL,
        process_id         INTEGER,
        source_ip          TEXT,
        destination_ip     TEXT,
        protocol           TEXT,
        application_protocol TEXT,
        communication_type TEXT,
        user_status        TEXT    NOT NULL,
        idle_seconds       REAL    NOT NULL,
        packet_size        INTEGER NOT NULL,
        hour_of_day        INTEGER NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_time "
    "ON triggered_alerts(triggered_at_epoch)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_rule ON triggered_alerts(rule_name)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_session "
    "ON triggered_alerts(session_id)",
)


class BaselineStore:
    """
    Reads and writes the learned baseline and triggered-alert history.

    Every method degrades rather than raising (see module docstring), so
    callers can treat persistence as best-effort and never need to guard
    individual calls. :attr:`available` reports whether the store is
    currently usable, for callers that want to tell the user.

    Connections are opened per operation rather than held open. This is
    deliberate: ``sqlite3`` connections are bound to the thread that
    created them, and this store is written to from a background
    checkpointer thread while alerts are recorded from the capture
    thread. A short-lived connection per call sidesteps that entirely,
    and at one checkpoint per 30 seconds the connect cost is irrelevant.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else BASELINE_DB_PATH
        self._available = True
        self._schema_ready = False

    # ----------------------------------------------------------------- #
    # Properties
    # ----------------------------------------------------------------- #

    @property
    def db_path(self) -> Path:
        """Filesystem path of the SQLite database this store uses."""
        return self._db_path

    @property
    def available(self) -> bool:
        """
        Whether persistence is currently working.

        Set to ``False`` the first time an operation fails for a reason
        that won't fix itself (unwritable location, corrupt file), so
        the application can report "running without persistence" once
        rather than logging the same warning every checkpoint.
        """
        return self._available

    # ----------------------------------------------------------------- #
    # Connection handling
    # ----------------------------------------------------------------- #

    def _connect(self) -> sqlite3.Connection:
        """
        Open a connection, creating the parent directory and schema on
        first use.

        Raises:
            OSError, sqlite3.Error: Propagated to the calling public
                method, which is responsible for degrading gracefully.
        """
        if self._db_path.parent == BASELINE_DB_PATH.parent:
            ensure_runtime_directories()
        else:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(self._db_path, timeout=10.0)
        connection.row_factory = sqlite3.Row

        try:
            # WAL lets a reader (e.g. the native UI) run concurrently with
            # the capture process's writes. It's a persistent property of
            # the database file, so setting it on every connect is a
            # no-op after the first time. synchronous=NORMAL is the
            # standard companion setting: it drops the per-commit fsync
            # while remaining crash-safe under WAL.
            #
            # This is also where a corrupt/non-database file first makes
            # itself known: sqlite3.connect() is lazy and succeeds on any
            # path, so the "file is not a database" error surfaces on the
            # first statement executed, not on connect.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")

            if not self._schema_ready:
                self._initialize_schema(connection)
                self._schema_ready = True
        except BaseException:
            # Never leak the handle when setup fails - on Windows an open
            # handle to a bad file would also block the user from simply
            # deleting it to recover.
            connection.close()
            raise

        return connection

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        """Create tables/indexes if absent and record the schema version."""
        with connection:
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
            columns = {row[1] for row in connection.execute('PRAGMA table_info(triggered_alerts)')}
            # Additive migration preserves existing alert history and baseline statistics.
            for name, sql_type in (
                ('direction', 'TEXT'), ('source_port', 'INTEGER'), ('destination_port', 'INTEGER'),
                ('tcp_flags', 'TEXT'), ('dns_query_name', 'TEXT'), ('dns_is_response', 'INTEGER'),
                ('dns_id', 'INTEGER'), ('dns_rcode', 'INTEGER'),
                ('dns_qtype', 'INTEGER'), ('dns_qclass', 'INTEGER'),
            ):
                if name not in columns:
                    connection.execute(f'ALTER TABLE triggered_alerts ADD COLUMN {name} {sql_type}')
            connection.execute(
                "INSERT INTO schema_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO NOTHING",
                (_SCHEMA_VERSION_KEY, str(BASELINE_SCHEMA_VERSION)),
            )

    def _stored_schema_version(self, connection: sqlite3.Connection) -> int:
        """
        Return the schema version recorded in the database.

        A database with no recorded version is treated as the current
        version: that's what a freshly created database looks like
        between ``CREATE TABLE`` and the version ``INSERT``.
        """
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key = ?", (_SCHEMA_VERSION_KEY,)
        ).fetchone()
        if row is None:
            return BASELINE_SCHEMA_VERSION
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return -1

    def _disable(self, operation: str, exc: BaseException) -> None:
        """
        Record that persistence has failed unrecoverably and log why.

        Only logs on the transition, so a failing checkpoint every 30
        seconds doesn't flood the log with the same line.
        """
        if self._available:
            logger.warning(
                "Baseline persistence disabled after %s failed (%s: %s). "
                "The current run continues with an in-memory-only baseline.",
                operation,
                type(exc).__name__,
                exc,
            )
            log_module_event(
                logger, "PERSISTENCE_DISABLED", detail=f"operation={operation}"
            )
        self._available = False

    # ----------------------------------------------------------------- #
    # Baseline
    # ----------------------------------------------------------------- #

    def load_baseline(self) -> BaselineSnapshot:
        """
        Load the persisted baseline.

        Returns:
            A snapshot suitable for :meth:`BaselineTracker.restore`, or
            an empty dict when there is nothing to load - the database
            doesn't exist yet, holds no buckets, was written by an
            incompatible schema version, or is unreadable. In every one
            of those cases the correct behavior is an honest cold start,
            never an exception and never a partial guess.
        """
        if not self._db_path.exists():
            log_module_event(
                logger, "BASELINE_COLD_START", detail=f"path={self._db_path}"
            )
            return {}

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("load_baseline", exc)
            return {}

        try:
            with connection:
                stored_version = self._stored_schema_version(connection)
                if stored_version != BASELINE_SCHEMA_VERSION:
                    logger.warning(
                        "Ignoring baseline at %s: schema version %s does not "
                        "match this build's version %s. Starting with an "
                        "empty baseline rather than misreading it.",
                        self._db_path,
                        stored_version,
                        BASELINE_SCHEMA_VERSION,
                    )
                    return {}

                rows = connection.execute(
                    "SELECT metric_name, hour_of_day, observation_count, mean, m2 "
                    "FROM baseline_buckets"
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            self._disable("load_baseline", exc)
            return {}
        finally:
            connection.close()

        snapshot: BaselineSnapshot = {}
        for row in rows:
            metric_buckets = snapshot.setdefault(row["metric_name"], {})
            metric_buckets[int(row["hour_of_day"])] = (
                int(row["observation_count"]),
                float(row["mean"]),
                float(row["m2"]),
            )

        log_module_event(
            logger,
            "BASELINE_LOADED",
            detail=(
                f"metrics={len(snapshot)} buckets={len(rows)} "
                f"path={self._db_path}"
            ),
        )
        return snapshot

    def save_baseline(self, snapshot: BaselineSnapshot) -> bool:
        """
        Persist a baseline snapshot.

        Each bucket's row is REPLACED with the given absolute state -
        never accumulated into. This matters more than it looks:
        ``BaselineTracker.snapshot()`` always returns the full current
        state, which already includes everything loaded at startup. An
        UPSERT that added counts instead of overwriting them would
        re-add the entire loaded baseline on every checkpoint, inflating
        ``observation_count`` without bound and driving the learned
        variance toward nonsense - while looking perfectly healthy in a
        single-run test.

        Args:
            snapshot: State from :meth:`BaselineTracker.snapshot`.

        Returns:
            ``True`` if the write succeeded, ``False`` if persistence is
            unavailable or the write failed (already logged).
        """
        if not self._available:
            return False

        rows = [
            (
                metric_name,
                hour,
                state[0],
                state[1],
                state[2],
                _utc_now_iso(),
            )
            for metric_name, hour_states in snapshot.items()
            for hour, state in hour_states.items()
        ]

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_baseline", exc)
            return False

        try:
            with connection:
                connection.executemany(
                    "INSERT INTO baseline_buckets "
                    "(metric_name, hour_of_day, observation_count, mean, m2, "
                    " updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(metric_name, hour_of_day) DO UPDATE SET "
                    "  observation_count = excluded.observation_count, "
                    "  mean              = excluded.mean, "
                    "  m2                = excluded.m2, "
                    "  updated_at        = excluded.updated_at",
                    rows,
                )
        except (OSError, sqlite3.Error) as exc:
            self._disable("save_baseline", exc)
            return False
        finally:
            connection.close()

        log_module_event(
            logger, "BASELINE_SAVED", detail=f"buckets={len(rows)}"
        )
        return True

    def reset_baseline(self) -> bool:
        """
        Delete all learned baseline data, leaving alert history intact.

        Alert history is deliberately preserved: it's a record of things
        that actually happened, and discarding it because someone wanted
        to retrain the baseline would be destroying unrelated evidence.

        Returns:
            ``True`` if the reset succeeded, ``False`` otherwise.
        """
        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("reset_baseline", exc)
            return False

        try:
            with connection:
                connection.execute("DELETE FROM baseline_buckets")
        except (OSError, sqlite3.Error) as exc:
            self._disable("reset_baseline", exc)
            return False
        finally:
            connection.close()

        log_module_event(
            logger, "BASELINE_RESET", detail=f"path={self._db_path}"
        )
        return True

    # ----------------------------------------------------------------- #
    # Alerts
    # ----------------------------------------------------------------- #

    def record_alert(
        self, result: RuleResult, session_id: Optional[str] = None
    ) -> bool:
        """
        Append one triggered rule result to the alert history.

        This writes synchronously, which is only acceptable because of
        where it is called from: ``main.py``'s packet handler records an
        alert on a rule's RISING EDGE only (once when a condition
        starts, not per packet while it persists). Without that
        de-duplication this would be a disk write per packet, and would
        have to be batched instead.

        Args:
            result: The triggered rule result to record. Non-triggered
                results are ignored, so callers don't need to filter.
            session_id: The capture session this alert belongs to, for
                joining back to the session JSON file under
                ``sessions/``.

        Returns:
            ``True`` if the row was written, ``False`` otherwise.
        """
        if not result.triggered or not self._available:
            return False

        context = result.context

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("record_alert", exc)
            return False

        try:
            with connection:
                connection.execute(
                    "INSERT INTO triggered_alerts ("
                    " session_id, triggered_at, triggered_at_epoch, rule_name,"
                    " severity, reason, application_name, process_id,"
                    " source_ip, destination_ip, protocol, application_protocol,"
                    " communication_type,"
                    " user_status, idle_seconds, packet_size, hour_of_day,"
                    " direction, source_port, destination_port, tcp_flags, dns_query_name,"
                    " dns_is_response, dns_id, dns_rcode, dns_qtype, dns_qclass"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        session_id,
                        _epoch_to_iso(context.timestamp),
                        context.timestamp,
                        result.rule_name,
                        result.severity,
                        result.reason,
                        context.application_name,
                        context.process_id,
                        context.source_ip,
                        context.destination_ip,
                        context.protocol,
                        context.application_protocol,
                        context.communication_type,
                        context.user_status,
                        context.idle_seconds,
                        context.packet_size,
                        context.hour_of_day,
                        context.direction, context.source_port, context.destination_port,
                        context.tcp_flags, context.dns_query_name, context.dns_is_response,
                        context.dns_id, context.dns_rcode,
                        context.dns_qtype, context.dns_qclass,
                    ),
                )
        except (OSError, sqlite3.Error) as exc:
            self._disable("record_alert", exc)
            return False
        finally:
            connection.close()

        return True

    def recent_alerts(
        self, limit: int = RECENT_ALERTS_DEFAULT_LIMIT
    ) -> List[Dict[str, Any]]:
        """
        Return the most recent alerts, newest first.

        Args:
            limit: Maximum rows to return.

        Returns:
            A list of plain dicts (one per alert), or an empty list if
            there is no history or it can't be read.
        """
        if not self._db_path.exists():
            return []

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("recent_alerts", exc)
            return []

        try:
            with connection:
                rows = connection.execute(
                    "SELECT * FROM triggered_alerts "
                    "ORDER BY triggered_at_epoch DESC, id DESC LIMIT ?",
                    (max(0, int(limit)),),
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            self._disable("recent_alerts", exc)
            return []
        finally:
            connection.close()

        return [dict(row) for row in rows]

    def alert_count(self) -> int:
        """
        Total number of alerts recorded across all sessions.

        Returns ``0`` if there is no history or it can't be read.
        """
        if not self._db_path.exists():
            return 0

        try:
            connection = self._connect()
        except (OSError, sqlite3.Error) as exc:
            self._disable("alert_count", exc)
            return 0

        try:
            with connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM triggered_alerts"
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            self._disable("alert_count", exc)
            return 0
        finally:
            connection.close()

        return int(row["total"]) if row is not None else 0


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string (matches session.py's format)."""
    return datetime.now(timezone.utc).isoformat()


def _epoch_to_iso(epoch_seconds: float) -> str:
    """
    Convert an epoch timestamp to an ISO-8601 UTC string.

    Both the raw epoch value and this rendering are stored for each
    alert: the epoch column is what range queries and ordering use, the
    ISO column is what a human reads without conversion.
    """
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


__all__ = ["BaselineStore"]
