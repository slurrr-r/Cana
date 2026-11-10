"""
Unit tests for anomaly_detection.store (SQLite persistence).

Every test uses a temporary database via ``tmp_path``; nothing here
touches the project's real ``data/`` directory.
"""

from __future__ import annotations

import sqlite3
import time

import pytest

from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.config import BASELINE_SCHEMA_VERSION
from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from anomaly_detection.store import BaselineStore


def _context(**overrides) -> ContextRecord:
    fields = {
        "timestamp": 1_700_000_000.0,
        "hour_of_day": 14,
        "protocol": "TCP",
        "source_ip": "10.0.0.5",
        "destination_ip": "93.184.216.34",
        "direction": "OUTGOING",
        "communication_type": "INTERNET",
        "packet_size": 1400,
        "application_name": "chrome.exe",
        "process_id": 4242,
        "user_status": "IDLE",
        "idle_seconds": 320.0,
    }
    fields.update(overrides)
    return ContextRecord(**fields)


def _result(triggered: bool = True, **overrides) -> RuleResult:
    fields = {
        "rule_name": "idle_large_transfer",
        "triggered": triggered,
        "severity": "MEDIUM",
        "reason": "150000000 bytes transferred while idle for 320s.",
        "context": _context(),
    }
    fields.update(overrides)
    return RuleResult(**fields)


class TestBaselineRoundTrip:
    def test_welford_state_survives_a_save_load_cycle_losslessly(
        self, tmp_path
    ) -> None:
        """
        The claim the whole persistence feature rests on: because
        HourBucket uses Welford's algorithm, (count, mean, m2) is
        sufficient to RESUME the observation stream. Restoring mid-stream
        and continuing must produce the same statistics as a run that was
        never interrupted - otherwise a persisted baseline would slowly
        drift away from the truth with every restart.
        """
        values = [(i % 37) * 13.5 + 2.0 for i in range(200)]
        split = 120

        uninterrupted = BaselineTracker()
        for value in values:
            uninterrupted.update("packet_size", 14, value)

        before_restart = BaselineTracker()
        for value in values[:split]:
            before_restart.update("packet_size", 14, value)

        db_path = tmp_path / "baseline.db"
        assert BaselineStore(db_path).save_baseline(before_restart.snapshot())

        after_restart = BaselineTracker()
        after_restart.restore(BaselineStore(db_path).load_baseline())
        for value in values[split:]:
            after_restart.update("packet_size", 14, value)

        expected = uninterrupted.get_bucket("packet_size", 14)
        actual = after_restart.get_bucket("packet_size", 14)

        assert actual.count == expected.count
        assert actual.mean == pytest.approx(expected.mean, rel=1e-12)
        assert actual.std_dev == pytest.approx(expected.std_dev, rel=1e-12)

    def test_multiple_metrics_and_hours_round_trip(self, tmp_path) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", 9, 500.0)
        tracker.update("packet_size", 9, 700.0)
        tracker.update("packet_size", 20, 1200.0)
        tracker.update("idle_transfer_bytes", 20, 99_000.0)
        tracker.update("connection_rate:chrome.exe", 3, 4.5)

        db_path = tmp_path / "baseline.db"
        assert BaselineStore(db_path).save_baseline(tracker.snapshot())
        loaded = BaselineStore(db_path).load_baseline()

        assert set(loaded) == {
            "packet_size",
            "idle_transfer_bytes",
            "connection_rate:chrome.exe",
        }
        assert loaded["packet_size"][9][0] == 2
        assert loaded["packet_size"][9][1] == pytest.approx(600.0)
        assert loaded["packet_size"][20][0] == 1
        assert loaded["idle_transfer_bytes"][20][1] == pytest.approx(99_000.0)
        assert loaded["connection_rate:chrome.exe"][3][1] == pytest.approx(4.5)

    def test_repeated_saves_do_not_inflate_observation_counts(
        self, tmp_path
    ) -> None:
        """
        Guards the one bug this design is most exposed to. snapshot()
        always returns the FULL current state, including everything
        loaded at startup - so the UPSERT has to overwrite each bucket's
        row, never add to it. An accumulating UPSERT would look fine for
        one save and then inflate the baseline on every 30-second
        checkpoint, quietly destroying the learned variance.
        """
        tracker = BaselineTracker()
        for value in [100.0, 110.0, 120.0]:
            tracker.update("packet_size", 12, value)

        store = BaselineStore(tmp_path / "baseline.db")
        snapshot = tracker.snapshot()
        for _ in range(5):
            assert store.save_baseline(snapshot)

        loaded = store.load_baseline()
        assert loaded["packet_size"][12][0] == 3
        assert loaded["packet_size"][12][1] == pytest.approx(110.0)

    def test_reloading_then_resaving_is_stable(self, tmp_path) -> None:
        """A load -> restore -> save cycle with no new observations must
        leave the stored state byte-for-byte equivalent."""
        tracker = BaselineTracker()
        for value in [10.0, 20.0, 30.0, 40.0]:
            tracker.update("packet_size", 7, value)

        db_path = tmp_path / "baseline.db"
        BaselineStore(db_path).save_baseline(tracker.snapshot())

        first_load = BaselineStore(db_path).load_baseline()
        round_tripped = BaselineTracker()
        round_tripped.restore(first_load)
        BaselineStore(db_path).save_baseline(round_tripped.snapshot())

        assert BaselineStore(db_path).load_baseline() == first_load

    def test_empty_snapshot_saves_without_error(self, tmp_path) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        assert store.save_baseline({}) is True
        assert store.load_baseline() == {}


class TestBaselineLoadEdgeCases:
    def test_missing_database_loads_as_cold_start(self, tmp_path) -> None:
        store = BaselineStore(tmp_path / "does_not_exist.db")
        assert store.load_baseline() == {}
        assert store.available is True  # nothing failed; there's just no data

    def test_corrupt_database_degrades_instead_of_raising(self, tmp_path) -> None:
        """
        A garbage file where the database should be must not take down a
        capture. The honest outcome is an empty baseline plus a logged
        warning - never an exception out of load_baseline().
        """
        db_path = tmp_path / "baseline.db"
        db_path.write_bytes(b"this is definitely not a sqlite database" * 20)

        store = BaselineStore(db_path)
        assert store.load_baseline() == {}
        assert store.available is False

    def test_schema_version_mismatch_is_ignored(self, tmp_path) -> None:
        db_path = tmp_path / "baseline.db"
        tracker = BaselineTracker()
        tracker.update("packet_size", 11, 900.0)
        BaselineStore(db_path).save_baseline(tracker.snapshot())

        # Simulate a database written by an incompatible future build.
        connection = sqlite3.connect(db_path)
        with connection:
            connection.execute(
                "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                (str(BASELINE_SCHEMA_VERSION + 1),),
            )
        connection.close()

        assert BaselineStore(db_path).load_baseline() == {}

    def test_unusable_database_location_degrades(self, tmp_path) -> None:
        """
        A path whose parent is a regular file can never be created. This
        stands in for the whole family of "the filesystem said no"
        failures (read-only volume, missing drive, permissions) in a way
        that behaves identically on Windows and POSIX.
        """
        blocker = tmp_path / "not_a_directory"
        blocker.write_text("", encoding="utf-8")

        store = BaselineStore(blocker / "baseline.db")
        tracker = BaselineTracker()
        tracker.update("packet_size", 5, 100.0)

        assert store.save_baseline(tracker.snapshot()) is False
        assert store.available is False
        # Once unavailable, later calls short-circuit rather than retrying.
        assert store.save_baseline(tracker.snapshot()) is False
        assert store.record_alert(_result()) is False

    def test_negative_state_in_database_is_rejected_on_restore(
        self, tmp_path
    ) -> None:
        """
        Hand-edited or otherwise impossible state (a negative m2 can't
        come from a real observation stream) must be caught loudly at the
        restore boundary rather than producing a sqrt-domain error deep
        inside a rule evaluation later.
        """
        db_path = tmp_path / "baseline.db"
        tracker = BaselineTracker()
        tracker.update("packet_size", 8, 100.0)
        BaselineStore(db_path).save_baseline(tracker.snapshot())

        connection = sqlite3.connect(db_path)
        with connection:
            connection.execute("UPDATE baseline_buckets SET m2 = -5.0")
        connection.close()

        loaded = BaselineStore(db_path).load_baseline()
        with pytest.raises(ValueError):
            BaselineTracker().restore(loaded)


class TestResetBaseline:
    def test_reset_clears_buckets_but_preserves_alert_history(
        self, tmp_path
    ) -> None:
        """
        Alert history records things that actually happened. Retraining
        the baseline is not a reason to destroy that evidence.
        """
        store = BaselineStore(tmp_path / "baseline.db")
        tracker = BaselineTracker()
        tracker.update("packet_size", 15, 800.0)
        store.save_baseline(tracker.snapshot())
        store.record_alert(_result(), session_id="session-1")

        assert store.reset_baseline() is True
        assert store.load_baseline() == {}
        assert store.alert_count() == 1

    def test_reset_on_a_fresh_database_succeeds(self, tmp_path) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        assert store.reset_baseline() is True


class TestAlertHistory:
    def test_recorded_alert_round_trips_with_full_context(self, tmp_path) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        result = _result()

        assert store.record_alert(result, session_id="session-abc") is True

        alerts = store.recent_alerts()
        assert len(alerts) == 1
        alert = alerts[0]

        assert alert["session_id"] == "session-abc"
        assert alert["rule_name"] == "idle_large_transfer"
        assert alert["severity"] == "MEDIUM"
        # The reason string is the whole point of the "explainable rules"
        # design - it must survive persistence verbatim.
        assert alert["reason"] == result.reason
        assert alert["application_name"] == "chrome.exe"
        assert alert["process_id"] == 4242
        assert alert["source_ip"] == "10.0.0.5"
        assert alert["destination_ip"] == "93.184.216.34"
        assert alert["protocol"] == "TCP"
        assert alert["application_protocol"] is None
        assert alert["communication_type"] == "INTERNET"
        assert alert["user_status"] == "IDLE"
        assert alert["idle_seconds"] == pytest.approx(320.0)
        assert alert["packet_size"] == 1400
        assert alert["hour_of_day"] == 14
        assert alert["triggered_at_epoch"] == pytest.approx(1_700_000_000.0)
        assert alert["triggered_at"].startswith("2023-")

    def test_dns_alert_persists_application_protocol_separately_from_transport(
        self, tmp_path
    ) -> None:
        """Regression test for P2 Bug #3: a DNS alert must persist
        both the transport protocol (UDP/TCP) and the "DNS"
        application-layer label, not collapse them into one field."""
        store = BaselineStore(tmp_path / "baseline.db")
        result = _result(
            context=_context(protocol="UDP", application_protocol="DNS")
        )
        store.record_alert(result, session_id="session-dns")
        alert = store.recent_alerts()[0]
        assert alert["protocol"] == "UDP"
        assert alert["application_protocol"] == "DNS"

    def test_non_triggered_results_are_not_recorded(self, tmp_path) -> None:
        """Callers shouldn't have to filter; the store ignores non-alerts."""
        store = BaselineStore(tmp_path / "baseline.db")
        assert store.record_alert(_result(triggered=False)) is False
        assert store.alert_count() == 0

    def test_alerts_returned_newest_first_and_respect_limit(
        self, tmp_path
    ) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        for index in range(5):
            store.record_alert(
                _result(
                    rule_name=f"rule_{index}",
                    context=_context(timestamp=1_700_000_000.0 + index),
                )
            )

        assert store.alert_count() == 5

        recent = store.recent_alerts(limit=2)
        assert [row["rule_name"] for row in recent] == ["rule_4", "rule_3"]

    def test_alerts_persist_across_store_instances(self, tmp_path) -> None:
        db_path = tmp_path / "baseline.db"
        BaselineStore(db_path).record_alert(_result(), session_id="s1")
        assert BaselineStore(db_path).alert_count() == 1

    def test_alert_count_and_recent_alerts_on_missing_database(
        self, tmp_path
    ) -> None:
        store = BaselineStore(tmp_path / "absent.db")
        assert store.alert_count() == 0
        assert store.recent_alerts() == []

    def test_alerts_from_different_sessions_are_distinguishable(
        self, tmp_path
    ) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        store.record_alert(_result(), session_id="session-1")
        store.record_alert(
            _result(context=_context(timestamp=1_700_000_100.0)),
            session_id="session-2",
        )

        sessions = {row["session_id"] for row in store.recent_alerts()}
        assert sessions == {"session-1", "session-2"}


class TestStoreConfiguration:
    def test_database_uses_wal_mode(self, tmp_path) -> None:
        """
        WAL is what allows the native UI to read the baseline while
        a capture is still writing to it.
        """
        db_path = tmp_path / "baseline.db"
        BaselineStore(db_path).save_baseline({})

        connection = sqlite3.connect(db_path)
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        connection.close()
        assert mode.lower() == "wal"

    def test_parent_directory_is_created_on_demand(self, tmp_path) -> None:
        store = BaselineStore(tmp_path / "nested" / "deeper" / "baseline.db")
        assert store.save_baseline({}) is True
        assert store.db_path.exists()

    def test_schema_version_is_recorded(self, tmp_path) -> None:
        db_path = tmp_path / "baseline.db"
        BaselineStore(db_path).save_baseline({})

        connection = sqlite3.connect(db_path)
        value = connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        connection.close()
        assert int(value) == BASELINE_SCHEMA_VERSION

    def test_concurrent_read_while_writing_is_possible(self, tmp_path) -> None:
        """
        A second connection must be able to read the baseline while a
        store instance is actively using the same database - the
        behavior the native UI will depend on.
        """
        db_path = tmp_path / "baseline.db"
        store = BaselineStore(db_path)
        tracker = BaselineTracker()
        tracker.update("packet_size", 6, 300.0)
        store.save_baseline(tracker.snapshot())

        reader = sqlite3.connect(db_path)
        try:
            rows = reader.execute(
                "SELECT metric_name, observation_count FROM baseline_buckets"
            ).fetchall()
        finally:
            reader.close()

        assert rows == [("packet_size", 1)]

        tracker.update("packet_size", 6, 500.0)
        assert store.save_baseline(tracker.snapshot()) is True


class TestEndToEndAcrossRuns:
    def test_baseline_becomes_established_across_simulated_runs(
        self, tmp_path
    ) -> None:
        """
        The user-visible payoff: a rule that reports "not enough data
        yet" during a single short run becomes able to judge traffic once
        observations accumulate over several runs. Each iteration here
        stands in for one `python main.py` invocation.
        """
        db_path = tmp_path / "baseline.db"

        for _ in range(3):
            tracker = BaselineTracker()
            tracker.restore(BaselineStore(db_path).load_baseline())
            for value in [1000.0, 1100.0]:
                tracker.update("packet_size", 21, value)
            BaselineStore(db_path).save_baseline(tracker.snapshot())

        final = BaselineTracker()
        final.restore(BaselineStore(db_path).load_baseline())
        bucket = final.get_bucket("packet_size", 21)

        assert bucket.count == 6
        assert bucket.is_established() is True
        assert final.summary().established_bucket_count == 1
        assert final.summary().total_observations == 6

    def test_reset_returns_the_baseline_to_cold_start(self, tmp_path) -> None:
        db_path = tmp_path / "baseline.db"
        tracker = BaselineTracker()
        for value in range(10):
            tracker.update("packet_size", 21, float(value))
        BaselineStore(db_path).save_baseline(tracker.snapshot())

        BaselineStore(db_path).reset_baseline()

        restarted = BaselineTracker()
        restarted.restore(BaselineStore(db_path).load_baseline())
        assert restarted.summary().is_empty is True
        assert restarted.get_bucket("packet_size", 21) is None


class TestTimestampHandling:
    def test_epoch_and_iso_columns_describe_the_same_instant(
        self, tmp_path
    ) -> None:
        store = BaselineStore(tmp_path / "baseline.db")
        now = time.time()
        store.record_alert(_result(context=_context(timestamp=now)))

        alert = store.recent_alerts()[0]
        assert alert["triggered_at_epoch"] == pytest.approx(now)
        # Stored as UTC, so the rendering carries an explicit offset.
        assert "+00:00" in alert["triggered_at"]
