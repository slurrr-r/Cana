"""
Regression tests for risk state RESTORATION across restarts.

P0 review finding: RiskStore persisted risk scores, but RiskScorer had
no way to resume from them, so every restart began empty and the
database was only ever a historical log. These tests lock in the
restore path: value, event count, AND the persisted timestamp (so
time-decay resumes across the restart rather than being reset).
"""

from __future__ import annotations

import sqlite3

import pytest

from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore


def _context(**overrides) -> ContextRecord:
    fields = {
        "timestamp": 0.0,
        "hour_of_day": 20,
        "protocol": "TCP",
        "source_ip": "10.0.0.5",
        "destination_ip": "93.184.216.34",
        "direction": "OUTGOING",
        "communication_type": "INTERNET",
        "packet_size": 1200,
        "application_name": "chrome.exe",
        "process_id": 1234,
        "user_status": "ACTIVE",
        "idle_seconds": 0.0,
    }
    fields.update(overrides)
    return ContextRecord(**fields)


def _result(application="chrome.exe", destination="93.184.216.34"):
    return RuleResult(
        rule_name="connection_rate_anomaly",
        triggered=True,
        severity="MEDIUM",
        reason="test reason",
        context=_context(application_name=application, destination_ip=destination),
    )


def _record_and_persist(tmp_path, t0: float, half_life: float = 300.0):
    """Record two MEDIUM alerts, snapshot at t0, persist to a temp DB."""
    store = RiskStore(tmp_path / "risk.db")
    scorer = RiskScorer(half_life=half_life)
    scorer.record(_result(), now=t0)
    scorer.record(_result(), now=t0)
    assert store.save_risk_snapshot(scorer.snapshot(now=t0)) is True
    return store


class TestRiskRestoreRoundTrip:
    def test_score_events_and_destinations_survive_restart(self, tmp_path) -> None:
        t0 = 1_700_000_000.0
        store = _record_and_persist(tmp_path, t0)

        # A brand-new scorer, exactly as a restarted process would have.
        scorer = RiskScorer(half_life=300.0)
        rows = store.load_risk_state()
        restored = scorer.restore(rows, now=t0)

        # chrome.exe (application) + the destination IP.
        assert restored == 2
        assert scorer.application_score("chrome.exe", now=t0) == pytest.approx(4.0)
        assert scorer.events_for("application", "chrome.exe") == 2
        assert scorer.destination_score("93.184.216.34", now=t0) == pytest.approx(4.0)

    def test_restored_score_keeps_decaying_from_persisted_time(self, tmp_path) -> None:
        t0 = 1_700_000_000.0
        half_life = 600.0
        store = _record_and_persist(tmp_path, t0, half_life=half_life)

        scorer = RiskScorer(half_life=half_life)
        scorer.restore(store.load_risk_state(), now=t0)

        # Immediately after restart the value is exactly what was saved.
        assert scorer.application_score("chrome.exe", now=t0) == pytest.approx(4.0)
        # An hour later it has decayed from the PERSISTED timestamp
        # (half_life=600 -> 6 halvings in 1h).
        later = t0 + 3600.0
        expected = 4.0 * (0.5 ** (3600.0 / half_life))
        assert scorer.application_score("chrome.exe", now=later) == pytest.approx(
            expected
        )

    def test_restored_scorer_continues_accumulating(self, tmp_path) -> None:
        t0 = 1_700_000_000.0
        store = _record_and_persist(tmp_path, t0)

        scorer = RiskScorer(half_life=300.0)
        scorer.restore(store.load_risk_state(), now=t0)
        scorer.record(_result(), now=t0)

        # 4.0 restored + 2.0 new = 6.0.
        assert scorer.application_score("chrome.exe", now=t0) == pytest.approx(6.0)
        assert scorer.events_for("application", "chrome.exe") == 3

    def test_no_persisted_state_restores_nothing(self) -> None:
        scorer = RiskScorer()
        assert scorer.restore([]) == 0
        assert scorer.application_score("chrome.exe") == 0.0

    def test_rows_with_unknown_kind_or_no_events_are_skipped(self, tmp_path) -> None:
        scorer = RiskScorer()
        rows = [
            {"kind": "banana", "name": "x", "score": 9.0, "events": 3},
            {"kind": "application", "name": "y", "score": 5.0, "events": 0},
            {"kind": "application", "name": " ", "score": 5.0, "events": 2},
        ]
        assert scorer.restore(rows, now=0.0) == 0


class TestRiskRestoreLegacySchema:
    def _create_legacy_db(self, path) -> None:
        """A database written before updated_at_epoch existed."""
        connection = sqlite3.connect(path)
        connection.execute(
            "CREATE TABLE risk_scores ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " kind TEXT NOT NULL, name TEXT NOT NULL, score REAL NOT NULL,"
            " events INTEGER NOT NULL, updated_at TEXT NOT NULL,"
            " UNIQUE (kind, name))"
        )
        connection.execute(
            "INSERT INTO risk_scores (kind, name, score, events, updated_at) "
            "VALUES ('application', 'chrome.exe', 4.0, 2, "
            " '2026-08-31T20:00:00.000000+00:00')"
        )
        connection.commit()
        connection.close()

    def test_legacy_db_is_migrated_and_restorable(self, tmp_path) -> None:
        db_path = tmp_path / "legacy.db"
        self._create_legacy_db(db_path)

        store = RiskStore(db_path)
        rows = store.latest_risk_scores()
        assert len(rows) == 1
        # Migration succeeded: the store still works and exposes epoch.
        assert store.available is True

        state = store.load_risk_state()
        scorer = RiskScorer(half_life=300.0)
        restored = scorer.restore(state, now=1_700_000_000.0)
        assert restored == 1
        # last_update derived from the ISO string -> score decays.
        assert scorer.events_for("application", "chrome.exe") == 2

    def test_load_risk_state_on_missing_db_is_empty(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "missing.db")
        assert store.load_risk_state() == []
