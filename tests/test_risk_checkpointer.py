"""
Unit tests for risk_scoring.checkpointer (periodic risk snapshot saves).
"""

from __future__ import annotations

import time

from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from risk_scoring.checkpointer import RiskCheckpointer
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore


def _result() -> RuleResult:
    context = ContextRecord(
        timestamp=0.0,
        hour_of_day=20,
        protocol="TCP",
        source_ip="10.0.0.5",
        destination_ip="93.184.216.34",
        direction="OUTGOING",
        communication_type="INTERNET",
        packet_size=1200,
        application_name="chrome.exe",
        process_id=1234,
        user_status="ACTIVE",
        idle_seconds=0.0,
    )
    return RuleResult(
        rule_name="connection_rate_anomaly",
        triggered=True,
        severity="MEDIUM",
        reason="test",
        context=context,
    )


class TestRiskCheckpointer:
    def test_stop_saves_final_snapshot(self, tmp_path) -> None:
        scorer = RiskScorer(half_life=300.0)
        scorer.record(_result())
        store = RiskStore(tmp_path / "test.db")

        checkpointer = RiskCheckpointer(scorer, store, interval_seconds=1.0)
        checkpointer.start()
        time.sleep(0.05)
        saved = checkpointer.stop()

        assert saved is True
        rows = store.latest_risk_scores(kind="application")
        assert [r["name"] for r in rows] == ["chrome.exe"]

    def test_stop_is_idempotent(self, tmp_path) -> None:
        scorer = RiskScorer(half_life=300.0)
        store = RiskStore(tmp_path / "test.db")
        checkpointer = RiskCheckpointer(scorer, store, interval_seconds=1.0)
        checkpointer.start()
        checkpointer.stop()
        assert checkpointer.is_running() is False
        # Second stop must not raise and still returns a bool.
        assert checkpointer.stop() in (True, False)

    def test_interval_requires_positive_value(self, tmp_path) -> None:
        scorer = RiskScorer()
        store = RiskStore(tmp_path / "test.db")
        import pytest

        with pytest.raises(ValueError):
            RiskCheckpointer(scorer, store, interval_seconds=0.0)

    def test_periodic_save_runs_multiple_times(self, tmp_path) -> None:
        scorer = RiskScorer(half_life=300.0)
        scorer.record(_result())
        store = RiskStore(tmp_path / "test.db")
        checkpointer = RiskCheckpointer(scorer, store, interval_seconds=0.1)
        checkpointer.start()
        time.sleep(0.35)  # allow ~3 intervals to elapse
        checkpointer.stop()
        # Multiple snapshots of the same entity accumulate in history.
        history = store.risk_history("application", "chrome.exe", limit=100)
        assert len(history) >= 2
        assert checkpointer.saves_completed >= 2
