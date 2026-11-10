"""
Unit tests for risk_scoring.store (SQLite persistence).

Every test uses a temporary database via ``tmp_path``; nothing here
touches the project's real ``data/`` directory.
"""

from __future__ import annotations

import time

from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.scorer import RiskEntry, RiskSnapshot
from risk_scoring.store import RiskStore


def _snapshot(generated_at=1000.0) -> RiskSnapshot:
    return RiskSnapshot(
        applications=[
            RiskEntry(name="chrome.exe", kind="application", score=6.0, events=3),
            RiskEntry(name="spotify.exe", kind="application", score=2.0, events=1),
        ],
        destinations=[
            RiskEntry(name="1.1.1.1", kind="destination", score=4.0, events=2),
        ],
        generated_at=generated_at,
    )


def _alert(**overrides) -> CorrelatedAlert:
    fields = {
        "alert_id": "abc123",
        "started_at": 1000.0,
        "ended_at": 1002.0,
        "application_name": "chrome.exe",
        "destination_ip": "93.184.216.34",
        "rule_names": ("connection_rate_anomaly", "packet_size_anomaly"),
        "signal_count": 2,
        "severity": "MEDIUM",
        "score": 4.0,
        "confidence": 0.65,
        "reason": "2 suspicious signal(s) for chrome.exe -> 93.184.216.34.",
    }
    fields.update(overrides)
    return CorrelatedAlert(**fields)


class TestRiskScorePersistence:
    def test_save_and_read_latest_risk_scores(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        assert store.save_risk_snapshot(_snapshot()) is True
        rows = store.latest_risk_scores()
        assert len(rows) == 3
        # Ordered by score descending.
        assert rows[0]["name"] == "chrome.exe"
        assert rows[0]["score"] == 6.0
        assert rows[0]["events"] == 3

    def test_latest_risk_scores_kind_filter(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        store.save_risk_snapshot(_snapshot())
        apps = store.latest_risk_scores(kind="application")
        dests = store.latest_risk_scores(kind="destination")
        assert [r["name"] for r in apps] == ["chrome.exe", "spotify.exe"]
        assert [r["name"] for r in dests] == ["1.1.1.1"]

    def test_snapshot_upserts_without_duplicates(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        store.save_risk_snapshot(_snapshot(generated_at=1000.0))
        store.save_risk_snapshot(_snapshot(generated_at=2000.0))
        rows = store.latest_risk_scores()
        # Same three entities, updated not duplicated.
        assert len(rows) == 3

    def test_risk_history_newest_first_with_limit(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        store.save_risk_snapshot(_snapshot(generated_at=1000.0))
        store.save_risk_snapshot(_snapshot(generated_at=2000.0))
        history = store.risk_history("application", "chrome.exe", limit=10)
        assert len(history) == 2
        assert history[0]["recorded_at_epoch"] == 2000.0
        assert history[1]["recorded_at_epoch"] == 1000.0

        limited = store.risk_history("application", "chrome.exe", limit=1)
        assert len(limited) == 1
        assert limited[0]["recorded_at_epoch"] == 2000.0

    def test_reads_on_missing_db_return_empty(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "does_not_exist.db")
        assert store.latest_risk_scores() == []
        assert store.risk_history("application", "x") == []
        assert store.recent_correlated_alerts() == []
        assert store.correlated_alert_count() == 0


class TestCorrelatedAlertPersistence:
    def test_save_and_read_correlated_alert(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        assert store.save_correlated_alert(_alert()) is True
        rows = store.recent_correlated_alerts()
        assert len(rows) == 1
        assert rows[0]["alert_id"] == "abc123"
        # rule_names stored as JSON text, read back as a list.
        assert rows[0]["rule_names"] == ["connection_rate_anomaly", "packet_size_anomaly"]
        assert rows[0]["severity"] == "MEDIUM"
        assert rows[0]["confidence"] == 0.65
        assert store.correlated_alert_count() == 1

    def test_recent_ordered_newest_first(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        store.save_correlated_alert(_alert(alert_id="old", ended_at=1000.0))
        store.save_correlated_alert(_alert(alert_id="new", ended_at=2000.0))
        rows = store.recent_correlated_alerts(limit=10)
        assert [r["alert_id"] for r in rows] == ["new", "old"]

    def test_limit_respected(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        store.save_correlated_alert(_alert(alert_id="a", ended_at=1000.0))
        store.save_correlated_alert(_alert(alert_id="b", ended_at=2000.0))
        assert len(store.recent_correlated_alerts(limit=1)) == 1


class TestDegradation:
    def test_corrupt_db_degrades_without_raising(self, tmp_path) -> None:
        db = tmp_path / "corrupt.db"
        db.write_bytes(b"this is not a sqlite database at all")
        store = RiskStore(db)
        # First access attempts to open and initialize -> marks unavailable.
        assert store.save_risk_snapshot(_snapshot()) is False
        assert store.available is False
        assert store.latest_risk_scores() == []
        assert store.recent_correlated_alerts() == []

    def test_empty_snapshot_is_a_noop_success(self, tmp_path) -> None:
        store = RiskStore(tmp_path / "test.db")
        empty = RiskSnapshot(applications=[], destinations=[], generated_at=time.time())
        assert store.save_risk_snapshot(empty) is True
        assert store.latest_risk_scores() == []
