"""
Unit tests for risk_scoring.utils (console formatting).
"""

from __future__ import annotations

from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.scorer import RiskEntry, RiskSnapshot
from risk_scoring.utils import (
    format_correlated_alert,
    format_risk_entry,
    format_risk_summary,
)


def _snapshot() -> RiskSnapshot:
    return RiskSnapshot(
        applications=[
            RiskEntry(name="chrome.exe", kind="application", score=12.4, events=7),
            RiskEntry(name="spotify.exe", kind="application", score=0.5, events=1),
        ],
        destinations=[RiskEntry(name="1.1.1.1", kind="destination", score=4.0, events=2)],
        generated_at=0.0,
    )


def _alert() -> CorrelatedAlert:
    return CorrelatedAlert(
        alert_id="abc",
        started_at=0.0,
        ended_at=10.0,
        application_name="chrome.exe",
        destination_ip="93.184.216.34",
        rule_names=("connection_rate_anomaly", "packet_size_anomaly"),
        signal_count=2,
        severity="HIGH",
        score=6.0,
        confidence=0.85,
        reason="2 suspicious signal(s) for chrome.exe -> 93.184.216.34.",
    )


class TestFormatRiskEntry:
    def test_includes_name_score_and_events(self) -> None:
        text = format_risk_entry(RiskEntry(name="chrome.exe", kind="application", score=12.4, events=7))
        assert "chrome.exe" in text
        assert "12.4" in text
        assert "7 event(s)" in text


class TestFormatRiskSummary:
    def test_shows_both_leaderboards(self) -> None:
        text = format_risk_summary(_snapshot(), top_n=5)
        assert "Top applications by risk" in text
        assert "Top remote peers by risk" in text
        assert "chrome.exe" in text
        assert "1.1.1.1" in text

    def test_empty_snapshot_reports_nothing_recorded(self) -> None:
        empty = RiskSnapshot(applications=[], destinations=[], generated_at=0.0)
        text = format_risk_summary(empty, top_n=5)
        assert "(no risk recorded yet)" in text

    def test_top_n_limits_rows(self) -> None:
        text = format_risk_summary(_snapshot(), top_n=1)
        assert "chrome.exe" in text
        assert "spotify.exe" not in text


class TestFormatCorrelatedAlert:
    def test_includes_severity_signals_and_confidence(self) -> None:
        text = format_correlated_alert(_alert())
        assert "[CORRELATED - HIGH]" in text
        assert "connection_rate_anomaly, packet_size_anomaly" in text
        assert "0.85" in text
        assert "chrome.exe" in text
        assert "93.184.216.34" in text
