"""
Unit tests for risk_scoring.scorer (time-decayed risk scoring).
"""

from __future__ import annotations

import pytest

from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from risk_scoring.scorer import RiskScorer


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


def _result(severity="MEDIUM", triggered=True, application="chrome.exe", destination="93.184.216.34"):
    return RuleResult(
        rule_name="connection_rate_anomaly",
        triggered=triggered,
        severity=severity,
        reason="test reason",
        context=_context(application_name=application, destination_ip=destination),
    )


class TestRecording:
    def test_non_triggered_results_are_ignored(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(triggered=False), now=100.0)
        assert scorer.application_score("chrome.exe", now=100.0) == 0.0
        assert scorer.events_for("application", "chrome.exe", now=100.0) == 0

    def test_triggered_result_accumulates_weight(self) -> None:
        scorer = RiskScorer()
        # MEDIUM weight is 2.0
        scorer.record(_result(severity="MEDIUM"), now=100.0)
        assert scorer.application_score("chrome.exe", now=100.0) == pytest.approx(2.0)
        assert scorer.destination_score("93.184.216.34", now=100.0) == pytest.approx(2.0)
        assert scorer.events_for("application", "chrome.exe", now=100.0) == 1

    def test_high_weights_more_than_low(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(severity="LOW"), now=0.0)
        scorer.record(_result(severity="HIGH"), now=0.0)
        # 1.0 + 4.0 = 5.0 (both recorded at the same instant, no decay)
        assert scorer.application_score("chrome.exe", now=0.0) == pytest.approx(5.0)

    def test_repeated_events_increment_and_stack(self) -> None:
        scorer = RiskScorer()
        for _ in range(3):
            scorer.record(_result(), now=10.0)
        assert scorer.events_for("application", "chrome.exe", now=10.0) == 3
        assert scorer.application_score("chrome.exe", now=10.0) == pytest.approx(6.0)

    def test_entities_without_destination_only_score_application(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(destination=None), now=0.0)
        assert scorer.application_score("chrome.exe", now=0.0) == pytest.approx(2.0)
        assert scorer.events_for("destination", "93.184.216.34", now=0.0) == 0


class TestDecay:
    def test_score_halves_after_one_half_life(self) -> None:
        scorer = RiskScorer(half_life=1.0)
        scorer.record(_result(), now=0.0)  # +2.0 at t=0
        assert scorer.application_score("chrome.exe", now=1.0) == pytest.approx(1.0)

    def test_score_quarter_after_two_half_lives(self) -> None:
        scorer = RiskScorer(half_life=1.0)
        scorer.record(_result(), now=0.0)
        assert scorer.application_score("chrome.exe", now=2.0) == pytest.approx(0.5)

    def test_score_never_goes_negative_and_clamps_to_zero(self) -> None:
        scorer = RiskScorer(half_life=1.0)
        scorer.record(_result(), now=0.0)
        # After ~60 half-lives the value is far below the noise floor.
        assert scorer.application_score("chrome.exe", now=60.0) == 0.0

    def test_decay_is_idempotent_for_same_timestamp(self) -> None:
        scorer = RiskScorer(half_life=1.0)
        scorer.record(_result(), now=0.0)
        first = scorer.application_score("chrome.exe", now=1.0)
        second = scorer.application_score("chrome.exe", now=1.0)
        assert first == pytest.approx(second)

    def test_new_records_after_decay_are_relative_to_decayed_value(self) -> None:
        scorer = RiskScorer(half_life=1.0)
        scorer.record(_result(), now=0.0)  # 2.0 at t=0
        scorer.record(_result(), now=1.0)  # 2.0*0.5 + 2.0 = 3.0 at t=1
        assert scorer.application_score("chrome.exe", now=1.0) == pytest.approx(3.0)


class TestLeaderboard:
    def test_sorted_descending_with_stable_ties(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(application="zeta.exe"), now=0.0)
        scorer.record(_result(application="alpha.exe"), now=0.0)
        scorer.record(_result(application="alpha.exe"), now=0.0)
        scorer.record(_result(application="beta.exe"), now=0.0)
        scores = [(e.name, e.score) for e in scorer.leaderboard(kind="application", now=0.0)]
        assert scores == [
            ("alpha.exe", 4.0),
            ("beta.exe", 2.0),
            ("zeta.exe", 2.0),
        ]

    def test_top_n_limits_results(self) -> None:
        scorer = RiskScorer()
        for name in ("a.exe", "b.exe", "c.exe"):
            scorer.record(_result(application=name), now=0.0)
        board = scorer.leaderboard(kind="application", top_n=2, now=0.0)
        assert len(board) == 2

    def test_top_n_none_returns_everything(self) -> None:
        scorer = RiskScorer()
        for name in ("a.exe", "b.exe", "c.exe"):
            scorer.record(_result(application=name), now=0.0)
        board = scorer.leaderboard(kind="application", top_n=None, now=0.0)
        assert len(board) == 3

    def test_invalid_kind_raises_value_error(self) -> None:
        scorer = RiskScorer()
        with pytest.raises(ValueError):
            scorer.leaderboard(kind="bogus", now=0.0)

    def test_empty_leaderboard_is_empty_list(self) -> None:
        scorer = RiskScorer()
        assert scorer.leaderboard(kind="application", now=0.0) == []
        assert scorer.leaderboard(kind="destination", now=0.0) == []

    def test_destinations_are_separate_dimension(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(destination="1.1.1.1"), now=0.0)
        apps = scorer.leaderboard(kind="application", now=0.0)
        dests = scorer.leaderboard(kind="destination", now=0.0)
        assert [e.name for e in apps] == ["chrome.exe"]
        assert [e.name for e in dests] == ["1.1.1.1"]


class TestSnapshot:
    def test_snapshot_includes_both_kinds_and_timestamp(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(), now=42.0)
        snap = scorer.snapshot(now=42.0)
        assert snap.generated_at == 42.0
        assert [e.name for e in snap.applications] == ["chrome.exe"]
        assert [e.name for e in snap.destinations] == ["93.184.216.34"]

    def test_snapshot_to_dict_shape(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(), now=0.0)
        data = scorer.snapshot(now=0.0).to_dict()
        assert set(data) == {"applications", "destinations", "generated_at"}
        assert data["applications"][0]["name"] == "chrome.exe"
        assert data["applications"][0]["score"] == 2.0

    def test_clear_resets_all_state(self) -> None:
        scorer = RiskScorer()
        scorer.record(_result(), now=0.0)
        scorer.clear()
        assert scorer.application_score("chrome.exe", now=0.0) == 0.0
        assert scorer.leaderboard(kind="application", now=0.0) == []


class TestEviction:
    def test_max_entities_evicts_lowest_score(self) -> None:
        scorer = RiskScorer(max_entities=2)
        scorer.record(_result(application="a.exe", destination=None), now=0.0)
        scorer.record(_result(application="a.exe", destination=None), now=0.0)
        scorer.record(_result(application="b.exe", destination=None), now=0.0)
        scorer.record(_result(application="c.exe", destination=None), now=0.0)
        names = {e.name for e in scorer.leaderboard(kind="application", top_n=None, now=0.0)}
        assert len(names) == 2
        assert "c.exe" in names
        assert "a.exe" in names

    def test_zero_max_entities_rejected(self) -> None:
        with pytest.raises(ValueError):
            RiskScorer(max_entities=0)
