"""
Unit tests for risk_scoring.correlator (alert correlation).
"""

from __future__ import annotations

import pytest

from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from risk_scoring.correlator import AlertCorrelator


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


def _result(
    rule="connection_rate_anomaly",
    severity="MEDIUM",
    app="chrome.exe",
    dest="93.184.216.34",
    direction="OUTGOING",
    source="10.0.0.5",
):
    return RuleResult(
        rule_name=rule,
        triggered=True,
        severity=severity,
        reason=f"reason for {rule}",
        context=_context(
            application_name=app,
            destination_ip=dest,
            direction=direction,
            source_ip=source,
        ),
    )


class TestQualification:
    def test_non_triggered_result_returns_none(self) -> None:
        correlator = AlertCorrelator()
        result = _result()
        result = RuleResult(
            rule_name=result.rule_name,
            triggered=False,
            severity=result.severity,
            reason=result.reason,
            context=result.context,
        )
        assert correlator.observe(result, now=0.0) is None

    def test_single_medium_does_not_emit(self) -> None:
        correlator = AlertCorrelator()
        assert correlator.observe(_result(severity="MEDIUM"), now=0.0) is None
        assert correlator.open_count == 1

    def test_single_high_emits_immediately(self) -> None:
        correlator = AlertCorrelator()
        alert = correlator.observe(_result(severity="HIGH"), now=0.0)
        assert alert is not None
        assert alert.signal_count == 1
        assert alert.severity == "HIGH"
        assert alert.rule_names == ("connection_rate_anomaly",)

    def test_two_distinct_rules_within_window_emit(self) -> None:
        correlator = AlertCorrelator(window_seconds=60.0)
        assert correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0) is None
        alert = correlator.observe(_result(rule="packet_size_anomaly"), now=1.0)
        assert alert is not None
        assert alert.signal_count == 2
        assert alert.rule_names == ("connection_rate_anomaly", "packet_size_anomaly")
        assert alert.confidence >= 0.5
        assert alert.application_name == "chrome.exe"
        assert alert.destination_ip == "93.184.216.34"
        assert correlator.open_count == 0

    def test_three_distinct_rules_raise_confidence(self) -> None:
        # A three-rule incident (min_signals=3 so it accumulates before
        # emitting) must carry higher confidence than a two-rule one.
        correlator = AlertCorrelator(min_signals=3, window_seconds=60.0)
        correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        correlator.observe(_result(rule="packet_size_anomaly"), now=1.0)
        alert = correlator.observe(_result(rule="idle_large_transfer"), now=2.0)
        assert alert is not None
        assert alert.signal_count == 3
        assert alert.confidence == pytest.approx(0.80)

        two_rule = AlertCorrelator(min_signals=2, window_seconds=60.0)
        two_rule.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        two_alert = two_rule.observe(_result(rule="packet_size_anomaly"), now=1.0)
        assert two_alert is not None
        assert two_alert.confidence == pytest.approx(0.65)
        assert alert.confidence > two_alert.confidence

    def test_duplicate_same_rule_does_not_count_as_distinct(self) -> None:
        correlator = AlertCorrelator(min_signals=2, window_seconds=60.0)
        assert correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0) is None
        # Same rule again: still only 1 distinct rule -> no emit.
        assert correlator.observe(_result(rule="connection_rate_anomaly"), now=1.0) is None
        assert correlator.open_count == 1


class TestWindowExpiry:
    def test_window_expiry_closes_group_and_starts_new(self) -> None:
        correlator = AlertCorrelator(window_seconds=5.0)
        assert correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0) is None
        # Gap larger than the window -> old group closes (not qualifying:
        # one distinct rule, MEDIUM), new group starts.
        assert correlator.observe(_result(rule="packet_size_anomaly"), now=100.0) is None
        assert correlator.open_count == 1

    def test_window_expiry_drops_weak_group(self) -> None:
        correlator = AlertCorrelator(window_seconds=5.0)
        correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        # The MEDIUM-only group at now=0 was never qualifying, and the gap
        # past the window closes it without emitting - the signal at 100
        # starts a fresh window instead.
        assert correlator.observe(_result(rule="packet_size_anomaly"), now=100.0) is None
        assert correlator.open_count == 1
        # A second distinct signal inside the new window qualifies.
        alert = correlator.observe(_result(rule="idle_large_transfer"), now=101.0)
        assert alert is not None
        assert alert.signal_count == 2
        assert alert.rule_names == ("packet_size_anomaly", "idle_large_transfer")


class TestFlush:
    def test_flush_clears_open_windows_and_drops_weak_groups(self) -> None:
        correlator = AlertCorrelator()
        correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        correlator.observe(_result(rule="packet_size_anomaly"), now=1.0)  # emits at 2 rules
        correlator.observe(_result(rule="connection_rate_anomaly"), now=2.0)  # new weak group
        emitted = correlator.flush(now=4.0)
        assert emitted == []
        assert correlator.open_count == 0

    def test_flush_drops_non_qualifying_groups(self) -> None:
        correlator = AlertCorrelator()
        correlator.observe(_result(severity="MEDIUM"), now=0.0)
        assert correlator.flush(now=1.0) == []
        assert correlator.open_count == 0


class TestIsolation:
    def test_different_keys_correlate_independently(self) -> None:
        correlator = AlertCorrelator(window_seconds=60.0)
        correlator.observe(_result(app="chrome.exe", dest="1.1.1.1", rule="connection_rate_anomaly"), now=0.0)
        correlator.observe(_result(app="chrome.exe", dest="2.2.2.2", rule="connection_rate_anomaly"), now=1.0)
        # Each key has only 1 distinct rule so far -> nothing emitted.
        assert correlator.open_count == 2
        alert = correlator.observe(
            _result(app="chrome.exe", dest="1.1.1.1", rule="packet_size_anomaly"), now=2.0
        )
        assert alert is not None
        assert alert.destination_ip == "1.1.1.1"
        assert correlator.open_count == 1  # only the 2.2.2.2 group remains

    def test_inbound_groups_by_remote_source_not_local_destination(self) -> None:
        correlator = AlertCorrelator(window_seconds=60.0)
        correlator.observe(
            _result(
                direction="INCOMING",
                source="1.1.1.1",
                dest="10.0.0.5",
                rule="connection_rate_anomaly",
            ),
            now=0.0,
        )
        correlator.observe(
            _result(
                direction="INCOMING",
                source="2.2.2.2",
                dest="10.0.0.5",
                rule="connection_rate_anomaly",
            ),
            now=1.0,
        )
        assert correlator.open_count == 2
        alert = correlator.observe(
            _result(
                direction="INCOMING",
                source="1.1.1.1",
                dest="10.0.0.5",
                rule="packet_size_anomaly",
            ),
            now=2.0,
        )
        assert alert is not None
        assert alert.destination_ip == "1.1.1.1"

    def test_to_dict_shape(self) -> None:
        correlator = AlertCorrelator(window_seconds=60.0)
        correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        alert = correlator.observe(_result(rule="packet_size_anomaly"), now=1.0)
        data = alert.to_dict()
        assert set(data) == {
            "alert_id",
            "started_at",
            "ended_at",
            "application_name",
            "destination_ip",
            "rule_names",
            "signal_count",
            "severity",
            "score",
            "confidence",
            "reason",
        }
        assert isinstance(data["rule_names"], list)

    def test_reason_is_explanatory(self) -> None:
        correlator = AlertCorrelator(window_seconds=60.0)
        correlator.observe(_result(rule="connection_rate_anomaly"), now=0.0)
        alert = correlator.observe(_result(rule="packet_size_anomaly"), now=1.0)
        assert "chrome.exe" in alert.reason
        assert "connection_rate_anomaly" in alert.reason
        assert "packet_size_anomaly" in alert.reason
