"""Unit tests for anomaly_detection.utils."""

from __future__ import annotations

from anomaly_detection.context import ContextRecord
from anomaly_detection.rules import RuleResult
from anomaly_detection.utils import format_alert


def _result(**overrides) -> RuleResult:
    context = ContextRecord(
        timestamp=0.0,
        hour_of_day=20,
        protocol="TCP",
        source_ip="10.0.0.5",
        destination_ip="93.184.216.34",
        direction="OUTGOING",
        communication_type="INTERNET",
        packet_size=1500,
        application_name="chrome.exe",
        process_id=1234,
        user_status="IDLE",
        idle_seconds=320.0,
    )
    base = dict(
        rule_name="idle_large_transfer",
        triggered=True,
        severity="MEDIUM",
        reason="150000000 bytes transferred while idle for 320s.",
        context=context,
    )
    base.update(overrides)
    return RuleResult(**base)


class TestFormatAlert:
    def test_includes_severity_and_reason(self) -> None:
        output = format_alert(_result())
        assert "MEDIUM" in output
        assert "150000000 bytes" in output

    def test_includes_readable_rule_name(self) -> None:
        output = format_alert(_result())
        assert "Large data transfer while idle" in output

    def test_unknown_rule_name_falls_back_to_raw_name(self) -> None:
        output = format_alert(_result(rule_name="some_future_rule"))
        assert "some_future_rule" in output

    def test_includes_application_and_endpoints(self) -> None:
        output = format_alert(_result())
        assert "chrome.exe" in output
        assert "10.0.0.5" in output
        assert "93.184.216.34" in output
