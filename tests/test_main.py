"""Unit tests for main.py's diagnostic helper functions and packet-handler wiring."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest

from anomaly_detection.context import ContextRecord
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.rules import RuleResult
from main import _print_capture_error_help, build_packet_handler
from risk_scoring.correlator import AlertCorrelator
from risk_scoring.notifier import AlertNotifier
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore


def _captured_output(exc: Exception) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        _print_capture_error_help(exc)
    return buffer.getvalue()


def _packet(**overrides):
    packet = {
        "protocol": "TCP",
        "source_ip": "10.0.0.1",
        "destination_ip": "93.184.216.34",
        "direction": "OUTGOING",
        "communication_type": "INTERNET",
        "packet_size": 1000,
        "application_name": "UNKNOWN",
        "process_id": None,
    }
    packet.update(overrides)
    return packet


class TestPrintCaptureErrorHelp:
    def test_npcap_missing_gives_specific_guidance(self) -> None:
        exc = OSError(
            "Sniffing and sending packets is not available at layer 2: "
            "winpcap is not installed. You may use conf.L3socket "
            "or conf.L3socket6 to access layer 3"
        )
        output = _captured_output(exc)
        assert "Npcap" in output
        assert "npcap.com" in output
        assert "WinPcap API-compatible Mode" in output

    def test_permission_error_gives_admin_guidance(self) -> None:
        exc = PermissionError("Access is denied")
        output = _captured_output(exc)
        assert "Administrator" in output

    def test_generic_error_falls_back_to_message(self) -> None:
        exc = RuntimeError("some other unexpected failure")
        output = _captured_output(exc)
        assert "some other unexpected failure" in output

    def test_libpcap_keyword_also_triggers_npcap_guidance(self) -> None:
        exc = OSError("no libpcap provider available")
        output = _captured_output(exc)
        assert "npcap.com" in output


class TestBuildPacketHandler:
    def test_handler_processes_without_activity(self):
        orchestrator = AnomalyDetectionOrchestrator()
        build_packet_handler(orchestrator, None)(_packet())
        assert orchestrator.packets_processed == 1

    def test_missing_attribution_does_not_emit_security_alert(self, capsys):
        handler = build_packet_handler(AnomalyDetectionOrchestrator(), None)
        for _ in range(20):
            handler(_packet())
        assert "ALERT" not in capsys.readouterr().out

    def test_rising_edges_and_distinct_peers(self, capsys):
        def event(peer, triggered):
            return RuleResult('tcp_port_probe', triggered, 'HIGH', 'probe',
                              _context(destination_ip=peer))
        sequence = [[event('1.1.1.1', True)], [event('1.1.1.1', True)],
                    [event('9.9.9.9', False)], [event('1.1.1.1', True)],
                    [event('9.9.9.9', True)], [event('1.1.1.1', False)],
                    [event('1.1.1.1', True)]]
        handler = build_packet_handler(_StubOrchestrator(sequence), None)
        for _ in sequence:
            handler(_packet())
        assert capsys.readouterr().out.count('ALERT') == 3

    def test_distinct_rules_are_independent(self, capsys):
        events = [_result('tcp_port_probe', 'HIGH'), _result('unusual_tcp_flags', 'MEDIUM')]
        handler = build_packet_handler(_StubOrchestrator([events]), None)
        handler(_packet())
        handler(_packet())
        assert capsys.readouterr().out.count('ALERT') == 2

    @pytest.mark.parametrize('running', [False, True])
    def test_activity_lookup_requires_running_tracker(self, running):
        from types import SimpleNamespace
        from unittest.mock import Mock
        tracker = Mock()
        tracker.is_running.return_value = running
        tracker.get_status.return_value = SimpleNamespace(status='IDLE', idle_seconds=400)
        orchestrator = AnomalyDetectionOrchestrator()
        build_packet_handler(orchestrator, tracker)(_packet())
        assert tracker.get_status.call_count == int(running)
        assert orchestrator.packets_processed == 1


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
        "user_status": "ACTIVE",
        "idle_seconds": 0.0,
    }
    fields.update(overrides)
    return ContextRecord(**fields)


def _result(rule_name: str, severity: str) -> RuleResult:
    return RuleResult(
        rule_name=rule_name,
        triggered=True,
        severity=severity,
        reason=f"reason for {rule_name}",
        context=_context(),
    )


class _StubOrchestrator:
    """Returns a scripted sequence of rule-result lists, like the real one."""

    def __init__(self, sequence):
        self._sequence = sequence
        self._idx = 0
        self.packets_processed = 0

    def process_packet(self, packet, activity_status):
        results = self._sequence[min(self._idx, len(self._sequence) - 1)]
        self._idx += 1
        self.packets_processed += 1
        return results


class _RecordingChannel:
    def __init__(self):
        self.alerts = []

    def notify_alert(self, alert):
        self.alerts.append(alert)
        return True


class TestModule5Wiring:
    def test_inbound_peers_have_independent_alert_suppression(self) -> None:
        def result(source, triggered=True):
            return RuleResult(
                rule_name="unusual_tcp_flags", triggered=triggered,
                severity="MEDIUM", reason="Unusual flags",
                context=_context(direction="INCOMING", source_ip=source,
                                 destination_ip="10.0.0.5"),
            )

        peer_a = "1.1.1.1"
        peer_b = "9.9.9.9"
        sequence = [[result(peer_a)], [result(peer_b)], [result(peer_b, False)],
                    [result(peer_a)], [result(peer_b)]]
        scorer = RiskScorer(half_life=300.0)
        handler = build_packet_handler(
            _StubOrchestrator(sequence), activity_tracker=None,
            risk_scorer=scorer, print_alerts=False,
        )
        for _ in sequence:
            handler(_packet())

        # A triggers once; B triggers twice after its own condition clears.
        assert scorer.events_for("application", "chrome.exe") == 3

    def test_triggered_results_feed_risk_scorer(self) -> None:
        orchestrator = _StubOrchestrator(
            [[_result("unusual_tcp_flags", "MEDIUM")]]
        )
        scorer = RiskScorer(half_life=300.0)
        handler = build_packet_handler(
            orchestrator, activity_tracker=None, risk_scorer=scorer
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            handler(_packet())
            handler(_packet())
            handler(_packet())

        # Each trigger (rising edge) adds MEDIUM weight (2.0) to chrome.exe.
        assert scorer.events_for("application", "chrome.exe") == 1
        assert scorer.application_score("chrome.exe") == pytest.approx(2.0, abs=0.01)

    def test_two_distinct_signals_produce_one_correlated_alert(self, tmp_path) -> None:
        orchestrator = _StubOrchestrator(
            [
                [_result("unusual_tcp_flags", "MEDIUM")],
                [_result("tcp_port_probe", "MEDIUM")],
                [_result("tcp_port_probe", "MEDIUM")],
            ]
        )
        scorer = RiskScorer(half_life=300.0)
        correlator = AlertCorrelator(window_seconds=60.0)
        channel = _RecordingChannel()
        notifier = AlertNotifier(channels=[channel])
        risk_store = RiskStore(tmp_path / "test.db")

        handler = build_packet_handler(
            orchestrator,
            activity_tracker=None,
            risk_scorer=scorer,
            correlator=correlator,
            notifier=notifier,
            risk_store=risk_store,
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            handler(_packet())  # signal 1: unusual_tcp_flags
            handler(_packet())  # signal 2: tcp_port_probe -> correlated
            handler(_packet())  # tcp_port_probe alone (not distinct) -> nothing

        output = buffer.getvalue()
        assert "CORRELATED" in output
        assert len(channel.alerts) == 1
        assert channel.alerts[0].signal_count == 2

        persisted = risk_store.recent_correlated_alerts(limit=10)
        assert len(persisted) == 1
        assert persisted[0]["rule_names"] == [
            "unusual_tcp_flags",
            "tcp_port_probe",
        ]

    def test_no_persist_mode_skips_risk_store(self) -> None:
        """With risk_store omitted, correlation still prints but nothing persists."""
        orchestrator = _StubOrchestrator(
            [
                [_result("unusual_tcp_flags", "MEDIUM")],
                [_result("tcp_port_probe", "MEDIUM")],
            ]
        )
        scorer = RiskScorer(half_life=300.0)
        correlator = AlertCorrelator(window_seconds=60.0)
        handler = build_packet_handler(
            orchestrator,
            activity_tracker=None,
            risk_scorer=scorer,
            correlator=correlator,
            risk_store=None,
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            handler(_packet())
            handler(_packet())

        assert "CORRELATED" in buffer.getvalue()

    def test_single_high_signal_emits_correlated_alert(self, tmp_path) -> None:
        orchestrator = _StubOrchestrator(
            [[_result("unusual_tcp_flags", "HIGH")]]
        )
        scorer = RiskScorer(half_life=300.0)
        correlator = AlertCorrelator(window_seconds=60.0)
        risk_store = RiskStore(tmp_path / "test.db")

        handler = build_packet_handler(
            orchestrator,
            activity_tracker=None,
            risk_scorer=scorer,
            correlator=correlator,
            risk_store=risk_store,
        )

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            handler(_packet())

        assert "CORRELATED" in buffer.getvalue()
        assert risk_store.correlated_alert_count() == 1
