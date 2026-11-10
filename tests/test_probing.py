from unittest.mock import patch

import pytest

from anomaly_detection.context import build_context_record
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.probing import ProbingDetector


def packet(**overrides):
    return dict(protocol="TCP", source_ip="192.168.1.5",
                destination_ip="8.8.8.8", destination_port=443,
                tcp_flags="S", direction="OUTGOING", packet_size=60,
                application_name="test", **overrides)


def evaluate(detector, **overrides):
    data = packet()
    data.update(overrides)
    return {r.rule_name: r for r in detector.evaluate(build_context_record(data))}


def test_port_probe_threshold_retries_and_cooldown():
    detector = ProbingDetector()
    with patch('anomaly_detection.probing.time.monotonic', return_value=0):
        for _ in range(30):
            assert not evaluate(detector)['tcp_port_probe'].triggered
        for port in range(1, 19):
            assert not evaluate(detector, destination_port=port)['tcp_port_probe'].triggered
        result = evaluate(detector, destination_port=19)['tcp_port_probe']
        assert result.triggered and result.severity == 'HIGH'
        assert not evaluate(detector, destination_port=20)['tcp_port_probe'].triggered
    with patch('anomaly_detection.probing.time.monotonic', return_value=61):
        assert not evaluate(detector, destination_port=21)['tcp_port_probe'].triggered


def test_host_probe_and_source_isolation():
    detector = ProbingDetector()
    with patch('anomaly_detection.probing.time.monotonic', return_value=0):
        for host in range(1, 20):
            assert not evaluate(detector, destination_ip=f'10.0.0.{host}')['tcp_host_probe'].triggered
        assert not evaluate(detector, source_ip='192.168.1.6', destination_ip='10.0.0.20')['tcp_host_probe'].triggered
        assert evaluate(detector, destination_ip='10.0.0.20')['tcp_host_probe'].triggered


@pytest.mark.parametrize('overrides', [
    {'tcp_flags': 'SA'}, {'tcp_flags': 'A'}, {'tcp_flags': None},
    {'direction': 'UNKNOWN'}, {'protocol': 'UDP'},
    {'destination_port': None}, {'destination_port': 70000},
    {'destination_ip': 'bad'}, {'destination_ip': '224.0.0.1'},
])
def test_non_attempts_do_not_accumulate(overrides):
    detector = ProbingDetector()
    for _ in range(25):
        assert not any(r.triggered for r in evaluate(detector, **overrides).values())
    assert not detector._groups


def test_smb_public_only_including_ipv6():
    detector = ProbingDetector()
    for destination in ('8.8.8.8', '2606:4700:4700::1111'):
        assert evaluate(detector, destination_ip=destination, destination_port=445)['internet_smb_attempt'].triggered
    assert not evaluate(detector, destination_ip='10.0.0.1', destination_port=445)['internet_smb_attempt'].triggered


def test_state_is_bounded():
    detector = ProbingDetector()
    detector.MAX_GROUPS = 8
    for port in range(1, 100):
        evaluate(detector, destination_port=port)
    assert len(detector._groups) <= 8
    assert all(len(targets) <= detector.DISTINCT_TARGETS for targets, _ in detector._groups.values())


def test_live_pipeline_preserves_evidence_and_triggers():
    orchestrator = AnomalyDetectionOrchestrator()
    for port in range(1, 21):
        data = packet()
        data['destination_port'] = port
        results = orchestrator.process_packet(data)
    result = next(r for r in results if r.rule_name == 'tcp_port_probe')
    assert result.triggered
    assert result.context.to_dict()['destination_port'] == 20
    assert result.context.to_dict()['tcp_flags'] == 'S'


def test_unknown_classification_is_not_internet_evidence():
    from anomaly_detection.rules import unknown_application_internet_rule
    data = packet()
    data.update(application_name='UNKNOWN', communication_type='UNKNOWN')
    assert not unknown_application_internet_rule(build_context_record(data)).triggered
