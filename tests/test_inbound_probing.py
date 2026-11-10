from unittest.mock import patch

import pytest

from anomaly_detection.context import build_context_record
from anomaly_detection.probing import ProbingDetector


def evaluate(detector, **overrides):
    packet = dict(protocol='TCP', source_ip='8.8.8.8',
                  destination_ip='192.168.1.5', destination_port=443,
                  tcp_flags='S', direction='INCOMING', packet_size=60)
    packet.update(overrides)
    return {result.rule_name: result for result in
            detector.evaluate(build_context_record(packet))}


def test_inbound_distinct_ports_threshold_retries_cooldown_and_expiry():
    detector = ProbingDetector()
    with patch('anomaly_detection.probing.time.monotonic', return_value=0):
        for _ in range(25):
            assert not evaluate(detector)['inbound_tcp_port_probe'].triggered
        for port in range(1, 19):
            assert not evaluate(detector, destination_port=port)['inbound_tcp_port_probe'].triggered
        results = evaluate(detector, destination_port=19)
        assert results['inbound_tcp_port_probe'].triggered
        assert results['inbound_tcp_port_probe'].severity == 'HIGH'
        assert not any(result.triggered for name, result in results.items()
                       if name != 'inbound_tcp_port_probe')
        assert '192.168.1.5' in results['inbound_tcp_port_probe'].reason
        assert '8.8.8.8' in results['inbound_tcp_port_probe'].reason
        assert not evaluate(detector, destination_port=20)['inbound_tcp_port_probe'].triggered
    with patch('anomaly_detection.probing.time.monotonic', return_value=60):
        assert not evaluate(detector, destination_port=21)['inbound_tcp_port_probe'].triggered
        for port in range(22, 40):
            assert not evaluate(detector, destination_port=port)['inbound_tcp_port_probe'].triggered
        assert evaluate(detector, destination_port=40)['inbound_tcp_port_probe'].triggered


@pytest.mark.parametrize('overrides', [
    {'tcp_flags': 'SA'}, {'tcp_flags': 'A'}, {'tcp_flags': None},
    {'tcp_flags': 'SF'}, {'tcp_flags': 2}, {'protocol': 'UDP'},
    {'source_ip': None}, {'destination_ip': None},
    {'source_ip': '224.0.0.1'}, {'source_ip': '0.0.0.0'},
    {'destination_port': None}, {'destination_port': True},
    {'direction': 'UNKNOWN'},
])
def test_inbound_non_attempts_and_missing_evidence_are_ignored(overrides):
    detector = ProbingDetector()
    for _ in range(25):
        assert not any(result.triggered for result in evaluate(detector, **overrides).values())
    assert not detector._groups


def test_remote_sources_local_destinations_and_direction_are_isolated():
    detector = ProbingDetector()
    for port in range(1, 20):
        evaluate(detector, destination_port=port)
    assert not evaluate(detector, destination_port=20, source_ip='1.1.1.1')['inbound_tcp_port_probe'].triggered
    assert not evaluate(detector, destination_port=20, destination_ip='192.168.1.6')['inbound_tcp_port_probe'].triggered
    assert not evaluate(detector, destination_port=20, direction='OUTGOING')['tcp_port_probe'].triggered
    assert evaluate(detector, destination_port=20)['inbound_tcp_port_probe'].triggered


def test_ipv6_and_bounded_tracking():
    detector = ProbingDetector()
    for port in range(1, 21):
        result = evaluate(detector, source_ip='2606:4700:4700::1111',
                          destination_ip='fd00::1', destination_port=port)
    assert result['inbound_tcp_port_probe'].triggered
    detector.MAX_GROUPS = 4
    for host in range(1, 10):
        evaluate(detector, source_ip=f'10.0.0.{host}')
    assert len(detector._groups) <= 4
    assert all(len(targets) <= detector.DISTINCT_TARGETS
               for targets, _ in detector._groups.values())
