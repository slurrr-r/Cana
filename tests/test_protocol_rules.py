from unittest.mock import patch

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from anomaly_detection.context import build_context_record
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.protocol_rules import ProtocolDetector
from cana_ui.explain import explain_alert
from packet_capture.parser import parse_packet


def evaluate(detector=None, **overrides):
    packet = dict(protocol='TCP', tcp_flags='S', destination_port=443,
                  source_ip='192.168.1.5', destination_ip='8.8.8.8',
                  direction='OUTGOING', application_name='test.exe')
    packet.update(overrides)
    return {r.rule_name: r for r in (detector or ProtocolDetector()).evaluate(build_context_record(packet))}


@pytest.mark.parametrize('flags', ['', 'SF', 'SR', 'FPU'])
@pytest.mark.parametrize('direction', ['INCOMING', 'OUTGOING'])
def test_unusual_flags_identified(flags, direction):
    result = evaluate(tcp_flags=flags, direction=direction)['unusual_tcp_flags']
    assert result.triggered
    assert 'TCP packet' in result.reason
    assert 'authorized' in result.reason.lower()


@pytest.mark.parametrize('flags', [None, 'S', 'SA', 'PA', 'FA', 'R', 'RA', 'SEC'])
def test_normal_or_missing_flags_not_flagged(flags):
    assert not evaluate(tcp_flags=flags)['unusual_tcp_flags'].triggered


@pytest.mark.parametrize('port', [21, 23])
def test_legacy_attempts_only_public_outbound_syn(port):
    assert evaluate(destination_port=port)['public_legacy_service'].triggered
    for change in ({'direction': 'INCOMING'}, {'tcp_flags': 'SA'},
                   {'destination_ip': '10.0.0.1'}, {'protocol': 'UDP'}):
        assert not evaluate(destination_port=port, **change)['public_legacy_service'].triggered
    assert evaluate(destination_port=port, destination_ip='2606:4700:4700::1111')['public_legacy_service'].triggered


def dns(detector, index, **changes):
    values = dict(protocol='UDP', application_protocol='DNS', dns_is_response=False,
                  dns_query_name=f'{index:050d}.example.com')
    values.update(changes)
    return evaluate(detector, **values)['long_dns_query_burst']


def test_dns_distinct_threshold_cooldown_and_expiration():
    detector = ProtocolDetector()
    with patch('anomaly_detection.protocol_rules.time.monotonic', return_value=0):
        for _ in range(25):
            assert not dns(detector, 0).triggered
        for index in range(1, 19):
            assert not dns(detector, index).triggered
        assert dns(detector, 19).triggered
        assert not dns(detector, 20).triggered
    with patch('anomaly_detection.protocol_rules.time.monotonic', return_value=61):
        assert not dns(detector, 21).triggered
        for index in range(22, 40):
            assert not dns(detector, index).triggered
        assert dns(detector, 40).triggered


@pytest.mark.parametrize('changes', [
    {'dns_is_response': True}, {'dns_is_response': None},
    {'direction': 'INCOMING'}, {'direction': 'UNKNOWN'},
    {'dns_query_name': 'example.com'}, {'dns_query_name': 'a' * 64 + '.com'},
    {'dns_query_name': None}, {'destination_ip': 'invalid'},
])
def test_dns_exclusions(changes):
    detector = ProtocolDetector()
    for index in range(25):
        assert not dns(detector, index, **changes).triggered
    assert not detector._dns


def test_dns_resolvers_are_separate_and_storage_bounded():
    detector = ProtocolDetector()
    detector.MAX_GROUPS = 4
    for index in range(19):
        dns(detector, index)
    assert not dns(detector, 19, destination_ip='1.1.1.1').triggered
    for host in range(1, 10):
        dns(detector, host, destination_ip=f'10.0.0.{host}')
        evaluate(detector, destination_ip=f'10.0.0.{host}', tcp_flags='SF')
    assert len(detector._dns) <= 4
    assert len(detector._alerts) <= 4


def test_parser_to_engine_dns_pipeline_and_response_exclusion():
    engine = AnomalyDetectionOrchestrator()
    for index in range(20):
        raw = IP(src='192.168.1.5', dst='8.8.8.8') / UDP(dport=53) / DNS(
            qr=0, qd=DNSQR(qname=f'{index:050d}.example.com'))
        packet = parse_packet(raw)
        assert packet['dns_is_response'] is False
        packet['direction'] = 'OUTGOING'
        results = engine.process_packet(packet)
    result = next(r for r in results if r.rule_name == 'long_dns_query_burst')
    assert result.triggered
    assert result.context.to_dict()['dns_query_name'].endswith('.example.com')
    raw[DNS].qr = 1
    assert parse_packet(raw)['dns_is_response'] is True


@pytest.mark.parametrize('rule', ['unusual_tcp_flags', 'long_dns_query_burst',
    'public_legacy_service', 'tcp_port_probe', 'tcp_host_probe', 'internet_smb_attempt'])
def test_ui_keeps_specific_anomaly_with_known_app(rule):
    explanation = explain_alert(dict(rule_name=rule, application_name='test.exe', reason='Exact evidence'))
    if rule in {'long_dns_query_burst', 'tcp_port_probe', 'tcp_host_probe'}:
        assert not explanation['title'].startswith('Test: ')
    else:
        assert explanation['title'].startswith('Test: ')
    assert 'generated unusual network activity' not in explanation['title']
    assert 'learned' not in explanation['why']
    assert explanation['technical'] == 'Exact evidence'
