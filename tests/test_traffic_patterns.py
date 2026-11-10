from unittest.mock import patch
import sqlite3

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from anomaly_detection.context import build_context_record
from anomaly_detection.traffic_patterns import TrafficPatternDetector
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.rules import RuleResult
from anomaly_detection.store import BaselineStore, _SCHEMA_STATEMENTS
from packet_capture.parser import parse_packet


def context(**changes):
    packet = dict(source_ip='192.168.1.5', destination_ip='8.8.8.8',
                  source_port=50000, destination_port=53, protocol='UDP',
                  direction='OUTGOING', application_protocol='DNS', dns_id=1,
                  dns_query_name='example.com', dns_is_response=False, dns_rcode=0,
                  dns_qtype=1, dns_qclass=1,
                  packet_size=1000, application_name='test.exe')
    packet.update(changes)
    return build_context_record(packet)


def exchange(detector, index, code=3, **changes):
    query = f'name{index}.example.com'
    detector.evaluate(context(dns_id=index, dns_query_name=query))
    response = dict(source_ip='8.8.8.8', destination_ip='192.168.1.5',
                    source_port=53, destination_port=50000, direction='INCOMING',
                    dns_is_response=True, dns_id=index, dns_query_name=query, dns_rcode=code)
    response.update(changes)
    return detector.evaluate(context(**response))[0]


def test_dns_threshold_duplicate_cooldown_and_expiry():
    detector = TrafficPatternDetector()
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=0):
        for index in range(29):
            assert not exchange(detector, index).triggered
        for _ in range(10):
            assert not exchange(detector, 0).triggered
        result = exchange(detector, 29)
        assert result.triggered and '30/30' in result.reason
        assert not exchange(detector, 30).triggered
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=61):
        assert not exchange(detector, 31).triggered


def test_successful_names_reduce_ratio():
    detector = TrafficPatternDetector()
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=0):
        for index in range(20):
            exchange(detector, index, code=0)
        for index in range(20, 50):
            assert not exchange(detector, index).triggered


def test_unmatched_wrong_port_wrong_id_and_expired_responses_ignored():
    for change in ({'destination_port': 49999}, {'dns_id': 60000}, {'source_ip': '1.1.1.1'}, {'dns_qtype': 28}, {'dns_qclass': 3}):
        detector = TrafficPatternDetector()
        for index in range(35):
            assert not exchange(detector, index, **change).triggered
        assert not detector._dns
    detector = TrafficPatternDetector()
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=0):
        detector.evaluate(context())
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=61):
        detector.evaluate(context(source_ip='8.8.8.8', destination_ip='192.168.1.5',
            source_port=53, destination_port=50000, direction='INCOMING', dns_is_response=True, dns_rcode=3))
    assert not detector._dns


def test_upload_volume_duration_ratio_and_download_exclusion():
    detector = TrafficPatternDetector()
    detector.UPLOAD_MIN_BYTES = 10000
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=0):
        for _ in range(9):
            assert not detector.evaluate(context(application_protocol=None))[1].triggered
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=65):
        result = detector.evaluate(context(application_protocol=None))[1]
        assert result.triggered
        assert not detector.evaluate(context())[1].triggered
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=361):
        assert not detector.evaluate(context())[1].triggered
    detector = TrafficPatternDetector()
    detector.UPLOAD_MIN_BYTES = 10000
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=0):
        for _ in range(15):
            assert not detector.evaluate(context(source_ip='8.8.8.8', destination_ip='192.168.1.5', direction='INCOMING'))[1].triggered
            detector.evaluate(context())
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=65):
        assert not detector.evaluate(context())[1].triggered


def test_state_bounds_and_private_upload_exclusion():
    detector = TrafficPatternDetector()
    detector.MAX_GROUPS = 4
    detector.MAX_PENDING = 8
    for index in range(20):
        exchange(detector, index)
        detector.evaluate(context(destination_ip=f'8.8.4.{index + 1}'))
    assert len(detector._pending) <= 8
    assert len(detector._transfers) <= 4
    assert not TrafficPatternDetector().evaluate(context(destination_ip='10.0.0.1'))[1].triggered


def test_upload_minimum_duration_is_not_shortened_by_bucket_rounding():
    detector = TrafficPatternDetector()
    detector.UPLOAD_MIN_BYTES = 1000
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=4.9):
        detector.evaluate(context())
    with patch('anomaly_detection.traffic_patterns.time.monotonic', return_value=60):
        assert not detector.evaluate(context())[1].triggered


def test_servfail_responses_remain_in_dns_denominator():
    detector = TrafficPatternDetector()
    for index in range(70):
        exchange(detector, index, code=2)
    for index in range(70, 100):
        assert not exchange(detector, index).triggered


def test_dns_parser_engine_store_ui_roundtrip(tmp_path):
    engine = AnomalyDetectionOrchestrator()
    for index in range(30):
        raw = IP(src='192.168.1.5', dst='8.8.8.8') / UDP(sport=50000, dport=53) / DNS(id=index, qr=0, qd=DNSQR(qname=f'name{index}.example.com'))
        packet = parse_packet(raw)
        packet['direction'] = 'OUTGOING'
        engine.process_packet(packet)
        raw[IP].src, raw[IP].dst = raw[IP].dst, raw[IP].src
        raw[UDP].sport, raw[UDP].dport = 53, 50000
        raw[DNS].qr, raw[DNS].rcode = 1, 3
        packet = parse_packet(raw)
        packet['direction'] = 'INCOMING'
        results = engine.process_packet(packet)
    result = next(r for r in results if r.rule_name == 'dns_failure_burst')
    assert result.triggered
    store = BaselineStore(tmp_path / 'alerts.db')
    assert store.record_alert(result)
    row = store.recent_alerts()[0]
    assert row['dns_rcode'] == 3 and row['dns_id'] == 29
    assert row['direction'] == 'INCOMING' and row['destination_port'] == 50000
    from cana_ui.explain import explain_alert
    assert 'do not exist' in explain_alert(row)['title']


def test_old_schema_migrates_without_losing_history(tmp_path):
    path = tmp_path / 'old.db'
    with sqlite3.connect(path) as db:
        for statement in _SCHEMA_STATEMENTS:
            db.execute(statement)
        db.execute("INSERT INTO baseline_buckets VALUES ('packet_size', 1, 5, 100, 0, 'old')")
    store = BaselineStore(path)
    result = RuleResult('test', True, 'LOW', 'evidence', context(tcp_flags='S'))
    assert store.record_alert(result)
    assert store.recent_alerts()[0]['tcp_flags'] == 'S'
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT observation_count FROM baseline_buckets').fetchone()[0] == 5
