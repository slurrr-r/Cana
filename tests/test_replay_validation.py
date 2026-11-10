"""Replay plumbing and the release gate, independent of downloaded samples."""
from unittest.mock import Mock

from scapy.all import Ether, IP, TCP, wrpcap

from anomaly_detection.context import build_context_record
from anomaly_detection.rules import RuleResult, SECURITY_ALERT_RULES
from cana_engine.handler import build_packet_handler
from tools.replay_existing_rules import replay


def test_unapproved_results_never_enter_security_sinks():
    context = build_context_record({})
    names = ['idle_large_transfer', 'unknown_application_internet', 'packet_size_anomaly',
             'connection_rate_anomaly', 'tcp_host_probe', 'internet_smb_attempt',
             'long_dns_query_burst', 'public_legacy_service', 'dns_failure_burst',
             'upload_heavy_transfer', 'future_unreviewed_rule']
    orchestrator = Mock()
    orchestrator.process_packet.return_value = [RuleResult(n, True, 'HIGH', 'evidence', context) for n in names]
    store, risk, correlator, notifier = Mock(), Mock(), Mock(), Mock()
    build_packet_handler(orchestrator, None, store=store, risk_scorer=risk,
                         correlator=correlator, notifier=notifier, print_alerts=False)({})
    store.record_alert.assert_not_called()
    risk.record.assert_not_called()
    correlator.observe.assert_not_called()
    notifier.notify.assert_not_called()
    assert SECURITY_ALERT_RULES == {'tcp_port_probe', 'inbound_tcp_port_probe', 'unusual_tcp_flags'}


def test_packet_replay_preserves_spacing_and_both_directions(tmp_path):
    def capture(path, spacing):
        packets = []
        for i in range(20):
            pkt = Ether()/IP(src='192.168.1.2', dst='192.168.1.3')/TCP(dport=1000+i, flags='S')
            pkt.time = 1_700_000_000 + i * spacing
            packets.append(pkt)
        wrpcap(str(path), packets)
    fast, slow = tmp_path/'fast.pcap', tmp_path/'slow.pcap'
    capture(fast, 1)
    capture(slow, 61)
    hosts = ['192.168.1.2', '192.168.1.3']
    result = replay(fast, hosts)
    assert result['hosts'][hosts[0]]['emitted_alerts'] == {'tcp_port_probe': 1}
    assert result['hosts'][hosts[1]]['emitted_alerts'] == {'inbound_tcp_port_probe': 1}
    result = replay(slow, hosts)
    assert all(not h['emitted_alerts'] for h in result['hosts'].values())
