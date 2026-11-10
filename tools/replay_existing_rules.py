"""Passive PCAP replay through CANA parser, classifier, rules and alert handler.

Run as a separate process: virtual clocks are scoped patches for replay only.
No process ownership or activity is inferred from historical packet captures.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import json
import logging
import lzma
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scapy.all import RawPcapReader, conf
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from cana_engine.handler import build_packet_handler
from packet_capture.parser import parse_packet
from packet_capture.classifier import classify_packet
from packet_capture.validator import validate_packet


class Recorder:
    def __init__(self):
        self.counts = Counter()

    def record_alert(self, result, session_id=None):
        self.counts[result.rule_name] += 1


def replay(path, hosts):
    engines = {host: AnomalyDetectionOrchestrator() for host in hosts}
    stores = {host: Recorder() for host in hosts}
    handlers = {host: build_packet_handler(engine, None, store=stores[host], print_alerts=False)
                for host, engine in engines.items()}
    raw_counts = {host: Counter() for host in hosts}
    evaluated = {host: Counter() for host in hosts}
    for host, engine in engines.items():
        original = engine.process_packet
        def observe(packet, activity=None, original=original, host=host):
            results = original(packet, activity)
            evaluated[host].update(r.rule_name for r in results)
            raw_counts[host].update(r.rule_name for r in results if r.triggered)
            return results
        engine.process_packet = observe
    clock = [0.0]
    packet_count = truncated = regressions = rejected = 0
    first = last = None
    host_times = {host: [] for host in hosts}
    opener = lzma.open if path.suffix == '.xz' else open
    with ExitStack() as stack:
        stack.enter_context(patch('time.time', lambda: clock[0]))
        stack.enter_context(patch('time.monotonic', lambda: clock[0]))
        stream = stack.enter_context(opener(path, 'rb'))
        reader = stack.enter_context(RawPcapReader(stream))
        for data, meta in reader:
            if hasattr(meta, 'caplen') and len(data) != meta.caplen:
                truncated += 1
                continue
            linktype = getattr(meta, 'linktype', getattr(reader, 'linktype', None))
            decoder = conf.l2types.get(linktype)
            if decoder is None:
                raise ValueError(f'Unsupported link type: {linktype}')
            timestamp = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol if hasattr(meta, 'tsresol') else meta.sec + meta.usec / (1e9 if reader.nano else 1e6)
            if last is not None and timestamp < last:
                regressions += 1
            # Preserve arrival order and prevent timers running backwards.
            clock[0] = max(clock[0], timestamp)
            first = timestamp if first is None else first
            last = timestamp
            packet_count += 1
            raw = decoder(data)
            raw.time = timestamp
            parsed = parse_packet(raw)
            if not validate_packet(parsed).is_valid:
                rejected += 1
                continue
            for host in set((parsed['source_ip'], parsed['destination_ip'])) & engines.keys():
                times = host_times[host]
                if not times:
                    times.extend([timestamp, timestamp])
                times[1] = timestamp
                handlers[host](classify_packet(parsed, host))
    return dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                packets=packet_count, truncated_records_excluded=truncated,
                validator_rejections=rejected,
                timestamp_regressions=regressions, span_seconds=None if first is None else last-first,
                hosts={host: dict(packets=engines[host].packets_processed,
                       observed_span_seconds=(host_times[host][1]-host_times[host][0]) if host_times[host] else 0,
                       evaluated=dict(evaluated[host]), raw_triggers=dict(raw_counts[host]),
                       emitted_alerts=dict(stores[host].counts)) for host in hosts})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='output/existing_rules_packet_replay.json')
    args = parser.parse_args()
    logging.disable(logging.CRITICAL)
    captures = [
        ('monday-prefix-complete.pcapng', ['192.168.10.'+n for n in ('9', '5', '8', '14', '15')]),
        ('monday-holdout.pcapng', ['192.168.10.'+n for n in ('9', '5', '8', '14', '15')]),
        ('hue.pcap.xz', ['192.168.1.132']),
        ('iot20.pcap', ['192.168.100.103']),
        ('nmap_standard_scan.pcap', ['192.168.100.103', '192.168.100.102']),
        ('nmap_OS_scan_succesful.pcap', ['192.168.100.103', '192.168.100.101']),
        ('nmap_ACK_scan_on_port_80.pcap', ['192.168.100.103', '192.168.100.102']),
    ]
    results = []
    for filename, hosts in captures:
        result = replay(ROOT / 'tmp' / 'real_traffic' / filename, hosts)
        results.append(result)
        print(filename, result['packets'], {h: r['emitted_alerts'] for h,r in result['hosts'].items()}, flush=True)
    benign = results[:3]
    assert all(not host['emitted_alerts'] for c in benign for host in c['hosts'].values()), 'Enabled rule failed benign replay'
    assert results[4]['hosts']['192.168.100.103']['emitted_alerts'].get('tcp_port_probe') == 1
    assert results[4]['hosts']['192.168.100.102']['emitted_alerts'].get('inbound_tcp_port_probe') == 1
    assert results[5]['hosts']['192.168.100.103']['emitted_alerts'].get('unusual_tcp_flags') == 1
    report = dict(scope='Actual offline packet replay; isolated cold baselines per host; no live sockets, notifications or database writes',
                  missing_context=['historical process attribution', 'historical user activity'],
                  windows_source='https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/Monday-WorkingHours.pcap',
                  windows_provenance='Mirror; first 128 MiB, split at complete block boundary 33554332. First 32 MiB discovery; subsequent bytes holdout with fresh baselines. Final 1564 incomplete bytes excluded. Windows IP mapping/benign Monday label: https://www.unb.ca/cic/datasets/ids-2017.html. Lab-generated user profiles; not a modern Windows fleet validation.',
                  nmap_source='https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip',
                  iot_source='https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/',
                  approved_scope='Three enabled rules pass these samples only. No production accuracy claim.',
                  decisions={
                      'tcp_port_probe': 'Enabled: positive standard/OS scans, zero benign sample alerts.',
                      'inbound_tcp_port_probe': 'Enabled: positive standard/OS scans from target perspective, zero benign sample alerts.',
                      'unusual_tcp_flags': 'Enabled: positive OS scan, zero benign sample alerts.',
                      'tcp_host_probe': 'Diagnostic only: false alert on labelled benign Windows discovery sample.',
                      'connection_rate_anomaly': 'Diagnostic only: false alert on Windows and repeated benign Hue alerts.',
                      'unknown_application_internet': 'Diagnostic only: missing ownership is not security evidence; PCAP cannot validate live attribution.',
                      'packet_size_anomaly': 'Diagnostic only: size alone is not security evidence.',
                      'idle_large_transfer': 'Diagnostic only: no recorded user activity or positive validation.',
                      'internet_smb_attempt': 'Diagnostic only: no positive/benign service-policy validation.',
                      'public_legacy_service': 'Diagnostic only: no positive/benign service-policy validation.',
                      'long_dns_query_burst': 'Diagnostic only: no labelled positive DNS-tunnel coverage.',
                      'dns_failure_burst': 'Diagnostic only: no labelled positive DNS-failure coverage.',
                      'upload_heavy_transfer': 'Diagnostic only: no labelled exfiltration/benign backup coverage.',
                  },
                  original_download_sha256={name: hashlib.sha256((ROOT/'tmp/real_traffic'/name).read_bytes()).hexdigest()
                      for name in ('monday-128m.pcapng', 'nmap-captures.zip')},
                  captures=results)
    (ROOT / args.output).write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
