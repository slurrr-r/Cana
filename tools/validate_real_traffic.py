"""Offline candidate evaluation on original IoT-23 Zeek logs; never sends packets."""
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict, deque
from pathlib import Path

from validate_candidate_rules import regular_connections, rejected_connections

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/'


def parse(text):
    fields = None
    rows = []
    for line in text.splitlines():
        if line.startswith('#fields'):
            fields = line.split()[1:]
        elif line and not line.startswith('#'):
            values = line.split()
            if fields is None or len(values) != len(fields):
                raise ValueError('Unexpected IoT-23 schema')
            row = dict(zip(fields, values))
            row['ts'] = float(row['ts'])
            rows.append(row)
    if not rows:
        raise ValueError('Empty capture')
    return sorted(rows, key=lambda row: row['ts'])


def evaluate(rows):
    cadence = defaultdict(lambda: deque(maxlen=12))
    rejection = defaultdict(deque)
    alerts = Counter()
    examples = []
    cooldown = {}
    seen = set()
    for row in rows:
        if row['uid'] in seen:
            continue
        seen.add(row['uid'])
        if row['proto'] != 'tcp' or not ipaddress.ip_address(row['id.resp_h']).is_global:
            continue
        key = (row['id.orig_h'], row['id.resp_h'], row['id.resp_p'])
        now = row['ts']
        cadence[key].append(now)
        state = {'REJ': 'rejected', 'SF': 'established', 'S1': 'established'}.get(row['conn_state'], 'unknown')
        rejection[key].append((now, row['uid'], state))
        while rejection[key] and rejection[key][0][0] < now - 60:
            rejection[key].popleft()
        for name, triggered in (
            ('regular_connections', regular_connections(list(cadence[key]))),
            ('tcp_rejection_burst', rejected_connections([(uid, state) for _, uid, state in rejection[key]])),
        ):
            if triggered and now - cooldown.get((name, key), float('-inf')) >= 600:
                cooldown[name, key] = now
                label = row['label'].lower()
                alerts[name + ':' + label] += 1
                if len(examples) < 20:
                    examples.append(dict(rule=name, ts=now, peer=key, triggering_flow_label=label))
    return dict(rows=len(rows), labels=dict(Counter(r['label'].lower() for r in rows)),
                detailed_labels=dict(Counter(r['detailed-label'] for r in rows)),
                span_seconds=rows[-1]['ts'] - rows[0]['ts'],
                alerts=dict(alerts), examples=examples)


def main():
    # Fail closed on malformed downloaded input; this is not a general Zeek importer.
    try:
        parse('#fields ts uid\n1\n')
    except ValueError:
        pass
    else:
        raise AssertionError('Malformed rows accepted')
    assert regular_connections([i * 60 for i in range(12)])
    assert not rejected_connections([('same', 'rejected')] * 40)
    fixture = [dict(ts=i * 60, uid=str(i), proto='tcp', **{
        'id.orig_h': '192.168.1.2', 'id.resp_h': '8.8.8.8', 'id.resp_p': '443',
        'conn_state': 'SF', 'label': 'Benign', 'detailed-label': '-',
    }) for i in range(12)]
    assert evaluate(fixture)['alerts'] == {'regular_connections:benign': 1}
    assert evaluate([fixture[0]] * 40)['alerts'] == {}
    for i, row in enumerate(fixture):
        row['ts'] = i
        row['conn_state'] = 'REJ'
    fixture += [dict(fixture[0], uid=str(i), ts=i) for i in range(12, 30)]
    assert evaluate(fixture)['alerts'] == {'tcp_rejection_burst:benign': 1}
    results = []
    for name in ('CTU-Honeypot-Capture-4-1', 'CTU-Honeypot-Capture-5-1', 'CTU-IoT-Malware-Capture-20-1'):
        raw = (ROOT / 'tmp' / 'real_traffic' / (name + '.log')).read_bytes()
        results.append(dict(capture=name, url=SOURCE + name + '/bro/conn.log.labeled',
                            sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw),
                            **evaluate(parse(raw.decode('utf-8')))))
    report = dict(
        scope='Real captured traffic, evaluated as published Zeek flows; not packet-pipeline replay',
        attribution='Garcia, Parmisano and Erquiaga (2020), IoT-23, doi:10.5281/zenodo.4743746',
        method='Fixed previous thresholds; rolling 12 TCP flows per origin/responder/port; rejection window 60s; cooldown 600s. Only globally routable responders. No threshold tuning.',
        label_limit='Triggering flow labels are descriptive, not ground truth for a whole alert window. No precision or recall claimed.',
        captures=results,
        approved_rules=[],
        decisions={
            'regular_connections': 'HOLD: cadence is not malware ground truth; no representative Windows benign set or packet pipeline validation.',
            'tcp_rejection_burst': 'HOLD: no validated positive rejection scenario and CANA lacks matched flow outcomes.',
            'dns_resolver_policy_deviation': 'NOT EVALUABLE: conn logs lack DNS query evidence and no approved resolver policy exists.',
        },
        existing_live_rules='Not validated by this flow-only experiment; do not infer certification of existing rules.',
        runtime_changed=False,
    )
    out = ROOT / 'output' / 'real_traffic_validation.json'
    out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
