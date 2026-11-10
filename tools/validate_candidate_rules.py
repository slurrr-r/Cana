"""Offline hypothesis checks only. No capture, traffic generation, or live rule integration."""
import json
from pathlib import Path
from statistics import mean, pstdev


def regular_connections(times):
    if len(times) < 12 or times[-1] - times[0] < 600:
        return False
    gaps = [b - a for a, b in zip(times, times[1:])]
    return min(gaps) > 0 and pstdev(gaps) / mean(gaps) <= 0.1


def rejected_connections(flows):
    # Input is already matched flow evidence; CANA does not yet produce these states.
    unique = {identity: state for identity, state in flows}
    answered = [state for state in unique.values() if state in {'rejected', 'established'}]
    failures = answered.count('rejected')
    return failures >= 30 and failures / len(answered) >= 0.8


def resolver_policy(destination, approved, confirmed_outbound_dns):
    if not approved or not confirmed_outbound_dns:
        return None  # Unknown, not evidence of a violation.
    return destination not in approved


def validate():
    cases = []
    def check(name, actual, expected):
        assert actual == expected, (name, actual, expected)
        cases.append(dict(name=name, result=actual, expected=expected, passed=True))

    cadence = [i * 600 for i in range(12)]
    check('synthetic_regular_connection_pattern', regular_connections(cadence), True)
    check('benign_scheduled_health_checks_same_pattern', regular_connections(cadence), True)
    check('too_few_connections', regular_connections(cadence[:4]), False)
    check('irregular_connections', regular_connections([0, 10, 50, 160, 300, 301, 900, 1000, 1700, 2400, 2401, 3600]), False)
    check('duplicate_timestamps_not_independent_connections', regular_connections([0] * 11 + [600]), False)
    rejected = [(i, 'rejected') for i in range(30)]
    check('rejection_burst', rejected_connections(rejected), True)
    check('benign_broken_client_same_rejection_pattern', rejected_connections(rejected), True)
    check('retransmissions_not_distinct_attempts', rejected_connections([(1, 'rejected')] * 100), False)
    check('unanswered_is_not_explicitly_rejected', rejected_connections([(i, 'unanswered') for i in range(100)]), False)
    check('normal_successes_reduce_rejection_ratio', rejected_connections(rejected + [(i, 'established') for i in range(30, 100)]), False)
    check('below_rejection_count', rejected_connections(rejected[:29]), False)
    check('resolver_without_policy', resolver_policy('8.8.8.8', set(), True), None)
    check('approved_resolver', resolver_policy('8.8.8.8', {'8.8.8.8'}, True), False)
    check('unapproved_plain_dns_resolver', resolver_policy('1.1.1.1', {'8.8.8.8'}, True), True)
    check('https_is_not_proof_of_dns', resolver_policy('1.1.1.1', {'8.8.8.8'}, False), None)

    report = {
        'scope': 'Synthetic offline hypothesis validation; not production detector implementation',
        'thresholds': 'Experimental choices, not values endorsed by the cited experts',
        'cases': cases,
        'real_traffic_tested': False,
        'human_review_performed': False,
        'live_detector_changed': False,
        'candidates': [
            {'name': 'regular_outbound_connections', 'decision': 'Do not enable as standalone attack detection',
             'reason': 'Identical cadence flags benign health checks; process/peer context and real benign validation required.',
             'telemetry_gap': 'Need event-time flow observations, SYN retransmission deduplication and stable process identity.',
             'source': 'https://www.elastic.co/security-labs/blog/identifying-beaconing-malware-using-elastic',
             'authors': ['Apoorva Joshi', 'Thomas Veasey', 'Craig Chamberlain']},
            {'name': 'tcp_rejection_burst', 'decision': 'Candidate operational anomaly; not validated for live integration',
             'reason': 'Broken clients also trigger. Need matched SYN/RST evidence and real traffic validation; never label brute force.',
             'telemetry_gap': 'Context drops TCP sequence/ack numbers and has no connection outcome tracker.',
             'source': 'https://docs.zeek.org/en/v7.1.1/scripts/base/protocols/conn/main.zeek.html'},
            {'name': 'dns_resolver_policy_deviation', 'decision': 'Requires explicitly configured resolver policy before integration',
             'reason': 'No policy means unknown. Public DNS is not inherently malicious; HTTPS alone cannot establish DoH.',
             'telemetry_gap': 'No approved resolver policy or VPN/network-change handling configured.',
             'source': 'https://media.defense.gov/2021/Jan/14/2002564889/-1/-1/0/CSI_ADOPTING_ENCRYPTED_DNS_U_OO_102904_21.PDF'},
        ],
        'release_gate': [
            'Preserve capture timestamps and connection identity; test retries, IPv6, missing packets and restarts.',
            'Replay labelled positive samples and separate representative benign Windows traffic without transmitting them.',
            'Measure missed cases and false alerts per host-day on held-out data; do not tune and score on the same traces.',
            'Demonstrate bounded memory, duplicate suppression, persistence and truthful UI explanations.',
            'Only then integrate the candidate; no automatic blocking from these patterns.',
        ],
    }
    output = Path(__file__).resolve().parents[1] / 'output' / 'candidate_rule_validation.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'{len(cases)} synthetic checks passed; 0 new rules approved for live integration. Report: {output}')


if __name__ == '__main__':
    validate()
