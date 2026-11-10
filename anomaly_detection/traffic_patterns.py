"""Bounded DNS failure and directional traffic evidence for investigation."""

from collections import OrderedDict
from ipaddress import ip_address
import time

from anomaly_detection.rules import RuleResult


class TrafficPatternDetector:
    MAX_GROUPS = 1024
    MAX_PENDING = 4096
    DNS_WINDOW = 60
    DNS_MIN_FAILURES = 30
    DNS_FAILURE_RATIO = 0.8
    UPLOAD_WINDOW = 300
    UPLOAD_MIN_BYTES = 50 * 1024 * 1024
    UPLOAD_RATIO = 5

    def __init__(self):
        self._pending = OrderedDict()
        self._dns = OrderedDict()
        self._transfers = OrderedDict()

    def evaluate(self, context):
        results = [RuleResult(name, False, 'LOW', 'Insufficient qualifying evidence.', context)
                   for name in ('dns_failure_burst', 'upload_heavy_transfer')]
        if context.direction not in {'INCOMING', 'OUTGOING'} or context.protocol not in {'TCP', 'UDP'}:
            return results
        try:
            src, dst = ip_address(context.source_ip), ip_address(context.destination_ip)
        except (ValueError, TypeError):
            return results
        if any(ip.is_multicast or ip.is_unspecified or ip.is_loopback for ip in (src, dst)):
            return results
        outgoing = context.direction == 'OUTGOING'
        local, remote = (str(src), str(dst)) if outgoing else (str(dst), str(src))
        now = time.monotonic()
        results[0] = self._dns_result(context, local, remote, outgoing, now, results[0])
        size = context.packet_size
        if not (dst if outgoing else src).is_global or not isinstance(size, int) or not 0 < size <= 262144:
            return results
        key = (local, remote, context.application_name)
        buckets, last_alert = self._transfers.pop(key, (OrderedDict(), float('-inf')))
        # shortcut: five-second buckets undercount by up to five seconds; use flow telemetry for exact accounting.
        tick = int(now // 5) * 5
        while buckets and next(iter(buckets)) <= now - self.UPLOAD_WINDOW:
            buckets.popitem(last=False)
        counts = buckets.setdefault(tick, [0, 0])
        counts[0 if outgoing else 1] += size
        sent = sum(value[0] for value in buckets.values())
        received = sum(value[1] for value in buckets.values())
        if (outgoing and now - next(iter(buckets)) >= 65
                and sent >= self.UPLOAD_MIN_BYTES and sent >= self.UPLOAD_RATIO * max(received, 1)
                and now - last_alert >= self.UPLOAD_WINDOW):
            results[1] = RuleResult('upload_heavy_transfer', True, 'MEDIUM',
                f'{context.application_name} exchanged {sent} outbound and {received} inbound captured bytes '
                f'with {remote} over up to {self.UPLOAD_WINDOW}s. Outbound volume is at least {self.UPLOAD_MIN_BYTES} bytes '
                f'and {self.UPLOAD_RATIO} times inbound volume. Backups and file uploads can cause this; '
                'this is not proof of data theft. Headers and retransmissions are included.', context)
            last_alert = now
        self._transfers[key] = (buckets, last_alert)
        while len(self._transfers) > self.MAX_GROUPS:
            self._transfers.popitem(last=False)
        return results

    def _dns_result(self, context, local, remote, outgoing, now, result):
        query = context.dns_query_name
        if context.application_protocol != 'DNS' or not isinstance(query, str):
            return result
        query = query.lower().rstrip('.')
        if not 0 < len(query) <= 253 or not all(0 < len(label) <= 63 for label in query.split('.')):
            return result
        port = context.source_port if outgoing else context.destination_port
        server_port = context.destination_port if outgoing else context.source_port
        if not (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
                and server_port == 53 and isinstance(context.dns_id, int)
                and not isinstance(context.dns_id, bool) and 0 <= context.dns_id <= 65535):
            return result
        while self._pending and next(iter(self._pending.values())) <= now - self.DNS_WINDOW:
            self._pending.popitem(last=False)
        if not all(isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535
                   for value in (context.dns_qtype, context.dns_qclass)):
            return result
        key = (local, remote, context.protocol, port, context.dns_id, query,
               context.dns_qtype, context.dns_qclass)
        if outgoing and context.dns_is_response is False:
            self._pending.pop(key, None)
            self._pending[key] = now
            while len(self._pending) > self.MAX_PENDING:
                self._pending.popitem(last=False)
        elif not outgoing and context.dns_is_response is True:
            if (not isinstance(context.dns_rcode, int) or isinstance(context.dns_rcode, bool)
                    or not 0 <= context.dns_rcode <= 15 or self._pending.pop(key, None) is None):
                return result
            group = (local, remote)
            names, last_alert = self._dns.pop(group, (OrderedDict(), float('-inf')))
            while names and next(iter(names.values()))[0] <= now - self.DNS_WINDOW:
                names.popitem(last=False)
            names.pop(query, None)
            names[query] = (now, context.dns_rcode == 3)
            # shortcut: ratio uses the latest 256 distinct names; use resolver logs for exhaustive DNS analytics.
            while len(names) > 256:
                names.popitem(last=False)
            failures = sum(value[1] for value in names.values())
            if (failures >= self.DNS_MIN_FAILURES and failures / len(names) >= self.DNS_FAILURE_RATIO
                    and now - last_alert >= self.DNS_WINDOW):
                result = RuleResult('dns_failure_burst', True, 'MEDIUM',
                    f'{failures}/{len(names)} distinct names received NXDOMAIN from {remote} '
                    f'within {self.DNS_WINDOW}s after matching observed queries from {local}. '
                    'These names do not exist according to this resolver. Generated-domain malware, '
                    'broken software, and DNS filtering can cause this; malware is not confirmed.', context)
                last_alert = now
            self._dns[group] = (names, last_alert)
            while len(self._dns) > self.MAX_GROUPS:
                self._dns.popitem(last=False)
        return result
