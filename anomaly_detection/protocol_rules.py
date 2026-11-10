"""Explainable metadata checks; findings describe evidence, not confirmed attacks."""

from collections import OrderedDict
from ipaddress import ip_address
import time

from anomaly_detection.rules import RuleResult


class ProtocolDetector:
    WINDOW_SECONDS = 60
    DNS_DISTINCT_QUERIES = 20
    MAX_GROUPS = 1024

    def __init__(self):
        self._dns = OrderedDict()
        self._alerts = OrderedDict()

    def evaluate(self, context):
        names = ('unusual_tcp_flags', 'long_dns_query_burst', 'public_legacy_service')
        results = {name: RuleResult(name, False, 'LOW',
                   'No qualifying protocol evidence.', context) for name in names}
        if context.direction not in {'OUTGOING', 'INCOMING'}:
            return list(results.values())
        try:
            source = ip_address(context.source_ip)
            destination = ip_address(context.destination_ip)
        except (ValueError, TypeError):
            return list(results.values())
        if any(ip.is_multicast or ip.is_unspecified or ip.is_loopback
               for ip in (source, destination)):
            return list(results.values())
        now = time.monotonic()

        def flag(name, reason, severity='MEDIUM'):
            key = (name, str(source), str(destination))
            previous = self._alerts.get(key, float('-inf'))
            if now - previous < self.WINDOW_SECONDS:
                return
            self._alerts.pop(key, None)
            self._alerts[key] = now
            while len(self._alerts) > self.MAX_GROUPS:
                self._alerts.popitem(last=False)
            results[name] = RuleResult(name, True, severity, reason, context)

        flags = context.tcp_flags
        if context.protocol == 'TCP' and isinstance(flags, str):
            bits = set(flags)
            pattern = None
            if 'S' in bits and 'F' in bits:
                pattern = 'SYN and FIN together (start and finish requested together)'
            elif 'S' in bits and 'R' in bits:
                pattern = 'SYN and RST together (start and reset requested together)'
            elif not bits:
                pattern = 'no TCP control flags (NULL-style packet)'
            elif bits == {'F', 'P', 'U'}:
                pattern = 'FIN, PSH and URG only (Xmas-style packet)'
            if pattern:
                flag(names[0], f'{context.direction} TCP packet {source} -> {destination} '
                     f'has {pattern}. This can indicate crafted probing or malformed traffic; '
                     'authorized testing and capture artifacts are also possible.')
            port = context.destination_port
            if (context.direction == 'OUTGOING' and destination.is_global
                    and isinstance(port, int) and not isinstance(port, bool)
                    and port in (21, 23) and 'S' in bits and not bits & set('ARF')):
                service = 'FTP control' if port == 21 else 'Telnet'
                flag(names[2], f'Outbound TCP attempt to {destination}:{port}, commonly {service}. '
                     'This service commonly uses unencrypted communication. Verify the intended '
                     'service and encryption; the port alone does not prove plaintext credentials '
                     'or a successful login.')

        query = context.dns_query_name
        if (context.direction == 'OUTGOING' and context.protocol in {'TCP', 'UDP'}
                and context.application_protocol == 'DNS' and context.dns_is_response is False
                and isinstance(query, str)):
            query = query.rstrip('.').lower()
            labels = query.split('.')
            if (0 < len(query) <= 253 and all(0 < len(label) <= 63 for label in labels)
                    and (len(query) >= 100 or max(map(len, labels)) >= 50)):
                key = (str(source), str(destination))
                queries = self._dns.pop(key, OrderedDict())
                while queries and next(iter(queries.values())) <= now - self.WINDOW_SECONDS:
                    queries.popitem(last=False)
                queries.pop(query, None)
                queries[query] = now
                while len(queries) > self.DNS_DISTINCT_QUERIES:
                    queries.popitem(last=False)
                self._dns[key] = queries
                while len(self._dns) > self.MAX_GROUPS:
                    self._dns.popitem(last=False)
                if len(queries) >= self.DNS_DISTINCT_QUERIES:
                    flag(names[1], f'At least {len(queries)} distinct long DNS query names from '
                         f'{source} to resolver {destination} in {self.WINDOW_SECONDS}s. '
                         'Each name has at least 100 characters or a label of at least 50. '
                         'This may resemble data encoded in DNS; telemetry and security software '
                         'can also generate long names. This does not confirm DNS tunneling.')
        return list(results.values())
