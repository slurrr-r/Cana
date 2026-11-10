"""Bounded, live TCP attempt tracking; no payload inspection or attack traffic."""

from collections import OrderedDict
from ipaddress import ip_address
import time

from anomaly_detection.rules import RuleResult


class ProbingDetector:
    WINDOW_SECONDS = 60.0
    DISTINCT_TARGETS = 20
    MAX_GROUPS = 2048

    def __init__(self):
        self._groups = OrderedDict()

    def evaluate(self, context):
        names = ("tcp_port_probe", "tcp_host_probe", "internet_smb_attempt",
                 "inbound_tcp_port_probe")
        results = {name: RuleResult(name, False, "LOW",
                   "No qualifying TCP attempt.", context) for name in names}
        flags = context.tcp_flags or ""
        port = context.destination_port
        if (context.direction not in {"OUTGOING", "INCOMING"} or context.protocol != "TCP"
                or not isinstance(flags, str)
                or "S" not in flags or any(flag in flags for flag in "ARF")
                or not isinstance(port, int) or isinstance(port, bool)
                or not 1 <= port <= 65535):
            return list(results.values())
        try:
            destination = ip_address(context.destination_ip)
            source_address = ip_address(context.source_ip)
            source = str(source_address)
        except (ValueError, TypeError):
            return list(results.values())
        if destination.is_multicast or destination.is_unspecified or destination.is_loopback:
            return list(results.values())
        if (context.direction == "INCOMING" and
                (source_address.is_multicast or source_address.is_unspecified
                 or source_address.is_loopback)):
            return list(results.values())

        if context.direction == "OUTGOING" and port == 445 and destination.is_global:
            results[names[2]] = RuleResult(names[2], True, "MEDIUM",
                f"Outbound TCP connection attempt to public address {destination}:445 "
                "(commonly SMB). Check whether this file-sharing destination is expected; "
                "a port number does not prove the service or a successful connection.", context)

        now = time.monotonic()
        cutoff = now - self.WINDOW_SECONDS
        observations = (
            (names[0], str(destination), port),
            (names[1], port, str(destination)),
        ) if context.direction == "OUTGOING" else (
            (names[3], str(destination), port),
        )
        # Each group retains at most the trigger count of recent distinct targets.
        for name, scope, target in observations:
            key = (name, source, scope)
            targets, last_alert = self._groups.pop(key, (OrderedDict(), float("-inf")))
            while targets and next(iter(targets.values())) <= cutoff:
                targets.popitem(last=False)
            targets.pop(target, None)
            targets[target] = now
            if len(targets) > self.DISTINCT_TARGETS:
                targets.popitem(last=False)
            triggered = len(targets) >= self.DISTINCT_TARGETS and now - last_alert >= self.WINDOW_SECONDS
            detail = (f"ports on {destination}" if name != names[1]
                      else f"hosts on TCP port {port}")
            results[name] = RuleResult(name, triggered, "HIGH" if triggered else "LOW",
                f"Observed {len(targets)} distinct {detail} attempted by {source} "
                f"within {self.WINDOW_SECONDS:.0f}s (trigger: {self.DISTINCT_TARGETS}). "
                "Repeated attempts to the same target count once. This resembles probing; "
                "authorized scanners and discovery tools can also cause it.", context)
            self._groups[key] = (targets, now if triggered else last_alert)
            while len(self._groups) > self.MAX_GROUPS:
                self._groups.popitem(last=False)
        return list(results.values())
