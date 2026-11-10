"""
utils.py
========

Console formatting for Module 4 alerts.
"""

from __future__ import annotations

import time

from anomaly_detection.rules import RuleResult

_RULE_DISPLAY_NAMES = {
    "inbound_tcp_port_probe": "Remote host probed many local ports",
    "dns_failure_burst": "Many DNS names do not exist",
    "upload_heavy_transfer": "Large upload-heavy transfer",
    "unusual_tcp_flags": "Unusual TCP control flags observed",
    "long_dns_query_burst": "Many distinct long DNS names requested",
    "public_legacy_service": "Potentially unencrypted Internet service contacted",
    "tcp_port_probe": "Rapid attempts to reach many network ports",
    "tcp_host_probe": "Rapid attempts to reach many devices",
    "internet_smb_attempt": "File-sharing connection attempted over the Internet",
    "idle_large_transfer": "Large data transfer while idle",
    "unknown_application_internet": "Unknown application on the internet",
    "packet_size_anomaly": "Unusual packet size",
    "connection_rate_anomaly": "Unusual connection rate",
}


def format_alert(result: RuleResult) -> str:
    """
    Build a clean, human-readable alert block for one triggered rule.

    Example output::

        [ALERT - MEDIUM] Large data transfer while idle
        Reason: 150000000 bytes transferred while idle for 320s - ...
        App: chrome.exe | 10.0.0.5 -> 93.184.216.34

    Args:
        result: A triggered ``RuleResult`` (see ``rules.py``).

    Returns:
        A formatted, multi-line alert block.
    """
    display_name = _RULE_DISPLAY_NAMES.get(result.rule_name, result.rule_name)
    time_part = time.strftime(
        "%H:%M:%S", time.localtime(result.context.timestamp)
    )

    return (
        f"\n[{time_part}] [ALERT - {result.severity}] {display_name}\n"
        f"Reason: {result.reason}\n"
        f"App: {result.context.application_name} | "
        f"{result.context.source_ip} -> {result.context.destination_ip}\n"
    )
