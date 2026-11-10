"""
explain.py
==========

Translate engine detection records into language a normal user can read.

The security engine keeps statistical reasons, IPs, protocols, and rule
ids. This module never changes those values; it only produces a parallel
user-facing view. Technical fields stay available under Details.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_TECHNICAL_WORDS = (
    "statistical outlier",
    "baseline mean",
    "std_dev",
    "standard deviation",
    "anomaly score",
    "feature vector",
    "isolation forest",
    "classifier",
    "threshold",
    "z-score",
    "packet size",
    "mean=",
    "std_dev=",
)

_UNKNOWN_APPS = frozenset({"", "unknown", "n/a", "none", "-", "null"})

_TAG_LABELS = {
    "LOCAL_NETWORK": "Local network",
    "UDP": "UDP traffic",
    "TCP": "TCP traffic",
    "MULTICAST": "Group network traffic",
    "BROADCAST": "Broadcast traffic",
    "INTERNET": "Internet",
    "ICMP": "Network ping",
    "ICMPV6": "Network ping",
    "HTTP": "Web traffic",
    "HTTPS": "Web traffic",
    "DNS": "Name lookup",
    "IDLE": "While idle",
}

_RULE_TITLES = {
    "inbound_tcp_port_probe": "Remote host probed many ports on this computer",
    "dns_failure_burst": "Many requested DNS names do not exist",
    "upload_heavy_transfer": "Large upload-heavy transfer to a public destination",
    "unusual_tcp_flags": "Unusual TCP control flags observed",
    "long_dns_query_burst": "Many distinct long DNS names requested",
    "public_legacy_service": "Potentially unencrypted Internet service contacted",
    "tcp_port_probe": "Rapid attempts to reach many network ports",
    "tcp_host_probe": "Rapid attempts to reach many devices",
    "internet_smb_attempt": "File-sharing connection attempted over the Internet",
    "packet_size_anomaly": "Packet size exceeded the learned range",
    "connection_rate_anomaly": "Packet rate exceeded the learned range",
    "idle_large_transfer": "Unusual network activity while this computer was idle",
    "unknown_application_internet": (
        "CANA detected network activity that could not be linked "
        "to a specific application"
    ),
}

_RULE_REASONS = {
    "inbound_tcp_port_probe": "One remote host attempted many ports on this computer. Authorized vulnerability scans can also cause this.",
    "dns_failure_burst": "Many distinct queries received a name-not-found response. Generated-domain malware, broken software, or DNS filtering are possible causes.",
    "upload_heavy_transfer": "Captured outgoing traffic to one public destination was large and greatly exceeded incoming traffic. Backups and file uploads can cause this too.",
    "unusual_tcp_flags": "The TCP control flags resemble crafted probes or malformed traffic. Authorized testing can cause this too.",
    "long_dns_query_burst": "Many different long DNS names were requested in a short period. Encoded data is one possibility; telemetry can look similar.",
    "public_legacy_service": "A connection was attempted on an Internet port commonly used by FTP or Telnet. Verify that the intended service protects sensitive data.",
    "tcp_port_probe": "This computer attempted many different ports on one device in a short period. Scanning and authorized discovery can cause this.",
    "tcp_host_probe": "This computer attempted the same port on many devices in a short period. Scanning and authorized discovery can cause this.",
    "internet_smb_attempt": "A connection was attempted to a public address on the port commonly used for SMB file sharing. Check whether that destination is expected.",
    "packet_size_anomaly": "An individual packet was larger than the range learned for this hour. This alone does not identify an attack.",
    "connection_rate_anomaly": "Packets were exchanged with a remote device faster than the range learned for this application and peer.",
}

_SEVERITY_NOTES = {
    "Low": (
        "This activity is unusual, but CANA does not currently "
        "see strong evidence that it is harmful."
    ),
    "Medium": (
        "This activity is more unusual than normal and may "
        "require your attention."
    ),
    "High": (
        "CANA detected behavior that is significantly different "
        "from normal activity and may indicate a security problem."
    ),
    "Critical": "CANA detected activity that requires immediate attention.",
}

_SEVERITY_ACTIONS = {
    "Low": (
        "No action is required unless you recognize other unusual behavior."
    ),
    "Medium": (
        "If you do not recognize the related application or activity, "
        "you can investigate further."
    ),
    "High": (
        "Review the related application. If you do not recognize it, "
        "stop it and investigate further."
    ),
    "Critical": "This activity requires immediate attention.",
}


def looks_technical(text: str) -> bool:
    """True when a string is engine jargon, not a user-facing sentence."""
    lowered = str(text or "").lower()
    if not lowered.strip():
        return False
    if any(word in lowered for word in _TECHNICAL_WORDS):
        return True
    if _IPV4.search(text) or _IPV6.search(text):
        return True
    if " -> " in text or "bytes transferred" in lowered:
        return True
    return False


def known_application_name(value: Any) -> str:
    """Return a display name only when the engine actually identified one."""
    text = str(value or "").strip()
    if text.lower() in _UNKNOWN_APPS:
        return ""
    if text.endswith(".exe"):
        return text[:-4]
    return text


def friendly_tag(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    mapped = _TAG_LABELS.get(raw) or _TAG_LABELS.get(raw.upper())
    if mapped:
        return mapped
    if raw.lower().startswith("user "):
        return raw.replace("_", " ")
    if looks_technical(raw) or _IPV4.search(raw) or _IPV6.search(raw):
        return ""
    return raw.replace("_", " ")


def friendly_tags(values: List[Any]) -> List[str]:
    seen = []
    for value in values or []:
        label = friendly_tag(value)
        if label and label not in seen:
            seen.append(label)
    return seen


def severity_note(severity: str) -> str:
    return _SEVERITY_NOTES.get(str(severity or "Low"), _SEVERITY_NOTES["Low"])


def recommended_action(severity: str) -> str:
    return _SEVERITY_ACTIONS.get(str(severity or "Low"), _SEVERITY_ACTIONS["Low"])


def _title_for(rule: str, application: str, reason: str) -> str:
    app = known_application_name(application)
    mapped = _RULE_TITLES.get(rule)
    if mapped:
        if rule in {'tcp_port_probe', 'tcp_host_probe', 'inbound_tcp_port_probe',
                    'long_dns_query_burst', 'dns_failure_burst'}:
            return mapped
        return f"{app[0].upper() + app[1:]}: {mapped}" if app else mapped
    if app and rule != "unknown_application_internet":
        pretty = app[0].upper() + app[1:] if app else app
        return f"{pretty} generated unusual network activity"
    if reason and not looks_technical(reason) and len(reason) <= 80:
        return reason.rstrip(".")
    return "Unusual network activity detected"


def _why_for(rule: str, application: str) -> str:
    app = known_application_name(application)
    if rule in _RULE_REASONS:
        return _RULE_REASONS[rule]
    if rule == "unknown_application_internet":
        return (
            "CANA detected network activity that could not be linked "
            "to a specific application."
        )
    if rule == "idle_large_transfer":
        return (
            "This computer sent or received more data than usual while "
            "it appeared to be idle."
        )
    if app:
        return (
            f"{app} produced network activity that is different from the "
            "normal pattern CANA has learned for this computer."
        )
    return (
        "Network activity was different from the normal pattern "
        "CANA has learned for this computer."
    )


def technical_lines(alert: Dict[str, Any]) -> List[str]:
    """Preserve engine fields for View technical details."""
    lines: List[str] = []
    mapping = (
        ("reason", "Detection reason"),
        ("rule_name", "Detection rule"),
        ("severity", "Severity"),
        ("application_name", "Application"),
        ("protocol", "Protocol"),
        ("application_protocol", "Application protocol"),
        ("communication_type", "Communication type"),
        ("source_ip", "Source"),
        ("destination_ip", "Destination"),
        ("source_port", "Source port"),
        ("destination_port", "Destination port"),
        ("direction", "Direction"),
        ("tcp_flags", "TCP flags"),
        ("dns_query_name", "DNS name"),
        ("dns_rcode", "DNS response code"),
        ("packet_size", "Packet size"),
        ("risk_score", "Risk score"),
        ("triggered_at", "Time"),
        ("triggered_at_epoch", "Timestamp"),
    )
    for key, label in mapping:
        value = alert.get(key)
        if value in (None, "", []):
            continue
        lines.append(f"{label}: {value}")
    return lines


def explain_alert(alert: Dict[str, Any], severity: str = "") -> Dict[str, str]:
    """User-facing title, why, action, plus the original technical reason."""
    rule = str(alert.get("rule_name") or alert.get("rule") or "")
    reason = str(alert.get("reason") or "").strip()
    application = str(alert.get("application_name") or "")
    level = severity or str(alert.get("severity") or "Low")
    title = _title_for(rule, application, reason)
    return {
        "title": title,
        "summary": _why_for(rule, application),
        "why": _why_for(rule, application),
        "action": recommended_action(level),
        "severity_note": severity_note(level),
        "technical": reason,
    }


def format_technical_details(alert: Dict[str, Any]) -> str:
    lines = technical_lines(alert)
    return "\n".join(lines) if lines else "No technical details are available."


def learning_status(payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """First-run copy when CANA does not yet have enough history."""
    if "baseline" not in payload:
        return None
    baseline = payload.get("baseline") or {}
    observations = int(baseline.get("observations") or 0)
    established = int(baseline.get("established_buckets") or 0)
    health = payload.get("health") or {}
    apps = int(
        health.get("applications_observed")
        or payload.get("applications_observed")
        or 0
    )
    if established > 0 or observations >= 50:
        return None
    return {
        "title": "CANA is learning your normal network activity",
        "subtitle": (
            "CANA needs some time to understand the applications and "
            "network behavior normally seen on this computer."
        ),
        "apps": str(apps),
        "observations": str(observations),
    }


__all__ = [
    "explain_alert",
    "format_technical_details",
    "friendly_tag",
    "friendly_tags",
    "known_application_name",
    "learning_status",
    "looks_technical",
    "recommended_action",
    "severity_note",
    "technical_lines",
]
