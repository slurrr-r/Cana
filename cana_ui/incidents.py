"""
incidents.py
============

Derives the Alerts page model from CANA's persisted alert and
correlation records.

Everything here is a *derivation* of data the engine already stores
(``triggered_alerts`` and ``correlated_alerts``). Nothing is invented:

* **Alert name** - a user-facing title from :func:`cana_ui.explain.explain_alert`.
  The original engine ``reason`` is kept on the incident for technical details.
* **Severity** - the stored severity, normalized to High/Medium/Low.
* **Status** - Window closed for a matching stored correlation; otherwise
  Unknown. Closing an observation window does not prove remediation.
* **Tags** - real per-alert attributes (application-layer protocol,
  communication type) presented as chips.
* **KPIs** - counted from real records, except "Avg. time to detect",
  which the engine does not measure; that card reports
  :data:`NOT_TRACKED` instead of a fabricated duration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from cana_ui.explain import explain_alert, friendly_tags, known_application_name
from cana_ui.traffic import parse_packet_epoch

NOT_TRACKED = "—"

SEVERITY_LABELS = {
    "HIGH": "High",
    "CRITICAL": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
}

SEVERITY_FILTERS = ("All", "High", "Medium", "Low")
STATUS_FILTERS = ("All", "Window closed", "Unknown")


def severity_label(severity: Any) -> str:
    return SEVERITY_LABELS.get(str(severity or "").upper(), "Low")


def severity_rank(severity: Any) -> int:
    return {"High": 3, "Medium": 2, "Low": 1}.get(severity_label(severity), 0)


def humanize_rule(rule: Any) -> str:
    text = str(rule or "").replace("_", " ").strip()
    if not text:
        return "Network activity was flagged by a detection rule"
    return text[0].upper() + text[1:]


@dataclass
class Incident:
    """One row of the Alerts table."""

    key: str
    name: str
    severity: str
    status: str
    first_seen_epoch: Optional[float]
    tags: List[str] = field(default_factory=list)
    rule_name: str = ""
    application_name: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    count: int = 1
    reason: str = ""
    title: str = ""
    why: str = ""
    action: str = ""
    severity_note: str = ""
    summary: str = ""
    technical: str = ""

    @property
    def sort_key(self) -> float:
        return self.first_seen_epoch or 0.0


def _correlation_windows(correlated: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    windows = []
    for entry in correlated or []:
        start = parse_packet_epoch(entry.get("started_at_epoch") or entry.get("started_at"))
        end = parse_packet_epoch(entry.get("ended_at_epoch") or entry.get("ended_at"))
        if start is None:
            continue
        windows.append({"start": start, "end": end if end is not None else start, "entry": entry})
    return windows


def _status_for(epoch: Optional[float], windows: List[Dict[str, Any]], now: float,
                alert: Optional[Dict[str, Any]] = None) -> str:
    """
    Status derived from the correlation window that covers the alert.

    Match application, peer, rule and time; persisted windows do not prove resolution.
    """
    if epoch is None or alert is None:
        return "Unknown"
    direction = alert.get('direction')
    peer = alert.get('source_ip') if direction == 'INCOMING' else alert.get('destination_ip')
    if direction not in {'INCOMING', 'OUTGOING'} or not peer:
        return 'Unknown'
    covering = [w for w in windows if w['start'] <= epoch <= w['end']
                and w['end'] <= now
                and w['entry'].get('application_name') == alert.get('application_name')
                and w['entry'].get('destination_ip') == peer
                and alert.get('rule_name') in w['entry'].get('rule_names', [])]
    if not covering:
        return "Unknown"
    return "Window closed"


def _tags_for(alert: Dict[str, Any]) -> List[str]:
    raw: List[str] = []
    app_proto = str(alert.get("application_protocol") or "").strip()
    if app_proto:
        raw.append(app_proto)
    comm = str(alert.get("communication_type") or "").strip()
    if comm:
        raw.append(comm)
    transport = str(alert.get("protocol") or "").strip().upper()
    if transport and transport not in {t.upper() for t in raw}:
        raw.append(transport)
    user_status = str(alert.get("user_status") or "").strip()
    if user_status:
        raw.append(f"user {user_status.lower()}")
    return friendly_tags(raw)


def _incident_key(alert: Dict[str, Any]) -> str:
    rule = str(alert.get("rule_name") or "")
    app = str(alert.get("application_name") or "")
    source = str(alert.get("source_ip") or "")
    destination = str(alert.get("destination_ip") or "")
    direction = alert.get("direction")
    if direction == "INCOMING":
        target = source
    elif direction == "OUTGOING":
        target = destination
    else:
        # Older stored alerts lack direction; preserve both endpoints rather than guess.
        target = f"{source}>{destination}"
    return f"{rule}|{app}|{target}"


def build_incidents(
    alerts: List[Dict[str, Any]],
    correlated: Optional[List[Dict[str, Any]]] = None,
    now: Optional[float] = None,
) -> List[Incident]:
    """
    Group alerts into table rows.

    Alerts that share a rule, application, and peer are collapsed into a
    single incident carrying a count, which is what makes the table
    readable instead of one row per packet-level trigger.
    """
    import time as _time

    moment = now if now is not None else _time.time()
    windows = _correlation_windows(correlated or [])
    grouped: Dict[str, Incident] = {}

    for alert in alerts or []:
        key = _incident_key(alert)
        epoch = parse_packet_epoch(alert.get("triggered_at_epoch") or alert.get("triggered_at"))
        severity = severity_label(alert.get("severity"))
        status = _status_for(epoch, windows, moment, alert)
        existing = grouped.get(key)
        if existing is None:
            explained = explain_alert(alert, severity)
            application = known_application_name(alert.get("application_name"))
            grouped[key] = Incident(
                key=key,
                name=explained["title"],
                severity=severity,
                status=status,
                first_seen_epoch=epoch,
                tags=_tags_for(alert),
                rule_name=str(alert.get("rule_name") or ""),
                application_name=application,
                source_ip=str(alert.get("source_ip") or ""),
                destination_ip=str(alert.get("destination_ip") or ""),
                count=1,
                reason=str(alert.get("reason") or ""),
                title=explained["title"],
                why=explained["why"],
                action=explained["action"],
                severity_note=explained["severity_note"],
                summary=explained["summary"],
                technical=explained["technical"],
            )
        else:
            existing.count += 1
            if epoch is not None:
                if existing.first_seen_epoch is None or epoch > existing.first_seen_epoch:
                    existing.first_seen_epoch = epoch
            # A later, higher-severity trigger upgrades the row.
            if severity_rank(severity) > severity_rank(existing.severity):
                existing.severity = severity
            if epoch == existing.first_seen_epoch:
                existing.status = status

    return sorted(grouped.values(), key=lambda item: item.sort_key, reverse=True)


def filter_incidents(
    incidents: List[Incident],
    *,
    severity: str = "All",
    status: str = "All",
    search: str = "",
) -> List[Incident]:
    """Apply the toolbar filters to the incident list."""
    query = str(search or "").strip().lower()
    result = []
    for incident in incidents:
        if severity != "All" and incident.severity != severity:
            continue
        if status != "All" and incident.status != status:
            continue
        if query:
            haystack = " ".join(
                [
                    incident.name,
                    incident.severity,
                    incident.status,
                    incident.application_name,
                    incident.source_ip,
                    incident.destination_ip,
                    incident.rule_name,
                    " ".join(incident.tags),
                ]
            ).lower()
            if query not in haystack:
                continue
        result.append(incident)
    return result


def alerts_this_week(alerts: List[Dict[str, Any]], now: float) -> int:
    cutoff = now - 7 * 86400
    total = 0
    for alert in alerts or []:
        epoch = parse_packet_epoch(alert.get("triggered_at_epoch") or alert.get("triggered_at"))
        if epoch is not None and epoch >= cutoff:
            total += 1
    return total


def devices_flagged(alerts: List[Dict[str, Any]]) -> int:
    peers = {
        str(alert.get("source_ip")).strip()
        for alert in alerts or []
        if str(alert.get("source_ip") or "").strip()
    }
    return len(peers)


def auto_resolved(correlated: List[Dict[str, Any]], now: float) -> int:
    """
    Correlated incidents whose detection window has already closed.

    This is the only "resolved" signal CANA records - it has no manual
    acknowledgement or ticket state - so it is reported as-is.
    """
    total = 0
    for window in _correlation_windows(correlated or []):
        if window["end"] < now:
            total += 1
    return total


def build_kpis(
    alerts: List[Dict[str, Any]],
    correlated: Optional[List[Dict[str, Any]]] = None,
    now: Optional[float] = None,
) -> List[Dict[str, str]]:
    """
    The four KPI cards, in mockup order.

    ``Avg. time to detect`` is reported as :data:`NOT_TRACKED` because
    the engine does not measure detection latency; showing a number here
    would mean inventing one.
    """
    import time as _time

    moment = now if now is not None else _time.time()
    return [
        {"label": "Alerts this week", "value": str(alerts_this_week(alerts or [], moment))},
        {"label": "Auto-resolved", "value": str(auto_resolved(correlated or [], moment))},
        {"label": "Devices flagged", "value": str(devices_flagged(alerts or []))},
        {"label": "Avg. time to detect", "value": NOT_TRACKED},
    ]


__all__ = [
    "Incident",
    "NOT_TRACKED",
    "SEVERITY_FILTERS",
    "STATUS_FILTERS",
    "alerts_this_week",
    "auto_resolved",
    "build_incidents",
    "build_kpis",
    "devices_flagged",
    "filter_incidents",
    "humanize_rule",
    "severity_label",
    "severity_rank",
]
