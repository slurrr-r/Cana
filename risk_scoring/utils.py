"""
utils.py
========

Console formatting for Module 5: risk leaderboards and correlated
alerts. Mirrors the style of ``anomaly_detection/utils.py``.
"""

from __future__ import annotations

import time

from risk_scoring.config import RISK_DEFAULT_TOP_N
from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.scorer import RiskEntry, RiskSnapshot


def format_risk_entry(entry: RiskEntry) -> str:
    """
    Format one leaderboard entry.

    Example output::

        chrome.exe                12.4  (7 event(s))
    """
    return f"{entry.name:<28} {entry.score:>7.1f}  ({entry.events} event(s))"


def format_risk_summary(
    snapshot: RiskSnapshot, top_n: int = RISK_DEFAULT_TOP_N
) -> str:
    """
    Build a console block showing the current top risk entities.

    Example output::

        Top applications by risk
        ----------------------------------
        chrome.exe                12.4  (7 event(s))
        ...

    Args:
        snapshot: The risk snapshot to display.
        top_n: How many entries of each kind to show.

    Returns:
        A multi-line string (no trailing blank lines).
    """
    lines: list = []
    limit = top_n if top_n is not None else len(snapshot.applications)

    lines.append("Top applications by risk")
    lines.append("-" * 40)
    if snapshot.applications:
        lines.extend(format_risk_entry(e) for e in snapshot.applications[:limit])
    else:
        lines.append("(no risk recorded yet)")
    lines.append("")
    lines.append("Top remote peers by risk")
    lines.append("-" * 40)
    if snapshot.destinations:
        lines.extend(format_risk_entry(e) for e in snapshot.destinations[:limit])
    else:
        lines.append("(no risk recorded yet)")
    return "\n".join(lines)


def format_correlated_alert(alert: CorrelatedAlert) -> str:
    """
    Build a clean, human-readable block for one correlated alert.

    Example output::

        [20:15:03] [CORRELATED - HIGH] 3 suspicious signals for ...
        Reason: 3 suspicious signal(s) for chrome.exe -> ...: ...
        App: chrome.exe | 10.0.0.5 -> 93.184.216.34
        Signals: connection_rate_anomaly, unknown_application_internet
        Confidence: 0.75

    Args:
        alert: The correlated alert to format.

    Returns:
        A formatted, multi-line alert block.
    """
    time_part = time.strftime("%H:%M:%S", time.localtime(alert.ended_at))
    target = (
        alert.application_name
        if alert.destination_ip is None
        else f"{alert.application_name} | {alert.destination_ip}"
    )
    return (
        f"\n[{time_part}] [CORRELATED - {alert.severity}] "
        f"{alert.signal_count} suspicious signal(s) for "
        f"{alert.application_name}\n"
        f"Reason: {alert.reason}\n"
        f"App: {target}\n"
        f"Signals: {', '.join(alert.rule_names)}\n"
        f"Confidence: {alert.confidence:.2f}\n"
    )


__all__ = ["format_risk_entry", "format_risk_summary", "format_correlated_alert"]
