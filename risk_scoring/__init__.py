"""
risk_scoring
============

Module 5 - Correlation, Risk Scoring, and Alerting.

Consumes the explainable rule results produced by Module 4
(``anomaly_detection``) and turns them into:

* **Risk scores** - time-decayed, per-application and per-destination
  numbers that answer "which entity is the biggest risk right now?"
  (:class:`RiskScorer`).
* **Correlated alerts** - several related rule signals collapsed into
  one meaningful incident with an explanation of WHAT/WHY/WHICH/HOW
  (:class:`AlertCorrelator`).
* **Persistence** - risk scores, score history, and correlated alerts
  stored in the same SQLite database used by the baseline and alert
  history (:class:`RiskStore`).
* **Alerting** - optional best-effort desktop notifications on top of
  the console/database paths (:class:`DesktopNotifier`,
  :class:`AlertNotifier`).

This package has no dependency on ``packet_capture`` or
``user_activity`` - it operates purely on ``RuleResult`` objects and
``ContextRecord`` values, keeping it independently testable.
"""

from __future__ import annotations

__all__ = [
    "SEVERITY_WEIGHTS",
    "severity_rank",
    "AlertCorrelator",
    "CorrelatedAlert",
    "AlertNotifier",
    "DesktopNotifier",
    "RiskEntry",
    "RiskScorer",
    "RiskSnapshot",
    "RiskStore",
]


def __getattr__(name: str):
    if name in {"SEVERITY_WEIGHTS", "severity_rank"}:
        from risk_scoring import config as _config

        return getattr(_config, name)
    if name in {"AlertCorrelator", "CorrelatedAlert"}:
        from risk_scoring import correlator as _correlator

        return getattr(_correlator, name)
    if name in {"AlertNotifier", "DesktopNotifier"}:
        from risk_scoring import notifier as _notifier

        return getattr(_notifier, name)
    if name in {"RiskEntry", "RiskScorer", "RiskSnapshot"}:
        from risk_scoring import scorer as _scorer

        return getattr(_scorer, name)
    if name == "RiskStore":
        from risk_scoring.store import RiskStore as _store

        return _store
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
