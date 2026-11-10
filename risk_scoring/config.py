"""
config.py
=========

Centralized configuration for the risk-scoring/correlation subsystem.

This is Module 5's configuration: everything that governs how raw rule
results are turned into risk scores and correlated alerts lives here so
it can be tuned without touching the logic.
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------- #
# Severity weights
# --------------------------------------------------------------------------- #

# Numeric weight assigned to each severity level. Risk scores accumulate
# these weights (see scorer.py); HIGH deliberately weighs four times a
# LOW so a single high-severity condition outweighs several low ones.
SEVERITY_WEIGHTS: Final[dict] = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 4.0}

# Ordering used to compare severities (lowest -> highest).
RISK_SEVERITY_ORDER: Final[tuple] = ("LOW", "MEDIUM", "HIGH")

# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #

# Half-life of a risk score in seconds. A score decays by half every
# this many seconds, so recent alerts dominate and an old burst of
# alerts fades back to zero on its own - no explicit reset needed.
RISK_HALF_LIFE_SECONDS: Final[float] = 300.0

# Default number of entries shown in a risk leaderboard.
RISK_DEFAULT_TOP_N: Final[int] = 10

# Cap in-memory risk entities so decayed/idle keys cannot grow forever.
RISK_MAX_ENTITIES: Final[int] = 5_000

# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #

# Signals (triggered rules) for the same (application, destination) that
# arrive within this many seconds of each other are treated as one
# incident rather than several unrelated alerts.
CORRELATION_WINDOW_SECONDS: Final[float] = 60.0

# A correlated alert is only worth emitting once this many DISTINCT
# rules have fired in the window (a single weak signal is ordinary).
CORRELATED_MIN_SIGNALS: Final[int] = 2

# ...unless the strongest signal in the window is at least this severe -
# a single HIGH is always worth surfacing as a correlated alert.
CORRELATED_MIN_SEVERITY: Final[str] = "MEDIUM"

# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

# Tables written by RiskStore live in the SAME database file as the
# baseline and alert history, so the native UI reads everything from one
# place. RiskStore only ADDS tables - it never touches the baseline or
# alert tables owned by anomaly_detection.store.
RISK_SCHEMA_VERSION: Final[int] = 1

# Default number of rows returned by the risk store's read methods.
RECENT_CORRELATED_DEFAULT_LIMIT: Final[int] = 20
RISK_HISTORY_DEFAULT_LIMIT: Final[int] = 100

# How often main.py persists a risk snapshot to disk during a run.
RISK_UPDATE_INTERVAL_SECONDS: Final[float] = 30.0


def severity_rank(severity: str) -> int:
    """
    Return the numeric rank of a severity ("LOW" -> 0, "HIGH" -> 2).

    Unknown severities rank as 0 rather than raising, so a future rule
    with a new severity string degrades to LOW instead of crashing.
    """
    try:
        return RISK_SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


__all__ = [
    "SEVERITY_WEIGHTS",
    "RISK_SEVERITY_ORDER",
    "RISK_HALF_LIFE_SECONDS",
    "RISK_DEFAULT_TOP_N",
    "RISK_MAX_ENTITIES",
    "CORRELATION_WINDOW_SECONDS",
    "CORRELATED_MIN_SIGNALS",
    "CORRELATED_MIN_SEVERITY",
    "RISK_SCHEMA_VERSION",
    "RECENT_CORRELATED_DEFAULT_LIMIT",
    "RISK_HISTORY_DEFAULT_LIMIT",
    "RISK_UPDATE_INTERVAL_SECONDS",
    "severity_rank",
]
