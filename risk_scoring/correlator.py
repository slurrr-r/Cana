"""
correlator.py
=============

Alert correlation: turning many rule signals into one meaningful alert.

The rules (Module 4) fire independently, so a single incident - say an
unknown process suddenly exchanging large amounts of data at a high
packet rate - can trigger three rules within a second. Reporting those
as three separate alerts buries the actual story in noise. This module
groups triggered results by (application, destination) inside a sliding
window and emits ONE correlated alert that explains WHAT happened, WHY
it was suspicious, WHICH signals contributed, and HOW severe it is.

The window is per (application, destination) and is time-based: signals
arriving within ``CORRELATION_WINDOW_SECONDS`` of the previous one for
the same key belong to the same incident; a gap longer than that closes
the incident and starts a new one.
"""

from __future__ import annotations
from collections import OrderedDict

import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from anomaly_detection.rules import RuleResult, connection_rate_peer

from risk_scoring.config import (
    CORRELATED_MIN_SEVERITY,
    CORRELATED_MIN_SIGNALS,
    CORRELATION_WINDOW_SECONDS,
    SEVERITY_WEIGHTS,
    severity_rank,
)

# Confidence is a blend of how many DISTINCT rules fired and how severe
# the strongest one was. A single rule firing once is the least
# informative; several different rules agreeing is much stronger.
_CONFIDENCE_BASE = 0.4
_CONFIDENCE_PER_EXTRA_RULE = 0.15
_CONFIDENCE_EXTRA_RULE_CAP = 0.3
_CONFIDENCE_HIGH_BONUS = 0.2
_CONFIDENCE_MEDIUM_BONUS = 0.1

_Signal = Tuple[str, str, float]  # (rule_name, severity, timestamp)


@dataclass(frozen=True)
class CorrelatedAlert:
    """
    One correlated incident, aggregating several rule signals.

    Attributes:
        alert_id: Stable unique identifier for this incident.
        started_at: Epoch of the first contributing signal.
        ended_at: Epoch of the last contributing signal.
        application_name: The application involved.
        destination_ip: The remote peer. Outbound uses destination_ip;
            inbound uses source_ip so distinct remotes are not pooled.
        rule_names: Distinct rules that fired, in order of first fire.
        signal_count: Total contributing signals (duplicates included).
        severity: The strongest severity among the contributing signals.
        score: Sum of the severity weights of every contributing signal.
        confidence: 0..1 estimate of how strong this correlation is.
        reason: Human-readable explanation covering WHAT/WHY/WHICH/HOW.
    """

    alert_id: str
    started_at: float
    ended_at: float
    application_name: str
    destination_ip: Optional[str]
    rule_names: Tuple[str, ...]
    signal_count: int
    severity: str
    score: float
    confidence: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation, suitable for JSON/DB export."""
        return {
            "alert_id": self.alert_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "application_name": self.application_name,
            "destination_ip": self.destination_ip,
            "rule_names": list(self.rule_names),
            "signal_count": self.signal_count,
            "severity": self.severity,
            "score": round(self.score, 2),
            "confidence": self.confidence,
            "reason": self.reason,
        }


@dataclass
class _Group:
    """One open correlation window for a single (application, destination)."""

    key: Tuple[str, Optional[str]]
    started_at: float
    last_seen: float
    signals: List[_Signal]
    distinct_rules: List[str]

    @property
    def count(self) -> int:
        return len(self.signals)

    @property
    def application_name(self) -> str:
        return self.key[0]

    @property
    def destination_ip(self) -> Optional[str]:
        return self.key[1]


class AlertCorrelator:
    """
    Groups triggered rule results into correlated alerts.

    Typical usage::

        correlator = AlertCorrelator()
        for result in results:
            alert = correlator.observe(result)
            if alert is not None:
                notifier.notify(alert)
        for alert in correlator.flush():
            notifier.notify(alert)
    """

    def __init__(
        self,
        window_seconds: float = CORRELATION_WINDOW_SECONDS,
        min_signals: int = CORRELATED_MIN_SIGNALS,
        min_severity: str = CORRELATED_MIN_SEVERITY,
    ) -> None:
        self.window_seconds = max(float(window_seconds), 0.0)
        self.min_signals = max(int(min_signals), 1)
        self.min_severity = min_severity
        self._open: Dict[Tuple[str, Optional[str]], _Group] = OrderedDict()
        self.max_groups = 1024
        self.max_signals = 256

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @property
    def open_count(self) -> int:
        """How many correlation windows are currently open."""
        return len(self._open)

    def observe(
        self, result: RuleResult, now: Optional[float] = None
    ) -> Optional[CorrelatedAlert]:
        """
        Feed one rule result into the correlator.

        Args:
            result: A rule result. Non-triggered results are ignored.
            now: Epoch timestamp; defaults to the current time.

        Returns:
            A :class:`CorrelatedAlert` when this signal either closes a
            qualifying incident or (alone) qualifies on severity, else
            ``None`` while the incident is still open or too weak.
        """
        if not result.triggered:
            return None

        timestamp = time.time() if now is None else now
        while self._open:
            oldest = next(iter(self._open))
            if timestamp - self._open[oldest].last_seen <= self.window_seconds:
                break
            self._open.pop(oldest)
        remote_peer = connection_rate_peer(result.context)
        if remote_peer == "UNKNOWN_PEER":
            remote_peer = None
        key = (
            str(result.context.application_name),
            remote_peer,
        )
        signal = (result.rule_name, result.severity, timestamp)

        emitted: Optional[CorrelatedAlert] = None
        group = self._open.get(key)
        if group is not None and timestamp - group.last_seen > self.window_seconds:
            # The previous incident for this key has gone quiet - close
            # it (possibly emitting) and treat this signal as the start
            # of a brand new incident.
            self._open.pop(key, None)
            emitted = self._close_group(group)
            group = None

        if group is None:
            group = _Group(
                key=key,
                started_at=timestamp,
                last_seen=timestamp,
                signals=[signal],
                distinct_rules=[result.rule_name],
            )
            self._open[key] = group
            while len(self._open) > self.max_groups:
                self._open.pop(next(iter(self._open)))
            if emitted is not None:
                # Report the just-expired incident; this new signal keeps
                # its own window open and is handled on later signals.
                return emitted
            if self._qualifies(group):
                # A single severe signal is already worth surfacing.
                self._open.pop(key, None)
                return self._build_alert(group)
            return None

        group.signals.append(signal)
        if len(group.signals) > self.max_signals:
            group.signals.pop(0)
            group.distinct_rules = list(dict.fromkeys(item[0] for item in group.signals))
        group.last_seen = timestamp
        self._open.move_to_end(key)
        if result.rule_name not in group.distinct_rules:
            group.distinct_rules.append(result.rule_name)

        if self._qualifies(group):
            self._open.pop(key, None)
            return self._build_alert(group)
        return None

    def flush(self, now: Optional[float] = None) -> List[CorrelatedAlert]:
        """
        Close every open window and return any qualifying alerts.

        Called at shutdown so an incident that was mid-window at the end
        of a capture still gets reported (if it had become strong
        enough).

        Returns:
            A list of the correlated alerts emitted by the close.
        """
        emitted: List[CorrelatedAlert] = []
        for key in list(self._open):
            group = self._open.pop(key)
            alert = self._close_group(group)
            if alert is not None:
                emitted.append(alert)
        return emitted

    def reset(self) -> None:
        """Clear all open windows (primarily for tests)."""
        self._open.clear()

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _qualifies(self, group: _Group) -> bool:
        """
        Whether an incident is worth surfacing.

        An incident qualifies if it has enough DISTINCT rules firing in
        the window, OR its strongest signal is severe enough on its own
        that burying it would be worse than reporting a one-signal
        incident.
        """
        if len(group.distinct_rules) >= self.min_signals:
            return True
        # Below the distinct-rule threshold, only a signal STRICTLY
        # stronger than the floor is surfaced alone (e.g. a lone HIGH
        # with min_severity=MEDIUM). A lone MEDIUM is ordinary noise.
        strongest = max((severity_rank(s[1]) for s in group.signals), default=0)
        return severity_rank(self.min_severity) < strongest

    def _close_group(self, group: _Group) -> Optional[CorrelatedAlert]:
        """Build the alert for a closing group, if it qualifies."""
        if not self._qualifies(group):
            return None
        return self._build_alert(group)

    def _build_alert(self, group: _Group) -> CorrelatedAlert:
        """Assemble a :class:`CorrelatedAlert` from a group."""
        severities = [s[1] for s in group.signals]
        strongest = max(severities, key=severity_rank)
        score = sum(SEVERITY_WEIGHTS.get(sev, 1.0) for sev in severities)

        distinct_count = len(group.distinct_rules)
        confidence = _CONFIDENCE_BASE
        confidence += min(
            _CONFIDENCE_EXTRA_RULE_CAP,
            (distinct_count - 1) * _CONFIDENCE_PER_EXTRA_RULE,
        )
        if strongest == "HIGH":
            confidence += _CONFIDENCE_HIGH_BONUS
        elif strongest == "MEDIUM":
            confidence += _CONFIDENCE_MEDIUM_BONUS
        confidence = min(1.0, max(0.0, round(confidence, 2)))

        return CorrelatedAlert(
            alert_id=uuid.uuid4().hex,
            started_at=group.started_at,
            ended_at=group.last_seen,
            application_name=group.application_name,
            destination_ip=group.destination_ip,
            rule_names=tuple(group.distinct_rules),
            signal_count=group.count,
            severity=strongest,
            score=score,
            confidence=confidence,
            reason=self._build_reason(group, strongest, score),
        )

    @staticmethod
    def _build_reason(group: _Group, strongest: str, score: float) -> str:
        target = (
            group.application_name
            if group.destination_ip is None
            else f"{group.application_name} -> {group.destination_ip}"
        )
        rules = ", ".join(group.distinct_rules)
        return (
            f"{group.count} suspicious signal(s) for {target} in the "
            f"last {max(group.last_seen - group.started_at, 0.0):.0f}s: "
            f"{rules}. Most severe: {strongest} (aggregate score {score:.1f})."
        )


__all__ = ["AlertCorrelator", "CorrelatedAlert"]
