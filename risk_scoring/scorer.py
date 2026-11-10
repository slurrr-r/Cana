"""
scorer.py
=========

Time-decayed per-entity risk scoring.

The anomaly rules (Module 4) emit per-packet verdicts with a severity,
but nothing aggregates those verdicts into "which application is my
biggest risk right now". This module fills that gap: every triggered
rule result adds a weighted amount to the risk score of its owning
application and its destination, and those scores decay exponentially
over time (half-life ``RISK_HALF_LIFE_SECONDS``) so recency dominates.

A decaying score is deliberately chosen over a plain cumulative counter
because the question the tool is answering is "is this happening NOW",
not "has this ever happened". An application that triggered one alert
an hour ago should not still rank as risky if it has been quiet since.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from anomaly_detection.rules import RuleResult, connection_rate_peer

from risk_scoring.config import (
    RISK_DEFAULT_TOP_N,
    RISK_HALF_LIFE_SECONDS,
    RISK_MAX_ENTITIES,
    SEVERITY_WEIGHTS,
)

# Anything below this is treated as zero - prevents scores from decaying
# to -0.0 and keeps the leaderboard free of noise-floor entries.
_MIN_RELEVANT_SCORE = 1e-9

_APPLICATION = "application"
_DESTINATION = "destination"


@dataclass(frozen=True)
class RiskEntry:
    """
    One entity's current risk position.

    Attributes:
        name: The entity name - an application name or destination IP.
        kind: "application" or "destination".
        score: The current (decayed) risk score.
        events: How many triggered results have contributed to it.
    """

    name: str
    kind: str
    score: float
    events: int

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation, suitable for JSON/DB export."""
        return {
            "name": self.name,
            "kind": self.kind,
            "score": round(self.score, 4),
            "events": self.events,
        }


@dataclass(frozen=True)
class RiskSnapshot:
    """
    A point-in-time view of every entity's risk, for both dimensions.

    Attributes:
        applications: All application risk entries, highest first.
        destinations: All destination risk entries, highest first.
        generated_at: Epoch timestamp the snapshot was taken.
    """

    applications: List[RiskEntry]
    destinations: List[RiskEntry]
    generated_at: float

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation."""
        return {
            "applications": [e.to_dict() for e in self.applications],
            "destinations": [e.to_dict() for e in self.destinations],
            "generated_at": self.generated_at,
        }


@dataclass
class _EntityState:
    """Internal running state for one entity's risk score."""

    value: float = 0.0
    last_update: Optional[float] = None
    events: int = 0


class RiskScorer:
    """
    Accumulates and time-decays risk scores per application and per
    destination.

    Typical usage::

        scorer = RiskScorer()
        for result in triggered_results:
            scorer.record(result)
        top = scorer.leaderboard(kind="application", top_n=5)
    """

    def __init__(
        self,
        half_life: float = RISK_HALF_LIFE_SECONDS,
        severity_weights: Optional[Dict[str, float]] = None,
        max_entities: int = RISK_MAX_ENTITIES,
    ) -> None:
        self.half_life = max(float(half_life), 1e-6)
        self.severity_weights = (
            dict(severity_weights) if severity_weights is not None else dict(SEVERITY_WEIGHTS)
        )
        if max_entities <= 0:
            raise ValueError("max_entities must be positive.")
        self._max_entities = max_entities
        self._lock = threading.RLock()
        self._applications: Dict[str, _EntityState] = {}
        self._destinations: Dict[str, _EntityState] = {}

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #

    def record(self, result: RuleResult, now: Optional[float] = None) -> None:
        """
        Add one triggered rule result to its entities' risk scores.

        Non-triggered results are ignored. Both the owning application
        and the destination IP receive the same weighted increment, so
        the two leaderboards answer "riskiest application" and
        "riskiest destination" from the same evidence.

        Args:
            result: A rule result. Only ``result.triggered`` matters.
            now: Epoch timestamp; defaults to the current time.
        """
        with self._lock:
            if not result.triggered:
                return

            timestamp = time.time() if now is None else now
            weight = self.severity_weights.get(result.severity, 1.0)

            application = str(result.context.application_name) or "UNKNOWN"
            self._update_entity(self._applications, application, weight, timestamp)

            destination = connection_rate_peer(result.context)
            if destination != "UNKNOWN_PEER":
                self._update_entity(self._destinations, str(destination), weight, timestamp)

    def _update_entity(
        self,
        table: Dict[str, _EntityState],
        name: str,
        weight: float,
        now: float,
    ) -> None:
        state = table.setdefault(name, _EntityState())
        current = self._apply_decay(state, now)
        state.value = current + weight
        state.events += 1
        state.last_update = now
        self._evict_if_needed(table, now, name)

    # ------------------------------------------------------------------ #
    # Decay
    # ------------------------------------------------------------------ #

    def _apply_decay(self, state: _EntityState, now: float) -> float:
        """
        Decay a state's value to what it would be at ``now``.

        Mutates ``last_update`` so repeated reads are idempotent, and
        clamps to zero at the noise floor.

        Returns:
            The decayed value.
        """
        if state.last_update is None:
            return state.value
        elapsed = max(now - state.last_update, 0.0)
        if elapsed <= 0.0:
            return state.value
        factor = 0.5 ** (elapsed / self.half_life)
        value = state.value * factor
        if value < _MIN_RELEVANT_SCORE:
            value = 0.0
        state.value = value
        state.last_update = now
        return value

    def _decayed_state(self, table: Dict[str, _EntityState], name: str, now: float) -> Optional[_EntityState]:
        """Return the decayed state for a name, or None if it doesn't exist."""
        state = table.get(name)
        if state is None:
            return None
        self._apply_decay(state, now)
        return state

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def application_score(self, name: str, now: Optional[float] = None) -> float:
        """Current decayed risk score for one application (0.0 if unknown)."""
        with self._lock:
            state = self._decayed_state(self._applications, str(name), self._resolve(now))
            return state.value if state is not None else 0.0

    def destination_score(self, ip: str, now: Optional[float] = None) -> float:
        """Current decayed risk score for one destination IP (0.0 if unknown)."""
        with self._lock:
            state = self._decayed_state(self._destinations, str(ip), self._resolve(now))
            return state.value if state is not None else 0.0

    def events_for(self, kind: str, name: str, now: Optional[float] = None) -> int:
        """Number of triggered results recorded for an entity (0 if unknown)."""
        with self._lock:
            table = self._applications if kind == _APPLICATION else self._destinations
            state = table.get(str(name))
            return state.events if state is not None else 0

    def leaderboard(
        self,
        kind: str = _APPLICATION,
        top_n: int = RISK_DEFAULT_TOP_N,
        now: Optional[float] = None,
    ) -> List[RiskEntry]:
        """
        Return the highest-risk entities of one kind, highest first.

        Args:
            kind: "application" or "destination".
            top_n: Maximum number of entries to return.
            now: Epoch timestamp for decay; defaults to now.

        Returns:
            A list of :class:`RiskEntry`, sorted by score descending
            (ties broken by name for determinism). Empty if nothing has
            been recorded.
        """
        with self._lock:
            if kind not in (_APPLICATION, _DESTINATION):
                raise ValueError(f"kind must be '{_APPLICATION}' or '{_DESTINATION}', got {kind!r}")

            table = self._applications if kind == _APPLICATION else self._destinations
            timestamp = self._resolve(now)

            entries = []
            for name, state in table.items():
                value = self._apply_decay(state, timestamp)
                if value > _MIN_RELEVANT_SCORE:
                    entries.append(RiskEntry(name=name, kind=kind, score=value, events=state.events))

            entries.sort(key=lambda e: (-e.score, e.name))
            limit = len(entries) if top_n is None else max(0, int(top_n))
            return entries[:limit]

    def snapshot(self, now: Optional[float] = None) -> RiskSnapshot:
        """
        Return the full current risk state for both dimensions.

        Unlike :meth:`leaderboard`, this is not limited to ``top_n`` -
        it captures every entity with any remaining score, which is what
        persistence needs so history survives across runs.
        """
        with self._lock:
            timestamp = self._resolve(now)
            return RiskSnapshot(
                applications=[
                    RiskEntry(
                        name=e.name,
                        kind=_APPLICATION,
                        score=e.score,
                        events=self._applications[e.name].events,
                    )
                    for e in self.leaderboard(kind=_APPLICATION, top_n=None, now=timestamp)
                ],
                destinations=[
                    RiskEntry(
                        name=e.name,
                        kind=_DESTINATION,
                        score=e.score,
                        events=self._destinations[e.name].events,
                    )
                    for e in self.leaderboard(kind=_DESTINATION, top_n=None, now=timestamp)
                ],
                generated_at=timestamp,
            )

    # ------------------------------------------------------------------ #
    # Restoration
    # ------------------------------------------------------------------ #

    def restore(
        self,
        entries: List[Dict[str, Any]],
        now: Optional[float] = None,
    ) -> int:
        """
        Resume risk state persisted by a previous run.

        Without this, restarting the analyzer always started with an
        empty scorer even though the database held risk state - making
        persistence only *historical*, not *restorable*. Restoring lets
        the scorer continue from the exact decayed position each entity
        was in when last checkpointed: its ``value`` is taken as-is and
        its ``last_update`` is set to the persisted timestamp, so every
        later read/record decays from that instant (not from startup).
        A score that was recorded an hour before shutdown therefore
        keeps aging naturally across the restart.

        Each entry is a plain dict as returned by
        ``RiskStore.latest_risk_scores`` / ``load_risk_state`` with
        keys ``kind``, ``name``, ``score``, ``events`` and an epoch
        timestamp in either ``updated_at_epoch`` or ``updated_at``.

        Args:
            entries: Persisted risk rows to resume from.
            now: Epoch reference for applying decay on restore; defaults
                to the current time.

        Returns:
            The number of entities actually restored.
        """
        with self._lock:
            timestamp = self._resolve(now)
            restored = 0
            for row in entries:
                kind = str(row.get("kind", ""))
                table = (
                    self._applications
                    if kind == _APPLICATION
                    else self._destinations
                    if kind == _DESTINATION
                    else None
                )
                if table is None:
                    continue

                try:
                    score = float(row.get("score", 0.0))
                    events = int(row.get("events", 0))
                except (TypeError, ValueError):
                    continue
                if score <= _MIN_RELEVANT_SCORE or events <= 0:
                    continue

                name = str(row.get("name", "")).strip()
                if not name:
                    continue

                epoch = row.get("updated_at_epoch")
                if not epoch:
                    epoch = row.get("updated_at")
                try:
                    last_update = float(epoch) if epoch is not None else None
                except (TypeError, ValueError):
                    last_update = None
                # A pre-epoch-column row carries an ISO string in
                # ``updated_at``; parse it rather than losing decay.
                if last_update is None and epoch:
                    try:
                        parsed = datetime.fromisoformat(str(epoch))
                        if parsed.tzinfo is None:
                            parsed = parsed.replace(tzinfo=timezone.utc)
                        last_update = parsed.timestamp()
                    except ValueError:
                        last_update = None

                state = _EntityState(value=score, last_update=last_update, events=events)
                table[name] = state
                self._apply_decay(state, timestamp)
                restored += 1

            self._evict_if_needed(self._applications, timestamp, "")
            self._evict_if_needed(self._destinations, timestamp, "")
            return restored

    def _evict_if_needed(
        self,
        table: Dict[str, _EntityState],
        now: float,
        keep: str,
    ) -> None:
        if len(table) <= self._max_entities:
            return
        stale = []
        for name, state in table.items():
            if name == keep:
                continue
            value = self._apply_decay(state, now)
            if value <= _MIN_RELEVANT_SCORE:
                stale.append(name)
        for name in stale:
            table.pop(name, None)
        overflow = len(table) - self._max_entities
        if overflow <= 0:
            return
        ranked = sorted(
            ((name, state) for name, state in table.items() if name != keep),
            key=lambda item: (item[1].value, item[1].last_update or 0.0),
        )
        for name, _ in ranked[:overflow]:
            table.pop(name, None)

    def clear(self) -> None:
        """Reset all recorded state (primarily for tests)."""
        with self._lock:
            self._applications.clear()
            self._destinations.clear()

    @staticmethod
    def _resolve(now: Optional[float]) -> float:
        return time.time() if now is None else now


__all__ = ["RiskScorer", "RiskEntry", "RiskSnapshot"]
