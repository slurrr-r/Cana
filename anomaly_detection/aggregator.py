"""
aggregator.py
==============

Stateful helpers that turn a stream of per-packet ContextRecords into
the SESSION-level aggregates some rules need.

Why this exists: individual packets are small (bounded by MTU, ~1500
bytes), so a single packet's size can never represent "150MB
transferred while idle" - that's a cumulative total across many
packets over an idle period, which needs to be tracked as state.

Statistical care taken here: the baseline should be fed the FINAL
total of a completed idle session (one independent observation), not
every intermediate running total as the session grows - feeding it
every incremental value would badly skew the mean/variance, since
those values are monotonically increasing within a session and are
not independent observations of "a typical idle session's volume."
See :meth:`IdleTransferAggregator.pop_completed_session`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional, Tuple

from anomaly_detection.context import ContextRecord


@dataclass
class _IdleWindowState:
    is_idle: bool = False
    accumulated_bytes: float = 0.0
    idle_started_hour: int = 0


class IdleTransferAggregator:
    """
    Tracks cumulative bytes transferred while the user is IDLE.

    Two distinct things are exposed, for two distinct purposes:

    * :meth:`update` returns the CURRENT running total for the
      in-progress idle window - used for real-time rule checking
      ("is this idle session, so far, already unusually large?").
    * :meth:`pop_completed_session` returns the FINAL total of the
      most recently *completed* idle window (i.e. once the user goes
      back to ACTIVE) - this, and only this, is what should be fed
      into the baseline, since it's a single independent observation
      rather than a monotonically growing running total.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = _IdleWindowState()
        self._completed_session: Optional[Tuple[int, float]] = None

    def update(self, context: ContextRecord) -> float:
        """
        Incorporate one packet's context into the current idle-window
        accumulator.

        Returns:
            The cumulative bytes transferred so far in the current
            idle window (0.0 if the user is currently ACTIVE).
        """
        with self._lock:
            if context.user_status != "IDLE":
                if self._state.is_idle:
                    self._completed_session = (
                        self._state.idle_started_hour,
                        self._state.accumulated_bytes,
                    )
                self._state = _IdleWindowState(is_idle=False)
                return 0.0

            if not self._state.is_idle:
                self._state = _IdleWindowState(
                    is_idle=True,
                    accumulated_bytes=0.0,
                    idle_started_hour=context.hour_of_day,
                )

            self._state.accumulated_bytes += context.packet_size
            return self._state.accumulated_bytes

    def pop_completed_session(self) -> Optional[Tuple[int, float]]:
        """
        Return and clear the most recently completed idle session's
        ``(hour_of_day, total_bytes)``, if one is pending.

        Returns ``None`` if no session has completed since the last
        call - callers (the orchestrator) should call this after every
        :meth:`update` and feed the result into the baseline exactly
        once when it's not ``None``.
        """
        with self._lock:
            result = self._completed_session
            self._completed_session = None
            return result

    def reset(self) -> None:
        """Clear all accumulator state."""
        with self._lock:
            self._state = _IdleWindowState()
            self._completed_session = None

    @property
    def current_accumulated_bytes(self) -> float:
        """Current running total for the in-progress idle window (0.0 if active)."""
        with self._lock:
            return self._state.accumulated_bytes if self._state.is_idle else 0.0
