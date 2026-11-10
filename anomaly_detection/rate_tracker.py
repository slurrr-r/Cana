"""
rate_tracker.py
================

Tracks how many packets have recently been seen for each
(application, destination IP) pair, using a fixed-size sliding time
window - supports a "many rapid packets in a short time" anomaly rule,
distinct from the volume-based idle-transfer rule (this catches burst
*rate*, not cumulative *volume*).

Statistical care taken here, same principle as aggregator.py: the
baseline must not be fed on every single packet event, since
consecutive rate samples within one ongoing burst are correlated, not
independent observations. Sampling is throttled to at most once per
window per (app, destination) key.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

from anomaly_detection.config import RATE_TRACKER_MAX_KEYS


class ConnectionRateTracker:
    """
    Sliding-window packet rate tracker, keyed by (application,
    destination IP).
    """

    def __init__(
        self,
        window_seconds: float,
        max_keys: int = RATE_TRACKER_MAX_KEYS,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive.")
        if max_keys <= 0:
            raise ValueError("max_keys must be positive.")
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._events: Dict[Tuple[str, str], Deque[float]] = {}
        self._last_sampled: Dict[Tuple[str, str], float] = {}

    def record(
        self, application_name: str, destination_ip: Optional[str]
    ) -> Tuple[float, bool]:
        """
        Record one packet event now for this (app, destination) pair.

        Args:
            application_name: Owning application (or "UNKNOWN").
            destination_ip: Destination IP, if known.

        Returns:
            ``(current_rate_per_second, should_sample_baseline)`` -
            the current rate over the sliding window, and whether
            enough time has passed since this key was last sampled
            into the baseline (at most once per window, to keep
            baseline observations roughly independent).
        """
        key = (application_name, destination_ip or "")
        now = time.time()

        with self._lock:
            events = self._events.setdefault(key, deque())
            events.append(now)

            cutoff = now - self._window_seconds
            while events and events[0] < cutoff:
                events.popleft()

            self._evict_if_needed(now, key)

            rate = len(events) / self._window_seconds

            last_sample = self._last_sampled.get(key, 0.0)
            should_sample = (now - last_sample) >= self._window_seconds
            if should_sample:
                self._last_sampled[key] = now

        return rate, should_sample

    def reset(self) -> None:
        """Clear all tracked event history."""
        with self._lock:
            self._events = {}
            self._last_sampled = {}

    def _evict_if_needed(
        self, now: float, current_key: Tuple[str, str]
    ) -> None:
        if len(self._events) <= self._max_keys:
            return
        cutoff = now - self._window_seconds
        stale = [
            key
            for key, events in self._events.items()
            if key != current_key and (not events or events[-1] < cutoff)
        ]
        for key in stale:
            self._events.pop(key, None)
            self._last_sampled.pop(key, None)
        overflow = len(self._events) - self._max_keys
        if overflow <= 0:
            return
        ranked = sorted(
            (
                (key, events)
                for key, events in self._events.items()
                if key != current_key
            ),
            key=lambda item: item[1][-1] if item[1] else 0.0,
        )
        for key, _ in ranked[:overflow]:
            self._events.pop(key, None)
            self._last_sampled.pop(key, None)
