"""
baseline.py
===========

Rolling, hour-of-day-bucketed baseline statistics of "normal"
behavior for this machine.

Design rationale (from project discussion): a fixed threshold like
"idle + >100MB = suspicious" produces false positives on completely
normal behavior (e.g. streaming video in the evening while away from
the keyboard). Comparing against a *learned baseline* instead - "is
this unusual for what THIS machine normally does at THIS time of day"
- is what actually distinguishes genuine anomalies from routine
behavior, without needing to hand-maintain lists of "known good"
services.

Honest, documented limitation: this has a cold-start problem. Until a
bucket has accumulated enough observations
(MIN_OBSERVATIONS_FOR_BASELINE), there isn't yet a meaningful baseline
to compare against, and callers should fall back to simpler fixed-
threshold logic (see rules.py) during that window. This module makes
that state explicit via :meth:`HourBucket.is_established` rather than
silently guessing.

Persistence: Welford's algorithm is what makes cross-run persistence
cheap here. A bucket's ENTIRE state is three numbers - ``count``,
``mean``, and ``_m2`` - and those three are mathematically sufficient
to resume the stream exactly: restoring them and continuing to call
:meth:`HourBucket.update` yields the same mean/std_dev as if the
process had never stopped. So saving a baseline costs
O(metrics x 24) rows rather than O(observations), and no raw
observation history ever has to be stored. :meth:`BaselineTracker.snapshot`
and :meth:`BaselineTracker.restore` are that serialization surface;
``anomaly_detection.store`` is what writes it to disk.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Tuple

from anomaly_detection.config import (
    ANOMALY_STD_DEV_MULTIPLIER,
    MIN_OBSERVATIONS_FOR_BASELINE,
)

# (count, mean, m2) - the complete persistable state of one HourBucket.
BucketState = Tuple[int, float, float]

# {metric_name: {hour_of_day: BucketState}}
BaselineSnapshot = Dict[str, Dict[int, BucketState]]


@dataclass
class HourBucket:
    """
    Running statistics for a single hour-of-day bucket (0-23).

    Uses Welford's online algorithm for numerically stable running
    mean/variance, so it doesn't need to store the full history of
    observed values to compute a standard deviation.
    """

    count: int = 0
    mean: float = 0.0
    _m2: float = field(default=0.0, repr=False)  # sum of squared deviations

    def update(self, value: float) -> None:
        """Incorporate one new observation into the running statistics."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2

    def to_state(self) -> BucketState:
        """
        Return this bucket's complete state as a plain
        ``(count, mean, m2)`` tuple, suitable for persisting.

        A tuple (rather than the bucket itself) is returned so callers
        can never mutate live tracker internals - see
        :meth:`BaselineTracker.snapshot`.
        """
        return (self.count, self.mean, self._m2)

    @classmethod
    def from_state(cls, count: int, mean: float, m2: float) -> "HourBucket":
        """
        Rebuild a bucket from previously persisted state.

        The rebuilt bucket is fully resumable: further
        :meth:`update` calls continue Welford's recurrence from exactly
        where it left off (see module docstring).

        Raises:
            ValueError: If the state is not internally consistent -
                a negative count or negative sum-of-squared-deviations
                cannot come from a real observation stream and would
                silently produce a nonsensical variance (or a
                ``math.sqrt`` domain error) if accepted.
        """
        if count < 0:
            raise ValueError(f"count cannot be negative, got {count}.")
        if m2 < 0:
            raise ValueError(f"m2 cannot be negative, got {m2}.")
        bucket = cls(count=int(count), mean=float(mean))
        bucket._m2 = float(m2)
        return bucket

    @property
    def variance(self) -> float:
        """Sample variance, or 0.0 if fewer than 2 observations exist."""
        if self.count < 2:
            return 0.0
        return self._m2 / (self.count - 1)

    @property
    def std_dev(self) -> float:
        """Sample standard deviation."""
        return math.sqrt(self.variance)

    def is_established(self, min_observations: Optional[int] = None) -> bool:
        """
        Whether this bucket has enough observations to be trusted as
        a meaningful baseline (see module docstring - cold start).

        Args:
            min_observations: Override the default
                ``MIN_OBSERVATIONS_FOR_BASELINE`` threshold. Some
                metrics are noisier than others and need more samples
                before their variance estimate is trustworthy (e.g.
                connection rate - see
                ``anomaly_detection.config.MIN_RATE_SAMPLES_FOR_BASELINE``).
                If omitted, the global default is used.
        """
        threshold = (
            min_observations
            if min_observations is not None
            else MIN_OBSERVATIONS_FOR_BASELINE
        )
        return self.count >= threshold

    def is_anomalous(
        self, value: float, min_observations: Optional[int] = None
    ) -> bool:
        """
        Determine whether ``value`` is anomalous relative to this
        bucket's learned mean/std-dev, using a z-score-style check.

        Returns False (never anomalous) if the bucket isn't yet
        established - callers should check :meth:`is_established`
        separately if they need to distinguish "not anomalous" from
        "not enough data to judge."

        Args:
            value: The observed value to check.
            min_observations: See :meth:`is_established`.
        """
        if not self.is_established(min_observations):
            return False
        if self.std_dev == 0.0:
            # No variance observed yet - treat any deviation from the
            # single known mean as anomalous only if clearly different.
            return value > self.mean * 2 and value > 0
        threshold = self.mean + (ANOMALY_STD_DEV_MULTIPLIER * self.std_dev)
        return value > threshold


@dataclass(frozen=True)
class BaselineSummary:
    """
    How much learning a :class:`BaselineTracker` currently holds.

    Attributes:
        metric_count: Number of distinct metrics being tracked.
        established_bucket_count: Number of hour buckets that have
            enough observations to actually be judged against (see
            :meth:`HourBucket.is_established`) - the number that
            matters, since an un-established bucket can't fire a rule.
        total_observations: Total observations across every bucket.
    """

    metric_count: int
    established_bucket_count: int
    total_observations: int

    @property
    def is_empty(self) -> bool:
        """True if nothing has been learned yet (a true cold start)."""
        return self.total_observations == 0


class BaselineTracker:
    """
    Maintains one :class:`HourBucket` per hour-of-day (0-23) for each
    named metric being tracked (e.g. "packet_size", "idle_transfer_bytes").

    Thread-safe: intended to be updated from a capture loop while
    potentially being read from elsewhere (e.g. a rule-evaluation
    pass) concurrently.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Dict[int, HourBucket]] = {}

    def update(self, metric_name: str, hour_of_day: int, value: float) -> None:
        """
        Record one new observation for a named metric at a given
        hour-of-day.

        Args:
            metric_name: Logical name of the metric being tracked
                (e.g. "packet_size_bytes").
            hour_of_day: 0-23.
            value: The observed value.
        """
        if not (0 <= hour_of_day <= 23):
            raise ValueError(f"hour_of_day must be 0-23, got {hour_of_day}.")

        with self._lock:
            if metric_name not in self._buckets:
                self._buckets[metric_name] = {h: HourBucket() for h in range(24)}
            self._buckets[metric_name][hour_of_day].update(value)

    def get_bucket(
        self, metric_name: str, hour_of_day: int
    ) -> Optional[HourBucket]:
        """
        Retrieve the :class:`HourBucket` for a metric/hour, if any
        observations have been recorded for it yet.

        Returns:
            The bucket, or ``None`` if this metric has never been
            updated at all.
        """
        with self._lock:
            metric_buckets = self._buckets.get(metric_name)
            if metric_buckets is None:
                return None
            return metric_buckets.get(hour_of_day)

    def is_anomalous(
        self, metric_name: str, hour_of_day: int, value: float
    ) -> bool:
        """
        Convenience check: is ``value`` anomalous for this metric at
        this hour, per the learned baseline?

        Returns False if no baseline exists yet for this metric/hour
        (cold start) - callers needing to distinguish "normal" from
        "not enough data" should use :meth:`get_bucket` directly.
        """
        bucket = self.get_bucket(metric_name, hour_of_day)
        if bucket is None:
            return False
        return bucket.is_anomalous(value)

    def reset(self) -> None:
        """Clear all learned baseline data."""
        with self._lock:
            self._buckets = {}

    # ----------------------------------------------------------------- #
    # Persistence surface (see module docstring)
    # ----------------------------------------------------------------- #

    def snapshot(self) -> BaselineSnapshot:
        """
        Return the complete current baseline state as plain, immutable
        ``(count, mean, m2)`` tuples.

        Taken atomically under the tracker's lock, and deliberately
        returning tuples rather than live :class:`HourBucket` objects:
        the caller (a background checkpointer thread) would otherwise
        hold references to buckets the capture thread is still
        mutating, and could serialize a bucket mid-``update()`` with a
        new ``count`` but a stale ``mean``.

        Buckets with no observations are omitted - a metric's 24 hour
        buckets are allocated together (see :meth:`update`), but a
        typical session only ever touches one or two of them, so
        persisting the empty ones is pure noise.

        Returns:
            ``{metric_name: {hour_of_day: (count, mean, m2)}}``.
        """
        with self._lock:
            return {
                metric_name: {
                    hour: bucket.to_state()
                    for hour, bucket in hour_buckets.items()
                    if bucket.count > 0
                }
                for metric_name, hour_buckets in self._buckets.items()
            }

    def restore(self, snapshot: Mapping[str, Mapping[int, BucketState]]) -> None:
        """
        Replace all in-memory baseline state with previously persisted
        state (see :meth:`snapshot`).

        Allocation semantics deliberately mirror :meth:`update`: for
        every metric present in ``snapshot``, all 24 hour buckets are
        created, and the persisted ones are filled in. This preserves
        the existing distinction the rules depend on -
        :meth:`get_bucket` returns a zero-count bucket for an unseen
        HOUR of a seen metric, but ``None`` for a metric that has never
        been observed at all. Restoring only the persisted hours would
        quietly change which branch rules like
        ``packet_size_anomaly_rule`` take, and therefore which reason
        string the user sees.

        Args:
            snapshot: State as produced by :meth:`snapshot`.

        Raises:
            ValueError: If any hour key is outside 0-23, or any bucket
                state is internally inconsistent (see
                :meth:`HourBucket.from_state`).
        """
        rebuilt: Dict[str, Dict[int, HourBucket]] = {}

        for metric_name, hour_states in snapshot.items():
            hour_buckets = {h: HourBucket() for h in range(24)}
            for hour, state in hour_states.items():
                if not (0 <= hour <= 23):
                    raise ValueError(
                        f"hour_of_day must be 0-23, got {hour} for metric "
                        f"'{metric_name}'."
                    )
                count, mean, m2 = state
                hour_buckets[hour] = HourBucket.from_state(count, mean, m2)
            rebuilt[metric_name] = hour_buckets

        with self._lock:
            self._buckets = rebuilt

    def summary(self) -> BaselineSummary:
        """
        Aggregate counts describing how much has been learned so far -
        used to report restored state at startup.
        """
        with self._lock:
            metric_count = len(self._buckets)
            established = 0
            observations = 0
            for hour_buckets in self._buckets.values():
                for bucket in hour_buckets.values():
                    observations += bucket.count
                    if bucket.is_established():
                        established += 1

        return BaselineSummary(
            metric_count=metric_count,
            established_bucket_count=established,
            total_observations=observations,
        )
