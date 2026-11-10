"""
orchestrator.py
================

Live orchestration for Module 4: this is the piece that actually
feeds packets into the baseline and evaluates rules against them in
real time - ties together Module 1 (packets, already app-mapped by
Module 2) and Module 3 (user activity) into a continuous stream of
ContextRecords.

This is intentionally the ONLY file in anomaly_detection that has any
awareness it will be fed data shaped like packet_capture/user_activity
output - everything else in this package (baseline, aggregator, rate
tracker, rules, context) works purely on plain dicts and
ContextRecords, with no import dependency on those other packages.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from anomaly_detection.aggregator import IdleTransferAggregator
from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.config import RATE_TRACKER_WINDOW_SECONDS
from anomaly_detection.context import build_context_record
from anomaly_detection.logger import get_logger, log_module_event
from anomaly_detection.rate_tracker import ConnectionRateTracker
from anomaly_detection.probing import ProbingDetector
from anomaly_detection.protocol_rules import ProtocolDetector
from anomaly_detection.traffic_patterns import TrafficPatternDetector
from anomaly_detection.rules import (
    METRIC_IDLE_TRANSFER_BYTES,
    METRIC_PACKET_SIZE,
    RuleResult,
    SECURITY_ALERT_RULES,
    evaluate_all_rules,
)

logger = get_logger(__name__)


class AnomalyDetectionOrchestrator:
    """
    Stateful orchestrator tying together baseline learning and rule
    evaluation for a continuous stream of packets + activity status.

    Typical usage::

        orchestrator = AnomalyDetectionOrchestrator()
        for packet in packets:
            results = orchestrator.process_packet(packet, activity_status)
            triggered = [r for r in results if r.triggered]
    """

    def __init__(
        self,
        baseline: Optional[BaselineTracker] = None,
        idle_aggregator: Optional[IdleTransferAggregator] = None,
        rate_tracker: Optional[ConnectionRateTracker] = None,
    ) -> None:
        self.baseline = baseline if baseline is not None else BaselineTracker()
        self.idle_aggregator = (
            idle_aggregator
            if idle_aggregator is not None
            else IdleTransferAggregator()
        )
        self.rate_tracker = (
            rate_tracker
            if rate_tracker is not None
            else ConnectionRateTracker(RATE_TRACKER_WINDOW_SECONDS)
        )
        self._packets_processed = 0
        self.probing_detector = ProbingDetector()
        self.protocol_detector = ProtocolDetector()
        self.traffic_detector = TrafficPatternDetector()
        self._total_triggers = 0
        # True if any packet within the CURRENT idle session has
        # triggered idle_large_transfer - see process_packet. Reset
        # once the session completes (whether learned or not).
        self._idle_session_alerted = False

    def process_packet(
        self,
        packet: Dict[str, Any],
        activity_status: Optional[Dict[str, Any]] = None,
    ) -> List[RuleResult]:
        """
        Process one packet end-to-end: build its context record,
        evaluate it against the EXISTING baseline, then selectively
        learn from observations that were not themselves flagged as
        anomalous, and return the results.

        Args:
            packet: A classified (and ideally application-mapped)
                packet dict, as produced by Module 1/2.
            activity_status: A dict shaped like
                ``user_activity.tracker.ActivityStatus.__dict__``
                (has "status" and "idle_seconds" keys), or ``None`` if
                activity tracking isn't running.

        Returns:
            A list of RuleResult - one per rule (see
            ``rules.evaluate_all_rules``).
        """
        context = build_context_record(packet, activity_status)
        self._packets_processed += 1

        # Update the running idle-transfer total (used for real-time
        # checking inside the rule itself) and detect a just-completed
        # idle session - see aggregator.py's docstring for why
        # intermediate running totals must never be fed to the
        # baseline directly. This does NOT yet decide whether to learn
        # from a completed session; that decision needs to know
        # whether the rule evaluation below flags it (see below).
        self.idle_aggregator.update(context)
        completed = self.idle_aggregator.pop_completed_session()

        # Evaluate every rule against the EXISTING baseline before any
        # learning happens this packet. This is the baseline-leakage
        # fix: an observation must be judged using only baselines
        # built from PRIOR observations, never contaminated by itself.
        results = evaluate_all_rules(
            context, self.baseline, self.idle_aggregator, self.rate_tracker
        )
        results.extend(self.probing_detector.evaluate(context))
        results.extend(self.protocol_detector.evaluate(context))
        results.extend(self.traffic_detector.evaluate(context))
        result_by_name = {result.rule_name: result for result in results}

        if result_by_name["idle_large_transfer"].triggered:
            self._idle_session_alerted = True

        # Size is diagnostic only; learn normal traffic changes instead of freezing the baseline.
        self.baseline.update(METRIC_PACKET_SIZE, context.hour_of_day, context.packet_size)

        # A completed idle session is a single logical observation. It
        # becomes eligible for learning only on completion, and only
        # if no packet within that session ever triggered
        # idle_large_transfer - an idle session that was itself
        # flagged as an anomalous transfer must not be learned as
        # "normal", the same leakage principle as packet size above.
        if completed is not None:
            completed_hour, completed_total = completed
            if completed_total > 0 and not self._idle_session_alerted:
                self.baseline.update(
                    METRIC_IDLE_TRANSFER_BYTES, completed_hour, completed_total
                )
                log_module_event(
                    logger,
                    "IDLE_SESSION_COMPLETED",
                    detail=f"hour={completed_hour} total_bytes={completed_total:.0f}",
                )
            self._idle_session_alerted = False

        self._total_triggers += sum(1 for r in results if r.triggered and r.rule_name in SECURITY_ALERT_RULES)

        return results

    @property
    def packets_processed(self) -> int:
        """Total packets processed by this orchestrator so far."""
        return self._packets_processed

    @property
    def total_triggers(self) -> int:
        """Total rule triggers (across all rules) observed so far."""
        return self._total_triggers
