"""
rules.py
========

The explainable rule set for Module 4: four rules, each returning a
human-readable ``reason`` string (Module 5 will need to show WHY
something was flagged, not just THAT it was).

Design note: rules check against a learned BaselineTracker where a
meaningful baseline exists, falling back to a fixed sanity threshold
during cold-start. This is an explicit, acknowledged limitation, not
hidden - each rule's reason string says which basis it used.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from anomaly_detection.aggregator import IdleTransferAggregator
from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.config import (
    FALLBACK_LARGE_TRANSFER_BYTES,
    MIN_RATE_SAMPLES_FOR_BASELINE,
)
from anomaly_detection.context import ContextRecord
from anomaly_detection.logger import get_logger, log_module_event
from anomaly_detection.rate_tracker import ConnectionRateTracker

logger = get_logger(__name__)

SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"

METRIC_IDLE_TRANSFER_BYTES = "idle_transfer_bytes"
METRIC_PACKET_SIZE = "packet_size"
METRIC_CONNECTION_RATE = "connection_rate"

# Only these rules passed positive packet replay and the bounded benign checks.
# This is sample-level evidence, not production certification (see README).
SECURITY_ALERT_RULES = frozenset({
    "tcp_port_probe", "inbound_tcp_port_probe", "unusual_tcp_flags",
})

# Communication types that are never "talking to the internet".
_LOCAL_ONLY_COMM_TYPES = frozenset({"LOCAL_NETWORK", "BROADCAST", "MULTICAST"})

# Protocols that legitimately never have an owning application/process
# (see project discussion - ICMP is kept in scope for its own security
# value, but flagging every ping as "unknown app" would be pure noise).
_NON_APPLICATION_PROTOCOLS = frozenset({"ICMP", "ICMPV6"})


def connection_rate_peer(context: ContextRecord) -> str:
    """
    Return the remote endpoint identity for connection-rate tracking.

    Outbound packets target ``destination_ip``; inbound packets
    originate at the remote host, so the remote peer is
    ``source_ip`` instead. Always using ``destination_ip`` (as before
    this fix) would use the LOCAL machine's own address as the "peer"
    for every inbound packet, silently pooling every distinct remote
    peer that talks to this app into one shared identity.
    """
    if context.direction == "INCOMING":
        return context.source_ip or "UNKNOWN_PEER"
    return context.destination_ip or "UNKNOWN_PEER"


def connection_rate_metric_name(application_name: str, peer: str) -> str:
    """
    Build the canonical baseline identity for connection-rate
    measurement, learning, and lookup.

    Kept as a single named function (rather than each call site
    formatting its own string) so measurement, baseline storage, and
    rule evaluation can never drift apart into inconsistent key
    formats for the same underlying (application, peer) pair.
    """
    return f"{METRIC_CONNECTION_RATE}:{application_name}:{peer}"


@dataclass(frozen=True)
class RuleResult:
    """
    The outcome of evaluating one rule against one ContextRecord.

    Attributes:
        rule_name: Stable, machine-readable rule identifier.
        triggered: Whether this rule fired.
        severity: "LOW", "MEDIUM", or "HIGH".
        reason: Human-readable explanation of the verdict - always
            populated, whether triggered or not, so callers/tests can
            see *why* a rule did or didn't fire.
        context: The ContextRecord this result was computed from.
    """

    rule_name: str
    triggered: bool
    severity: str
    reason: str
    context: ContextRecord


def idle_large_transfer_rule(
    context: ContextRecord,
    baseline: BaselineTracker,
    aggregator: IdleTransferAggregator,
) -> RuleResult:
    """
    Flags large cumulative data transfer while the user is IDLE -
    checked against the LEARNED BASELINE for this hour of day (falling
    back to a fixed sanity threshold during cold-start), so routine
    behavior like streaming video in the evening isn't flagged just
    because it's large in absolute terms. See the "movie night"
    scenario from the project design discussion.
    """
    # The orchestrator already incorporates every packet into the
    # aggregator before rules are evaluated (see orchestrator.py). Do
    # NOT call aggregator.update(context) again here - that would add
    # this same packet's bytes into the running idle-window total a
    # second time, inflating both this rule's live verdict and, once
    # the session completes, the value fed into the baseline.
    cumulative_bytes = aggregator.current_accumulated_bytes

    if context.user_status != "IDLE":
        return RuleResult(
            rule_name="idle_large_transfer",
            triggered=False,
            severity=SEVERITY_LOW,
            reason="User is active; this rule only applies while idle.",
            context=context,
        )

    bucket = baseline.get_bucket(METRIC_IDLE_TRANSFER_BYTES, context.hour_of_day)
    if bucket is not None and bucket.is_established():
        is_anomalous = bucket.is_anomalous(cumulative_bytes)
        basis = (
            f"learned baseline for this hour (mean={bucket.mean:.0f}B, "
            f"std_dev={bucket.std_dev:.0f}B)"
        )
    else:
        is_anomalous = cumulative_bytes > FALLBACK_LARGE_TRANSFER_BYTES
        basis = (
            f"fixed fallback threshold of {FALLBACK_LARGE_TRANSFER_BYTES}B "
            f"(baseline not yet established for this hour)"
        )

    if is_anomalous:
        return RuleResult(
            rule_name="idle_large_transfer",
            triggered=True,
            severity=SEVERITY_MEDIUM,
            reason=(
                f"{cumulative_bytes:.0f} bytes transferred while idle for "
                f"{context.idle_seconds:.0f}s - unusual compared to {basis}."
            ),
            context=context,
        )

    return RuleResult(
        rule_name="idle_large_transfer",
        triggered=False,
        severity=SEVERITY_LOW,
        reason=(
            f"Idle transfer volume ({cumulative_bytes:.0f}B) is within "
            f"normal range ({basis})."
        ),
        context=context,
    )


def unknown_application_internet_rule(context: ContextRecord) -> RuleResult:
    """
    Flags TCP/UDP traffic to/from the internet (not local network,
    broadcast, or multicast) where no owning application could be
    identified. ICMP/ICMPv6 are explicitly excluded, since those
    legitimately have no owning process by design and would otherwise
    spam an alert on every ping/router-discovery packet.
    """
    is_unknown_app = context.application_name == "UNKNOWN"
    is_internet_traffic = context.communication_type == "INTERNET"
    is_process_owned_protocol = context.protocol in {"TCP", "UDP"}

    triggered = is_unknown_app and is_internet_traffic and is_process_owned_protocol

    if triggered:
        return RuleResult(
            rule_name="unknown_application_internet",
            triggered=True,
            severity=SEVERITY_MEDIUM,
            reason=(
                f"{context.protocol} traffic to/from the internet "
                f"({context.source_ip} -> {context.destination_ip}) has no "
                f"identifiable owning application. Attribution can fail because of "
                f"permissions or short-lived sockets; this alone is not evidence of malware."
            ),
            context=context,
        )

    if not is_unknown_app:
        reason = (
            f"Traffic is attributed to a known application "
            f"({context.application_name})."
        )
    elif not is_internet_traffic:
        reason = f"Traffic is {context.communication_type}, not internet-facing."
    else:
        reason = f"{context.protocol} is exempt (no owning process by design)."

    return RuleResult(
        rule_name="unknown_application_internet",
        triggered=False,
        severity=SEVERITY_LOW,
        reason=reason,
        context=context,
    )


def packet_size_anomaly_rule(
    context: ContextRecord, baseline: BaselineTracker
) -> RuleResult:
    """
    Diagnostic comparison of packet size with the hourly baseline.
    The handler excludes this weak signal from security alerts and scoring.
    """
    bucket = baseline.get_bucket(METRIC_PACKET_SIZE, context.hour_of_day)

    if bucket is None or not bucket.is_established():
        return RuleResult(
            rule_name="packet_size_anomaly",
            triggered=False,
            severity=SEVERITY_LOW,
            reason="Baseline not yet established for this hour; skipping check.",
            context=context,
        )

    if bucket.is_anomalous(context.packet_size):
        return RuleResult(
            rule_name="packet_size_anomaly",
            triggered=True,
            severity=SEVERITY_LOW,
            reason=(
                f"Packet size {context.packet_size}B is a statistical outlier "
                f"for this hour (baseline mean={bucket.mean:.0f}B, "
                f"std_dev={bucket.std_dev:.0f}B)."
            ),
            context=context,
        )

    return RuleResult(
        rule_name="packet_size_anomaly",
        triggered=False,
        severity=SEVERITY_LOW,
        reason=(
            f"Packet size {context.packet_size}B is within normal range "
            f"(baseline mean={bucket.mean:.0f}B)."
        ),
        context=context,
    )


def connection_rate_anomaly_rule(
    context: ContextRecord,
    baseline: BaselineTracker,
    rate_tracker: ConnectionRateTracker,
) -> RuleResult:
    """
    Flags an unusually high rate of packets between one application
    and one remote peer in a short time window - checked against a
    LEARNED, PER-APPLICATION-AND-PEER BASELINE for this hour.

    Three things distinguish this from a naive fixed-threshold rate
    check, driven by real feedback on earlier versions of this rule:

    1. **Per-application-and-peer scoping.** A quiet background
       service and an actively browsed tab don't share a meaningful
       "normal" rate - pooling every app's connection rate into one
       shared baseline guarantees a bad baseline no matter how much
       data feeds it. Nor do two different remote peers for the same
       app necessarily share one: a steady backend connection and a
       bursty CDN fetch from the same app have different normal
       rates, so unrelated peers must not be able to contaminate each
       other's baseline. The metric name is therefore scoped by BOTH
       application and remote peer
       (``connection_rate:<application_name>:<peer>`` - see
       :func:`connection_rate_metric_name`), and the peer is resolved
       direction-aware (see :func:`connection_rate_peer`) so inbound
       traffic doesn't get keyed by the local machine's own address.
    2. **A higher, rate-specific sample requirement
       (``MIN_RATE_SAMPLES_FOR_BASELINE``, not the global default).**
       Connection rate is bursty and noisy (a page load spikes, then
       goes quiet) - too few samples produces a falsely tight
       std-dev, making ordinary jitter look anomalous.
    3. **Evaluate against the pre-existing baseline only, then learn.**
       The current sample is judged using whatever baseline already
       existed BEFORE this observation - it is only added to the
       baseline afterward, and only when it was not itself flagged as
       anomalous. Learning from the sample before judging it (as an
       earlier version of this rule did) would let a genuine burst
       relax the very threshold that should catch it.

    There is deliberately no fixed fallback threshold here (contrast
    with ``idle_large_transfer_rule``): a single global "N pkt/s is
    suspicious for everyone" number has the same flaw as the pooled
    baseline it replaces. This rule simply reports "not enough data
    yet" until a real, per-application-and-peer baseline exists - same
    pattern as ``packet_size_anomaly_rule``.
    """
    peer = connection_rate_peer(context)
    rate, should_sample = rate_tracker.record(context.application_name, peer)
    metric_name = connection_rate_metric_name(context.application_name, peer)

    bucket = baseline.get_bucket(metric_name, context.hour_of_day)

    if bucket is None or not bucket.is_established(MIN_RATE_SAMPLES_FOR_BASELINE):
        observed = bucket.count if bucket is not None else 0
        result = RuleResult(
            rule_name="connection_rate_anomaly",
            triggered=False,
            severity=SEVERITY_LOW,
            reason=(
                f"Not enough data yet to judge {context.application_name}'s "
                f"normal connection rate with {peer} for this hour "
                f"({observed}/{MIN_RATE_SAMPLES_FOR_BASELINE} samples "
                f"collected) - skipping check."
            ),
            context=context,
        )
    else:
        is_anomalous = bucket.is_anomalous(rate, MIN_RATE_SAMPLES_FOR_BASELINE)
        basis = (
            f"learned baseline for {context.application_name} communicating "
            f"with {peer} at this hour "
            f"(mean={bucket.mean:.1f} pkt/s, std_dev={bucket.std_dev:.1f} pkt/s)"
        )

        if is_anomalous:
            result = RuleResult(
                rule_name="connection_rate_anomaly",
                triggered=True,
                severity=SEVERITY_MEDIUM,
                reason=(
                    f"{context.application_name} is exchanging {rate:.1f} "
                    f"packets/sec with {peer} - unusual compared to {basis}."
                ),
                context=context,
            )
        else:
            result = RuleResult(
                rule_name="connection_rate_anomaly",
                triggered=False,
                severity=SEVERITY_LOW,
                reason=(
                    f"Connection rate ({rate:.1f} pkt/s) is within normal "
                    f"range ({basis})."
                ),
                context=context,
            )

    # Only a non-anomalous, throttled sample is eligible to train the
    # baseline - an outlier must never get to relax the very threshold
    # that judged it (baseline-leakage fix, same principle applied to
    # packet_size_anomaly_rule in orchestrator.py).
    if should_sample and not result.triggered:
        baseline.update(metric_name, context.hour_of_day, rate)

    return result


def evaluate_all_rules(
    context: ContextRecord,
    baseline: BaselineTracker,
    idle_aggregator: IdleTransferAggregator,
    rate_tracker: ConnectionRateTracker,
) -> List[RuleResult]:
    """
    Run every rule against one ContextRecord.

    Args:
        context: The record to evaluate.
        baseline: The shared BaselineTracker (see baseline.py).
        idle_aggregator: The shared IdleTransferAggregator (see
            aggregator.py) - must be the SAME instance across calls
            for a given capture session, since it carries state
            across packets.
        rate_tracker: The shared ConnectionRateTracker (see
            rate_tracker.py) - same statefulness requirement as
            idle_aggregator.

    Returns:
        A list of RuleResult, one per rule, for BOTH triggered and
        non-triggered outcomes - filter by ``.triggered`` for just the
        ones that fired. Returning all results (not just triggered
        ones) keeps this fully transparent/testable.
    """
    results = [
        idle_large_transfer_rule(context, baseline, idle_aggregator),
        unknown_application_internet_rule(context),
        packet_size_anomaly_rule(context, baseline),
        connection_rate_anomaly_rule(context, baseline, rate_tracker),
    ]

    for result in results:
        if result.triggered and result.rule_name in SECURITY_ALERT_RULES:
            log_module_event(
                logger,
                "RULE_TRIGGERED",
                detail=(
                    f"{result.rule_name} | severity={result.severity} | "
                    f"{result.reason}"
                ),
            )

    return results
