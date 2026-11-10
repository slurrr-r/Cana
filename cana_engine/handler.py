"""
handler.py
==========

Packet-handler wiring shared by the CLI and the CANA engine.

Moved out of ``main.py`` so the Windows service and developer CLI use
the same rising-edge alert / risk / correlation path. Detection rules
are unchanged.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Set

from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.rules import SECURITY_ALERT_RULES, connection_rate_peer
from anomaly_detection.utils import format_alert
from packet_capture.logger import get_logger
from packet_capture.session import SessionManager
from risk_scoring.correlator import AlertCorrelator
from risk_scoring.notifier import AlertNotifier
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore
from risk_scoring.utils import format_correlated_alert
from user_activity.tracker import ActivityTracker
from anomaly_detection.store import BaselineStore

logger = get_logger(__name__)


def build_packet_handler(
    orchestrator: AnomalyDetectionOrchestrator,
    activity_tracker: Optional[ActivityTracker],
    store: Optional[BaselineStore] = None,
    session_manager: Optional[SessionManager] = None,
    risk_scorer: Optional[RiskScorer] = None,
    correlator: Optional[AlertCorrelator] = None,
    notifier: Optional[AlertNotifier] = None,
    risk_store: Optional[RiskStore] = None,
    print_alerts: bool = True,
    on_processed: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Callable[[Dict[str, Any]], None]:
    """
    Build the ``on_packet`` callback wiring live capture into Module 3
    (user activity), Module 4 (anomaly detection), and Module 5 (risk
    scoring + correlation).

    Alerts are only printed on the "rising edge" of a rule's triggered
    state - once when a condition starts, not on every subsequent
    packet while it remains true.

    De-dup is keyed on ``(rule_name, application_name, remote_peer)``.
    """
    active_alert_keys: Set[Any] = set()

    def current_session_id() -> Optional[str]:
        if session_manager is None:
            return None
        session = session_manager.current_session
        return session.session_id if session is not None else None

    def handle_packet(packet: Dict[str, Any]) -> None:
        activity_status = None
        if activity_tracker is not None and activity_tracker.is_running():
            status = activity_tracker.get_status()
            activity_status = {
                "status": status.status,
                "idle_seconds": status.idle_seconds,
            }

        results = orchestrator.process_packet(packet, activity_status)
        for result in results:
            # Unvalidated observations must not enter alerts, risk or correlation.
            if result.rule_name not in SECURITY_ALERT_RULES:
                continue
            alert_key = (
                result.rule_name,
                result.context.application_name,
                connection_rate_peer(result.context),
            )
            if result.triggered and alert_key not in active_alert_keys:
                active_alert_keys.add(alert_key)
                if print_alerts:
                    print(format_alert(result))
                if store is not None:
                    try:
                        store.record_alert(result, current_session_id())
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Failed to record alert: %s", exc)

                if risk_scorer is not None:
                    risk_scorer.record(result)
                if correlator is not None:
                    correlated = correlator.observe(result)
                    if correlated is not None:
                        if print_alerts:
                            print(format_correlated_alert(correlated))
                        if risk_store is not None:
                            try:
                                risk_store.save_correlated_alert(correlated)
                            except Exception as exc:  # noqa: BLE001
                                logger.error(
                                    "Failed to record correlated alert: %s", exc
                                )
                        if notifier is not None:
                            try:
                                notifier.notify(correlated)
                            except Exception as exc:  # noqa: BLE001
                                logger.error(
                                    "Failed to notify correlated alert: %s", exc
                                )
            elif not result.triggered and alert_key in active_alert_keys:
                active_alert_keys.discard(alert_key)

        if on_processed is not None:
            try:
                on_processed(packet)
            except Exception as exc:  # noqa: BLE001
                logger.error("on_processed callback raised: %s", exc)

    return handle_packet


__all__ = ["build_packet_handler"]
