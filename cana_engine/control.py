"""
control.py
==========

Named-pipe status and snapshot payloads for the native UI.

Privileged start/stop/config and these reads live on
``\\\\.\\pipe\\CANAControl``. There is no HTTP control plane.
"""

from __future__ import annotations

from typing import Any, Dict

from cana_engine.config import public_config_dict
from cana_engine.engine import CANAEngine
from cana_engine.health import EngineStatus
from cana_engine.queries import (
    baseline_summary,
    overview,
    recent_alerts,
    recent_correlated,
    risk_leaderboard,
)


def status_payload(engine: CANAEngine) -> Dict[str, Any]:
    """Full read-only status used by the named pipe."""
    return _status_payload(engine.status(), engine)


def snapshot_payload(engine: CANAEngine) -> Dict[str, Any]:
    """Status plus persisted overview/alerts/risk for the native UI."""
    payload = status_payload(engine)
    payload["overview"] = _safe_overview(engine)
    payload["alerts"] = _safe_alerts(engine)
    payload["risk"] = _safe_risk(engine)
    payload["baseline"] = _safe_baseline(engine)
    payload["correlated"] = _safe_correlated(engine)
    payload["config"] = public_config_dict(engine.config)
    return payload


def _safe_overview(engine: CANAEngine) -> Dict[str, Any]:
    db = engine.config.resolved_database_path()
    sessions = engine.config.resolved_sessions_dir()
    try:
        data = overview(db, sessions)
    except Exception:  # noqa: BLE001
        data = {}
    data["service"] = status_payload(engine)
    return data


def _safe_alerts(engine: CANAEngine) -> list:
    db = engine.config.resolved_database_path()
    try:
        return recent_alerts(db, 50)
    except Exception:  # noqa: BLE001
        return []


def _safe_risk(engine: CANAEngine) -> list:
    db = engine.config.resolved_database_path()
    try:
        return risk_leaderboard(db, "application", 10)
    except Exception:  # noqa: BLE001
        return []


def _safe_correlated(engine: CANAEngine) -> list:
    db = engine.config.resolved_database_path()
    try:
        return recent_correlated(db)
    except Exception:  # noqa: BLE001
        return []


def _safe_baseline(engine: CANAEngine) -> Dict[str, Any]:
    db = engine.config.resolved_database_path()
    try:
        return baseline_summary(db)
    except Exception:  # noqa: BLE001
        return {}


def _status_payload(status: EngineStatus, engine: CANAEngine) -> Dict[str, Any]:
    health = status.health.to_dict()
    return {
        "state": status.state,
        "display_state": status.display_state,
        "running": status.running,
        "capture_active": status.capture_active,
        "last_error": status.last_error,
        "health": health,
        "selected_interface": health.get("selected_interface", ""),
        "packets_processed": health.get("packets_processed", 0),
        "packets_dropped": health.get("packets_dropped", 0),
        "applications_observed": health.get("applications_observed", 0),
        "service_health": {
            "service_alive": health.get("service_alive"),
            "engine_alive": health.get("engine_alive"),
            "capture_alive": health.get("capture_alive"),
            "database_available": health.get("database_available"),
            "last_packet_at": health.get("last_packet_at"),
            "last_checkpoint_at": health.get("last_checkpoint_at"),
        },
        "config": {
            "capture_interface": engine.config.capture_interface,
            "packet_filter": engine.config.packet_filter,
            "monitoring_enabled": engine.config.monitoring_enabled,
        },
    }


__all__ = [
    "snapshot_payload",
    "status_payload",
]
