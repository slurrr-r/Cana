"""
health.py
=========

Engine and capture health state.

"Running" is not merely "a Windows service process exists". Health
reports whether the engine, capture worker, database, and checkpointers
are actually alive, plus the last packet/checkpoint timestamps.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

STATE_STOPPED = "stopped"
STATE_STARTING = "starting"
STATE_MONITORING = "monitoring"
STATE_PROTECTED = "protected"
STATE_CAPTURE_UNAVAILABLE = "capture_unavailable"
STATE_SERVICE_ERROR = "service_error"
STATE_STOPPING = "stopping"

DISPLAY_STATES = {
    STATE_PROTECTED: "Protected",
    STATE_MONITORING: "Monitoring",
    STATE_STARTING: "Starting",
    STATE_STOPPED: "Stopped",
    STATE_CAPTURE_UNAVAILABLE: "Capture Unavailable",
    STATE_SERVICE_ERROR: "Unavailable",
    STATE_STOPPING: "Stopped",
}


@dataclass
class HealthSnapshot:
    """Point-in-time health of the CANA engine."""

    service_alive: bool = False
    engine_alive: bool = False
    capture_alive: bool = False
    database_available: bool = False
    worker_threads_alive: bool = False
    last_packet_at: Optional[float] = None
    last_checkpoint_at: Optional[float] = None
    packets_processed: int = 0
    packets_dropped: int = 0
    applications_observed: int = 0
    selected_interface: str = ""
    capture_interface_name: str = ""
    packet_filter: str = "ALL"
    ui_state: str = STATE_STOPPED
    display_state: str = DISPLAY_STATES[STATE_STOPPED]
    last_error: str = ""
    capture_error: str = ""
    monitoring_enabled: bool = True
    started_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EngineStatus:
    """Public status returned by ``CANAEngine.status()``."""

    state: str = STATE_STOPPED
    display_state: str = DISPLAY_STATES[STATE_STOPPED]
    health: HealthSnapshot = field(default_factory=HealthSnapshot)
    running: bool = False
    capture_active: bool = False
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return payload


def derive_ui_state(
    *,
    engine_alive: bool,
    capture_alive: bool,
    monitoring_enabled: bool,
    capture_error: str,
    last_error: str,
    starting: bool,
) -> str:
    """Map live engine facts onto the UI service-state labels."""
    if last_error and not engine_alive and not starting:
        return STATE_SERVICE_ERROR
    if starting:
        return STATE_STARTING
    if not engine_alive or not monitoring_enabled:
        return STATE_STOPPED
    if capture_error or not capture_alive:
        return STATE_CAPTURE_UNAVAILABLE
    return STATE_PROTECTED


__all__ = [
    "DISPLAY_STATES",
    "EngineStatus",
    "HealthSnapshot",
    "STATE_CAPTURE_UNAVAILABLE",
    "STATE_MONITORING",
    "STATE_PROTECTED",
    "STATE_SERVICE_ERROR",
    "STATE_STARTING",
    "STATE_STOPPED",
    "STATE_STOPPING",
    "derive_ui_state",
]
