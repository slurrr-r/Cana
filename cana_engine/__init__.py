"""
cana_engine
===========

Programmatic start/stop/status boundary for CANA monitoring.

Both the developer CLI (``main.py``) and the Windows service start the
same engine. The engine owns packet capture, detection, persistence,
checkpointing, health, and named-pipe status. The UI does not.
"""

from cana_engine.health import EngineStatus, HealthSnapshot

__all__ = [
    "CANAConfig",
    "CANAEngine",
    "EngineStatus",
    "HealthSnapshot",
    "load_config",
    "save_config",
]


def __getattr__(name: str):
    if name in {"CANAConfig", "load_config", "save_config"}:
        from cana_engine import config as _config

        return getattr(_config, name)
    if name == "CANAEngine":
        from cana_engine.engine import CANAEngine as _engine

        return _engine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
