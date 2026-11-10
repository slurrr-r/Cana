"""
cana_service
============

Windows Service wrapper around ``CANAEngine``.

The service starts the engine, keeps it running, stops it cleanly, and
exposes the named-pipe control API. Detection logic lives in the engine, not
in this package.
"""

from cana_service.constants import SERVICE_DISPLAY_NAME, SERVICE_NAME

__all__ = ["SERVICE_DISPLAY_NAME", "SERVICE_NAME"]
