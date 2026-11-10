"""
tracker.py
==========

Public API for Module 3 - User Activity Detection.

Determines whether the user is ACTIVE or IDLE based on how much time
has elapsed since the last keyboard/mouse event.

    from user_activity.tracker import ActivityTracker

    tracker = ActivityTracker()
    tracker.start()
    status = tracker.get_status()
    print(status.status)        # "ACTIVE" or "IDLE"
    print(status.idle_seconds)  # seconds since last input event
    tracker.stop()
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from user_activity.config import IDLE_THRESHOLD_SECONDS
from user_activity.listener import ActivityListener, ActivityListenerError
from user_activity.logger import get_logger, log_module_event

logger = get_logger(__name__)

STATUS_ACTIVE = "ACTIVE"
STATUS_IDLE = "IDLE"


@dataclass(frozen=True)
class ActivityStatus:
    """
    A point-in-time snapshot of the user's activity status.

    Attributes:
        status: ``"ACTIVE"`` or ``"IDLE"``.
        idle_seconds: Seconds elapsed since the last detected
            keyboard/mouse event.
        last_activity_time: Epoch timestamp of the last detected
            event.
    """

    status: str
    idle_seconds: float
    last_activity_time: float


class ActivityTracker:
    """
    Tracks user activity and classifies status as ACTIVE or IDLE.

    A custom :class:`ActivityListener` can be injected (primarily for
    testing) via the ``listener`` argument; if omitted, a real
    pynput-backed listener is created internally.
    """

    def __init__(
        self,
        idle_threshold_seconds: float = IDLE_THRESHOLD_SECONDS,
        listener: Optional[ActivityListener] = None,
    ) -> None:
        if idle_threshold_seconds <= 0:
            raise ValueError("idle_threshold_seconds must be positive.")
        self._idle_threshold_seconds = idle_threshold_seconds
        self._listener = listener if listener is not None else ActivityListener()

    def start(self) -> None:
        """
        Start tracking activity.

        Raises:
            ActivityListenerError: If the underlying input listener
                could not be started (see
                :meth:`user_activity.listener.ActivityListener.start`).
        """
        self._listener.start()
        log_module_event(
            logger,
            "TRACKER_STARTED",
            detail=f"idle_threshold_seconds={self._idle_threshold_seconds}",
        )

    def stop(self) -> None:
        """Stop tracking activity."""
        self._listener.stop()
        log_module_event(logger, "TRACKER_STOPPED")

    def get_status(self) -> ActivityStatus:
        """
        Compute the current activity status.

        Returns:
            An :class:`ActivityStatus` reflecting whether the user is
            currently ACTIVE or IDLE, and for how long.
        """
        last_activity = self._listener.get_last_activity_time()
        idle_seconds = max(0.0, time.time() - last_activity)
        status = (
            STATUS_IDLE
            if idle_seconds >= self._idle_threshold_seconds
            else STATUS_ACTIVE
        )
        return ActivityStatus(
            status=status,
            idle_seconds=idle_seconds,
            last_activity_time=last_activity,
        )

    def is_running(self) -> bool:
        """Return True if the underlying listener is currently active."""
        return self._listener.is_running()


__all__ = [
    "ActivityTracker",
    "ActivityStatus",
    "ActivityListenerError",
    "STATUS_ACTIVE",
    "STATUS_IDLE",
]
