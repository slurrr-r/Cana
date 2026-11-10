"""
listener.py
===========

Low-level keyboard/mouse activity listener, built on ``pynput``.

Critical design constraint: ``pynput`` requires a live GUI/input
backend (X11 on Linux, a display session on Windows/macOS) and raises
an ``ImportError`` at import time in headless environments where no
such backend exists. To keep this module (and everything that depends
on it) importable and unit-testable everywhere, ``pynput`` is imported
lazily - only inside :meth:`ActivityListener.start`, never at module
load time.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from user_activity.logger import get_logger, log_module_event

logger = get_logger(__name__)


class ActivityListenerError(Exception):
    """Raised when the underlying input listener cannot be started."""


class ActivityListener:
    """
    Wraps pynput's mouse and keyboard listeners, updating a shared,
    thread-safe "last activity" timestamp whenever any input event
    occurs system-wide.

    pynput's listeners run their own background threads internally,
    so this class does not spawn additional threads of its own - it
    only needs a lock to guard the shared timestamp, since pynput's
    callback threads and any reader thread could access it
    concurrently.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_activity_time: float = time.time()
        self._mouse_listener: Optional[Any] = None
        self._keyboard_listener: Optional[Any] = None
        self._running = False

    def _on_activity(self, *args: Any, **kwargs: Any) -> None:
        """Callback invoked by pynput on any mouse/keyboard event."""
        with self._lock:
            self._last_activity_time = time.time()

    def start(self) -> None:
        """
        Start listening for keyboard and mouse activity.

        Raises:
            ActivityListenerError: If pynput is not installed, or if
                the platform's input backend could not be initialized
                (e.g. no display/X server available).
        """
        if self._running:
            logger.warning("Activity listener already running; start() ignored.")
            return

        try:
            from pynput import keyboard, mouse
        except ImportError as exc:
            raise ActivityListenerError(
                "pynput is not installed or failed to import."
            ) from exc

        try:
            self._mouse_listener = mouse.Listener(
                on_move=self._on_activity,
                on_click=self._on_activity,
                on_scroll=self._on_activity,
            )
            self._keyboard_listener = keyboard.Listener(
                on_press=self._on_activity,
                on_release=self._on_activity,
            )
            self._mouse_listener.start()
            self._keyboard_listener.start()
        except Exception as exc:  # noqa: BLE001 - backend init errors vary by OS
            raise ActivityListenerError(
                f"Failed to start input listeners (no display/input backend "
                f"available?): {exc}"
            ) from exc

        with self._lock:
            self._last_activity_time = time.time()
        self._running = True
        log_module_event(logger, "LISTENER_STARTED")

    def stop(self) -> None:
        """Stop listening for keyboard and mouse activity."""
        if self._mouse_listener is not None:
            self._mouse_listener.stop()
            self._mouse_listener = None
        if self._keyboard_listener is not None:
            self._keyboard_listener.stop()
            self._keyboard_listener = None
        self._running = False
        log_module_event(logger, "LISTENER_STOPPED")

    def get_last_activity_time(self) -> float:
        """Return the epoch timestamp of the most recent input event."""
        with self._lock:
            return self._last_activity_time

    def record_activity(self) -> None:
        """
        Manually record activity "now".

        Exposed as a public method (not just the private callback) so
        tests - and any caller with an alternative activity signal -
        can simulate/inject an activity event without needing a real
        pynput backend.
        """
        self._on_activity()

    def is_running(self) -> bool:
        """Return True if the listener is currently active."""
        return self._running
