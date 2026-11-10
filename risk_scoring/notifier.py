"""
notifier.py
===========

Best-effort alert channels for Module 5.

The core alert paths are console (main.py prints an ``[ALERT]`` block)
and persistence (the database). This module adds OPTIONAL desktop
notifications on top: a thin wrapper around ``plyer`` that degrades to
a no-op the moment anything is unavailable (no plyer installed, no
notification daemon, a raise inside the call). Following the project's
established philosophy, an enhancement channel that fails must never
take the capture path down with it.

``plyer`` is imported lazily and is NOT a hard dependency: everything
works without it, desktop notification is simply reported as
unavailable.
"""

from __future__ import annotations

import importlib
import threading
import time
from typing import Any, Dict, List, Optional

from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.logger import get_logger

logger = get_logger(__name__)


class DesktopNotifier:
    """
    Sends desktop notifications via ``plyer`` when available.

    ``available`` reports whether notifications can actually be sent
    (plyer importable AND ``enabled``). ``notify`` is always safe to
    call - it returns ``False`` rather than raising when unavailable.
    A per-title cooldown prevents a sustained condition from spamming
    one notification per correlated alert.
    """

    def __init__(self, enabled: bool = True, cooldown_seconds: float = 60.0) -> None:
        self.enabled = bool(enabled)
        self.cooldown_seconds = max(float(cooldown_seconds), 0.0)
        self._lock = threading.Lock()
        self._plyer: Any = None
        self._failed = False
        self._last_sent: Dict[str, float] = {}

        try:
            self._plyer = importlib.import_module("plyer")
        except ImportError:
            logger.info("plyer not installed - desktop notifications unavailable")

    @property
    def available(self) -> bool:
        """Whether desktop notifications can currently be sent."""
        return self.enabled and self._plyer is not None

    def notify(self, title: str, message: str) -> bool:
        """
        Attempt to send one desktop notification.

        Args:
            title: Short notification title.
            message: Notification body text.

        Returns:
            ``True`` if a notification was actually dispatched,
            ``False`` if unavailable, on cooldown, or on failure.
        """
        if not self.available:
            return False

        with self._lock:
            now = time.time()
            last = self._last_sent.get(title, -self.cooldown_seconds)
            if now - last < self.cooldown_seconds:
                return False
            self._last_sent[title] = now

            if self._failed:
                return False

            try:
                self._plyer.notification.notify(
                    title=title,
                    message=message,
                    app_name="cana",
                    timeout=10,
                )
                return True
            except Exception as exc:  # noqa: BLE001 - never propagate from a channel
                logger.warning("Desktop notification failed (%s: %s)", type(exc).__name__, exc)
                self._failed = True
                return False

    def notify_alert(self, alert: CorrelatedAlert) -> bool:
        """
        Send a desktop notification for one correlated alert.

        Args:
            alert: The correlated alert to announce.

        Returns:
            ``True`` if dispatched, ``False`` otherwise.
        """
        target = (
            alert.application_name
            if alert.destination_ip is None
            else f"{alert.application_name} -> {alert.destination_ip}"
        )
        title = f"[{alert.severity}] {alert.signal_count} suspicious signal(s) for {target}"
        message = alert.reason
        return self.notify(title, message)


class AlertNotifier:
    """
    A hub that fans a correlated alert out to multiple channels.

    Channels are anything with a ``notify_alert(alert) -> bool`` method
    (e.g. :class:`DesktopNotifier`). The hub never raises: a failing
    channel is logged once and skipped. Returns ``True`` if any channel
    dispatched the alert.
    """

    def __init__(self, channels: Optional[List[Any]] = None) -> None:
        self._channels: List[Any] = list(channels) if channels is not None else []

    def add_channel(self, channel: Any) -> None:
        """Register a notification channel."""
        self._channels.append(channel)

    @property
    def channels(self) -> List[Any]:
        """The registered channels."""
        return list(self._channels)

    def notify(self, alert: CorrelatedAlert) -> bool:
        """
        Dispatch one correlated alert to every registered channel.

        Returns:
            ``True`` if at least one channel dispatched the alert.
        """
        dispatched = False
        for channel in self._channels:
            try:
                if channel.notify_alert(alert):
                    dispatched = True
            except Exception as exc:  # noqa: BLE001 - never propagate from a channel
                logger.warning(
                    "Alert channel %s failed (%s: %s)",
                    type(channel).__name__,
                    type(exc).__name__,
                    exc,
                )
        return dispatched


__all__ = ["DesktopNotifier", "AlertNotifier"]
