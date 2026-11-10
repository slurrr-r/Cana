"""
checkpointer.py
===============

Periodically writes the in-memory risk picture to disk while a capture
is running.

This mirrors ``anomaly_detection/checkpointer.py`` for the same reason:
risk scores decay in real time, so a snapshot that is only saved at
shutdown throws away the entire session's decayed picture if the process
dies uncleanly. A periodic checkpoint keeps disk I/O off the packet path
while bounding worst-case loss to one interval.

Correlated alerts are NOT handled here: they are persisted the moment
they are emitted (in the packet handler), so this thread only has to
worry about the risk scores themselves.
"""

from __future__ import annotations

import threading
from typing import Optional

from risk_scoring.config import RISK_UPDATE_INTERVAL_SECONDS
from risk_scoring.logger import get_logger, log_module_event
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore

logger = get_logger(__name__)


class RiskCheckpointer:
    """
    Saves a :class:`RiskScorer` to a :class:`RiskStore` on a fixed
    interval, on a daemon thread.

    Typical usage::

        checkpointer = RiskCheckpointer(scorer, store)
        checkpointer.start()
        ...                      # capture runs
        checkpointer.stop()      # final save + clean thread exit
    """

    def __init__(
        self,
        scorer: RiskScorer,
        store: RiskStore,
        interval_seconds: float = RISK_UPDATE_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive.")

        self._scorer = scorer
        self._store = store
        self._interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._saves_completed = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start checkpointing in the background (idempotent)."""
        if self.is_running():
            return

        self._stop_event.clear()
        thread = threading.Thread(
            target=self._run,
            name="risk-checkpointer",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        log_module_event(
            logger,
            "RISK_CHECKPOINTER_STARTED",
            detail=f"interval_seconds={self._interval_seconds}",
        )

    def stop(self, join_timeout: float = 5.0) -> bool:
        """
        Stop checkpointing and perform one final save.

        Idempotent and safe to call from any exit path (clean shutdown,
        capture error, unexpected exception).

        Returns:
            Whether the final save succeeded.
        """
        self._stop_event.set()

        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_timeout)
            if thread.is_alive():
                logger.warning(
                    "Risk checkpointer thread did not exit within %.1fs; "
                    "continuing with the final save anyway.",
                    join_timeout,
                )
        self._thread = None

        saved = self._save_once()
        log_module_event(
            logger,
            "RISK_CHECKPOINTER_STOPPED",
            detail=f"final_save_ok={saved} total_saves={self.saves_completed}",
        )
        return saved

    def is_running(self) -> bool:
        """Whether the background checkpoint thread is currently alive."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def saves_completed(self) -> int:
        """Number of successful saves performed by this checkpointer."""
        with self._lock:
            return self._saves_completed

    # ----------------------------------------------------------------- #
    # Internals
    # ----------------------------------------------------------------- #

    def _run(self) -> None:
        """Save every ``interval_seconds`` until stopped."""
        while not self._stop_event.wait(self._interval_seconds):
            self._save_once()

    def _save_once(self) -> bool:
        """
        Take a snapshot and write it, swallowing any failure.

        The store already degrades rather than raising, but this is the
        top of a thread's call stack: an unhandled exception here would
        kill the checkpointer silently.
        """
        try:
            saved = self._store.save_risk_snapshot(self._scorer.snapshot())
        except Exception as exc:  # noqa: BLE001 - thread must never die
            logger.error("Risk checkpoint failed unexpectedly: %s", exc)
            return False

        if saved:
            with self._lock:
                self._saves_completed += 1
        return saved


__all__ = ["RiskCheckpointer"]
