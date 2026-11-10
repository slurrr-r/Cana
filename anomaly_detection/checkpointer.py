"""
checkpointer.py
===============

Periodically writes the in-memory baseline to disk while a capture is
running.

Why a background thread at all: the two simpler options are both worse.
Saving inside the packet path would put a synchronous disk write between
every packet and the next (thousands per second during a download), and
saving only at shutdown would hand an entire session's learning to
whatever kills the process first - which matters here precisely because
the value of the baseline is that it accumulates over many runs. A
periodic checkpoint keeps disk I/O off the packet path while bounding
worst-case loss to one interval.

A clean shutdown always performs one final synchronous save on top of
the periodic ones (see :meth:`BaselineCheckpointer.stop`), so the
interval only ever costs anything on an unclean kill.
"""

from __future__ import annotations

import threading
from typing import Optional

from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.config import BASELINE_CHECKPOINT_INTERVAL_SECONDS
from anomaly_detection.logger import get_logger, log_module_event
from anomaly_detection.store import BaselineStore

logger = get_logger(__name__)


class BaselineCheckpointer:
    """
    Saves a :class:`BaselineTracker` to a :class:`BaselineStore` on a
    fixed interval, on a daemon thread.

    Typical usage::

        checkpointer = BaselineCheckpointer(tracker, store)
        checkpointer.start()
        ...                      # capture runs
        checkpointer.stop()      # final save + clean thread exit
    """

    def __init__(
        self,
        tracker: BaselineTracker,
        store: BaselineStore,
        interval_seconds: float = BASELINE_CHECKPOINT_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive.")

        self._tracker = tracker
        self._store = store
        self._interval_seconds = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._saves_completed = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """
        Start checkpointing in the background.

        Calling this on an already-running checkpointer is a no-op, so
        it's safe on any startup path.
        """
        if self.is_running():
            return

        self._stop_event.clear()
        thread = threading.Thread(
            target=self._run,
            name="baseline-checkpointer",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        log_module_event(
            logger,
            "CHECKPOINTER_STARTED",
            detail=f"interval_seconds={self._interval_seconds}",
        )

    def stop(self, join_timeout: float = 5.0) -> bool:
        """
        Stop checkpointing and perform one final save.

        Idempotent and safe to call whether or not :meth:`start`
        succeeded - ``main.py`` calls this from several different exit
        paths (clean shutdown, capture error, unexpected exception) and
        must not have to reason about which one it's on.

        Args:
            join_timeout: How long to wait for the background thread to
                exit before proceeding with the final save anyway.

        Returns:
            Whether the final save succeeded.
        """
        self._stop_event.set()

        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_timeout)
            if thread.is_alive():
                # The thread only ever waits on an Event or performs one
                # save, so this means a save is genuinely stuck (e.g. a
                # lock-contended database). Proceeding is still correct:
                # the final save below is a full-state overwrite, so a
                # slow in-flight save can only be superseded by it, never
                # merged with it into something inconsistent.
                logger.warning(
                    "Checkpointer thread did not exit within %.1fs; "
                    "continuing with the final save anyway.",
                    join_timeout,
                )
        self._thread = None

        saved = self._save_once()
        log_module_event(
            logger,
            "CHECKPOINTER_STOPPED",
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
        """
        Save every ``interval_seconds`` until stopped.

        ``Event.wait(timeout)`` rather than ``time.sleep`` so shutdown is
        immediate: with sleep, stopping could block for up to a full
        interval (30s by default) while the user waits on a Ctrl+C that
        looks ignored.
        """
        while not self._stop_event.wait(self._interval_seconds):
            self._save_once()

    def _save_once(self) -> bool:
        """
        Take a snapshot and write it, swallowing any failure.

        The store already degrades rather than raising, but this is the
        top of a thread's call stack: an unhandled exception here would
        kill the checkpointer silently and leave the rest of the run
        believing it was still saving.
        """
        try:
            saved = self._store.save_baseline(self._tracker.snapshot())
        except Exception as exc:  # noqa: BLE001 - thread must never die
            logger.error("Baseline checkpoint failed unexpectedly: %s", exc)
            return False

        if saved:
            with self._lock:
                self._saves_completed += 1
        return saved


__all__ = ["BaselineCheckpointer"]
