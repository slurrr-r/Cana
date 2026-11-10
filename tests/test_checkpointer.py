"""
Unit tests for anomaly_detection.checkpointer.

The checkpointer's interval is injectable specifically so these tests
run at 0.01s instead of the production 30s. Where a test has to wait for
a background thread, it polls against a deadline rather than sleeping a
fixed amount, so it stays reliable on a loaded machine without being
slow on an idle one.
"""

from __future__ import annotations

import threading
import time

import pytest

from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.checkpointer import BaselineCheckpointer
from anomaly_detection.store import BaselineStore

_DEADLINE_SECONDS = 5.0
_FAST_INTERVAL = 0.01
_THREAD_NAME = "baseline-checkpointer"


class FakeStore:
    """
    Records every snapshot handed to it.

    Stands in for BaselineStore where a test cares about *when and what*
    the checkpointer saves rather than about SQLite behavior, and lets a
    save be made to fail on demand.
    """

    def __init__(self, *, succeed: bool = True, raises: bool = False) -> None:
        self.succeed = succeed
        self.raises = raises
        self.snapshots = []
        self._lock = threading.Lock()

    def save_baseline(self, snapshot) -> bool:
        if self.raises:
            raise RuntimeError("simulated store failure")
        with self._lock:
            self.snapshots.append(snapshot)
        return self.succeed

    @property
    def save_count(self) -> int:
        with self._lock:
            return len(self.snapshots)


def _wait_until(predicate, timeout: float = _DEADLINE_SECONDS) -> bool:
    """Poll ``predicate`` until it is true or the deadline passes."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def _checkpointer_thread_count() -> int:
    return sum(1 for t in threading.enumerate() if t.name == _THREAD_NAME)


class TestConstruction:
    def test_non_positive_interval_is_rejected(self) -> None:
        """
        A zero or negative interval would make the wait loop spin,
        burning a core for the whole capture. Better to fail loudly at
        construction than to ship a busy-wait.
        """
        tracker = BaselineTracker()
        store = FakeStore()

        with pytest.raises(ValueError):
            BaselineCheckpointer(tracker, store, interval_seconds=0)
        with pytest.raises(ValueError):
            BaselineCheckpointer(tracker, store, interval_seconds=-1.0)

    def test_a_fresh_checkpointer_is_not_running(self) -> None:
        checkpointer = BaselineCheckpointer(BaselineTracker(), FakeStore())
        assert checkpointer.is_running() is False
        assert checkpointer.saves_completed == 0


class TestPeriodicSaving:
    def test_saves_repeatedly_while_running(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", 10, 500.0)
        store = FakeStore()
        checkpointer = BaselineCheckpointer(
            tracker, store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        try:
            assert checkpointer.is_running() is True
            assert _wait_until(lambda: checkpointer.saves_completed >= 3)
        finally:
            checkpointer.stop()

    def test_each_save_captures_the_state_at_that_moment(self) -> None:
        """
        The checkpointer must snapshot on every tick, not reuse a
        snapshot taken at start(): the whole point is to persist learning
        that accumulates *during* the run.
        """
        tracker = BaselineTracker()
        store = FakeStore()
        checkpointer = BaselineCheckpointer(
            tracker, store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        try:
            assert _wait_until(lambda: store.save_count >= 1)
            first_snapshot = store.snapshots[0]

            for value in [100.0, 200.0, 300.0]:
                tracker.update("packet_size", 10, value)

            assert _wait_until(
                lambda: any(
                    snapshot.get("packet_size", {}).get(10, (0,))[0] == 3
                    for snapshot in list(store.snapshots)
                )
            )
        finally:
            checkpointer.stop()

        # The early snapshot stays as it was - snapshot() returns plain
        # tuples, so a saved snapshot can't be mutated after the fact by
        # continued tracker updates.
        assert first_snapshot == {}

    def test_start_is_idempotent(self) -> None:
        """
        main.py may call start() from a path that has already started it;
        a second call must not leave an orphaned second thread writing to
        the same database.
        """
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), FakeStore(), interval_seconds=_FAST_INTERVAL
        )
        before = _checkpointer_thread_count()

        checkpointer.start()
        checkpointer.start()
        try:
            assert _checkpointer_thread_count() == before + 1
        finally:
            checkpointer.stop()


class TestStop:
    def test_stop_performs_a_final_save_and_ends_the_thread(self) -> None:
        """
        The final synchronous save is what makes the 30s interval
        acceptable in production: a clean Ctrl+C never loses the last
        partial interval of learning.
        """
        tracker = BaselineTracker()
        store = FakeStore()
        checkpointer = BaselineCheckpointer(
            tracker, store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        assert _wait_until(lambda: checkpointer.saves_completed >= 1)
        saves_before_stop = checkpointer.saves_completed

        tracker.update("packet_size", 4, 700.0)
        assert checkpointer.stop() is True

        assert checkpointer.is_running() is False
        assert checkpointer.saves_completed > saves_before_stop
        # The last thing written is the state as of the stop call.
        assert store.snapshots[-1]["packet_size"][4][0] == 1

    def test_stop_without_start_still_saves(self) -> None:
        """
        main.py's exit paths call stop() unconditionally, including ones
        reached before the checkpointer ever started. That must persist
        the baseline rather than raise.
        """
        tracker = BaselineTracker()
        tracker.update("packet_size", 2, 250.0)
        store = FakeStore()
        checkpointer = BaselineCheckpointer(tracker, store)

        assert checkpointer.stop() is True
        assert store.save_count == 1
        assert store.snapshots[0]["packet_size"][2][0] == 1

    def test_stop_is_idempotent(self) -> None:
        tracker = BaselineTracker()
        store = FakeStore()
        checkpointer = BaselineCheckpointer(
            tracker, store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        checkpointer.stop()
        assert checkpointer.stop() is True
        assert checkpointer.is_running() is False

    def test_stop_returns_false_when_the_final_save_fails(self) -> None:
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), FakeStore(succeed=False), interval_seconds=1.0
        )
        assert checkpointer.stop() is False

    def test_shutdown_does_not_wait_a_full_interval(self) -> None:
        """
        The loop waits on an Event rather than sleeping, so stopping is
        near-instant. With time.sleep, a Ctrl+C would appear ignored for
        up to a full interval (30s in production).
        """
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), FakeStore(), interval_seconds=30.0
        )
        checkpointer.start()

        started = time.monotonic()
        checkpointer.stop(join_timeout=5.0)
        elapsed = time.monotonic() - started

        assert elapsed < 2.0
        assert checkpointer.is_running() is False

    def test_checkpointer_thread_is_a_daemon(self) -> None:
        """
        A non-daemon thread would keep the interpreter alive after the
        capture ends if stop() were ever missed.
        """
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), FakeStore(), interval_seconds=1.0
        )
        checkpointer.start()
        try:
            threads = [t for t in threading.enumerate() if t.name == _THREAD_NAME]
            assert threads and all(t.daemon for t in threads)
        finally:
            checkpointer.stop()


class TestFailureTolerance:
    def test_a_failing_store_does_not_stop_checkpointing(self) -> None:
        store = FakeStore(succeed=False)
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        try:
            assert _wait_until(lambda: store.save_count >= 3)
            # Attempts happened, none counted as successful.
            assert checkpointer.saves_completed == 0
            assert checkpointer.is_running() is True
        finally:
            checkpointer.stop()

    def test_a_raising_store_does_not_kill_the_thread(self) -> None:
        """
        _save_once sits at the top of a thread's call stack. An
        unhandled exception there would kill the checkpointer silently
        and leave the rest of the run believing it was still saving.
        """
        store = FakeStore(raises=True)
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        try:
            time.sleep(0.1)  # several intervals' worth of failures
            assert checkpointer.is_running() is True
            assert checkpointer.saves_completed == 0
        finally:
            assert checkpointer.stop() is False


class TestWithRealStore:
    def test_checkpointed_baseline_is_readable_afterwards(self, tmp_path) -> None:
        """
        End-to-end through real SQLite: what the checkpointer writes in
        the background is exactly what the next run will load.
        """
        db_path = tmp_path / "baseline.db"
        tracker = BaselineTracker()
        for value in [900.0, 1000.0, 1100.0]:
            tracker.update("packet_size", 17, value)

        checkpointer = BaselineCheckpointer(
            tracker, BaselineStore(db_path), interval_seconds=_FAST_INTERVAL
        )
        checkpointer.start()
        assert _wait_until(lambda: checkpointer.saves_completed >= 2)
        checkpointer.stop()

        reloaded = BaselineTracker()
        reloaded.restore(BaselineStore(db_path).load_baseline())
        bucket = reloaded.get_bucket("packet_size", 17)

        assert bucket.count == 3
        assert bucket.mean == pytest.approx(1000.0)

    def test_repeated_checkpoints_do_not_inflate_the_baseline(
        self, tmp_path
    ) -> None:
        """
        The accumulate-vs-replace bug would only ever show up here: many
        saves of an unchanging snapshot must leave the stored count
        exactly as it is.
        """
        db_path = tmp_path / "baseline.db"
        tracker = BaselineTracker()
        for value in [10.0, 20.0, 30.0, 40.0, 50.0]:
            tracker.update("packet_size", 3, value)

        checkpointer = BaselineCheckpointer(
            tracker, BaselineStore(db_path), interval_seconds=_FAST_INTERVAL
        )
        checkpointer.start()
        assert _wait_until(lambda: checkpointer.saves_completed >= 10)
        checkpointer.stop()

        loaded = BaselineStore(db_path).load_baseline()
        assert loaded["packet_size"][3][0] == 5
        assert loaded["packet_size"][3][1] == pytest.approx(30.0)

    def test_unwritable_database_is_survivable(self, tmp_path) -> None:
        """
        A store that can never work must not turn into a crashing
        background thread - the run should simply proceed without
        persistence.
        """
        blocker = tmp_path / "not_a_directory"
        blocker.write_text("", encoding="utf-8")

        store = BaselineStore(blocker / "baseline.db")
        checkpointer = BaselineCheckpointer(
            BaselineTracker(), store, interval_seconds=_FAST_INTERVAL
        )

        checkpointer.start()
        try:
            time.sleep(0.1)
            assert checkpointer.is_running() is True
        finally:
            assert checkpointer.stop() is False

        assert store.available is False
        assert checkpointer.saves_completed == 0
