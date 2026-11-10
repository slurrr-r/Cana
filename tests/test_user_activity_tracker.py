"""Unit tests for user_activity.tracker."""

from __future__ import annotations

import time
from typing import Optional

import pytest

from user_activity.listener import ActivityListener
from user_activity.tracker import (
    STATUS_ACTIVE,
    STATUS_IDLE,
    ActivityStatus,
    ActivityTracker,
)


class _FakeListener(ActivityListener):
    """
    A controllable fake listener for tracker tests - avoids needing
    any real (or fake-pynput) input backend at all, since tracker
    logic only depends on ``get_last_activity_time()`` /
    ``start()`` / ``stop()`` / ``is_running()``.
    """

    def __init__(self, initial_last_activity: Optional[float] = None) -> None:
        super().__init__()
        if initial_last_activity is not None:
            self._last_activity_time = initial_last_activity
        self.start_called = False
        self.stop_called = False

    def start(self) -> None:
        self.start_called = True
        self._running = True

    def stop(self) -> None:
        self.stop_called = True
        self._running = False


class TestActivityTrackerStatus:
    def test_recent_activity_is_active(self) -> None:
        fake = _FakeListener(initial_last_activity=time.time())
        tracker = ActivityTracker(idle_threshold_seconds=300, listener=fake)
        status = tracker.get_status()
        assert status.status == STATUS_ACTIVE

    def test_old_activity_is_idle(self) -> None:
        long_ago = time.time() - 400  # older than default 300s threshold
        fake = _FakeListener(initial_last_activity=long_ago)
        tracker = ActivityTracker(idle_threshold_seconds=300, listener=fake)
        status = tracker.get_status()
        assert status.status == STATUS_IDLE

    def test_exactly_at_threshold_is_idle(self) -> None:
        exactly_threshold_ago = time.time() - 300
        fake = _FakeListener(initial_last_activity=exactly_threshold_ago)
        tracker = ActivityTracker(idle_threshold_seconds=300, listener=fake)
        status = tracker.get_status()
        assert status.status == STATUS_IDLE

    def test_custom_threshold_respected(self) -> None:
        ten_seconds_ago = time.time() - 10
        fake = _FakeListener(initial_last_activity=ten_seconds_ago)
        tracker = ActivityTracker(idle_threshold_seconds=5, listener=fake)
        status = tracker.get_status()
        assert status.status == STATUS_IDLE

    def test_idle_seconds_is_reasonable(self) -> None:
        five_seconds_ago = time.time() - 5
        fake = _FakeListener(initial_last_activity=five_seconds_ago)
        tracker = ActivityTracker(idle_threshold_seconds=300, listener=fake)
        status = tracker.get_status()
        assert 4.5 <= status.idle_seconds <= 6.0

    def test_status_never_negative_idle_seconds(self) -> None:
        # Listener reporting a timestamp slightly in the future (clock
        # skew edge case) should never yield negative idle time.
        fake = _FakeListener(initial_last_activity=time.time() + 5)
        tracker = ActivityTracker(idle_threshold_seconds=300, listener=fake)
        status = tracker.get_status()
        assert status.idle_seconds >= 0.0


class TestActivityTrackerLifecycle:
    def test_start_delegates_to_listener(self) -> None:
        fake = _FakeListener()
        tracker = ActivityTracker(listener=fake)
        tracker.start()
        assert fake.start_called is True

    def test_stop_delegates_to_listener(self) -> None:
        fake = _FakeListener()
        tracker = ActivityTracker(listener=fake)
        tracker.start()
        tracker.stop()
        assert fake.stop_called is True

    def test_is_running_reflects_listener_state(self) -> None:
        fake = _FakeListener()
        tracker = ActivityTracker(listener=fake)
        assert tracker.is_running() is False
        tracker.start()
        assert tracker.is_running() is True


class TestActivityTrackerConstruction:
    def test_default_listener_created_when_none_given(self) -> None:
        tracker = ActivityTracker()
        assert isinstance(tracker._listener, ActivityListener)

    def test_zero_threshold_rejected(self) -> None:
        with pytest.raises(ValueError):
            ActivityTracker(idle_threshold_seconds=0)

    def test_negative_threshold_rejected(self) -> None:
        with pytest.raises(ValueError):
            ActivityTracker(idle_threshold_seconds=-10)

    def test_default_threshold_is_five_minutes(self) -> None:
        from user_activity.config import IDLE_THRESHOLD_SECONDS

        assert IDLE_THRESHOLD_SECONDS == 300.0


class TestActivityStatusDataclass:
    def test_frozen(self) -> None:
        status = ActivityStatus(
            status=STATUS_ACTIVE, idle_seconds=0.0, last_activity_time=time.time()
        )
        with pytest.raises(AttributeError):
            status.status = STATUS_IDLE  # type: ignore[misc]
