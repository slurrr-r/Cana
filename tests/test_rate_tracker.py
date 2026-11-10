"""Unit tests for anomaly_detection.rate_tracker."""

from __future__ import annotations

import time

import pytest

from anomaly_detection.rate_tracker import ConnectionRateTracker


class TestConnectionRateTrackerBasics:
    def test_zero_window_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConnectionRateTracker(window_seconds=0)

    def test_negative_window_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConnectionRateTracker(window_seconds=-5)

    def test_single_event_rate(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        rate, _ = tracker.record("chrome.exe", "1.2.3.4")
        assert rate == pytest.approx(1.0 / 5.0)

    def test_multiple_events_increase_rate(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        for _ in range(10):
            rate, _ = tracker.record("chrome.exe", "1.2.3.4")
        assert rate == pytest.approx(10.0 / 5.0)

    def test_separate_keys_tracked_independently(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        for _ in range(10):
            tracker.record("chrome.exe", "1.2.3.4")
        rate_other, _ = tracker.record("Code.exe", "5.6.7.8")
        assert rate_other == pytest.approx(1.0 / 5.0)

    def test_old_events_expire_out_of_window(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=0.05)
        tracker.record("chrome.exe", "1.2.3.4")
        time.sleep(0.1)  # let the window fully expire
        rate, _ = tracker.record("chrome.exe", "1.2.3.4")
        # Only the most recent event should remain in the window.
        assert rate == pytest.approx(1.0 / 0.05, rel=0.2)

    def test_none_destination_handled_gracefully(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        rate, _ = tracker.record("chrome.exe", None)
        assert rate > 0


class TestConnectionRateTrackerSampling:
    def test_first_event_should_sample(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        _, should_sample = tracker.record("chrome.exe", "1.2.3.4")
        assert should_sample is True

    def test_rapid_repeated_events_only_sample_once_per_window(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        sample_flags = [
            tracker.record("chrome.exe", "1.2.3.4")[1] for _ in range(20)
        ]
        # Only the very first should_sample should be True; the rest,
        # all happening well within the same window, should be False.
        assert sample_flags[0] is True
        assert all(flag is False for flag in sample_flags[1:])

    def test_reset_clears_sampling_state(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0)
        tracker.record("chrome.exe", "1.2.3.4")
        tracker.reset()
        _, should_sample = tracker.record("chrome.exe", "1.2.3.4")
        assert should_sample is True


class TestConnectionRateTrackerEviction:
    def test_max_keys_evicts_oldest(self) -> None:
        tracker = ConnectionRateTracker(window_seconds=5.0, max_keys=3)
        tracker.record("app1", "1.1.1.1")
        time.sleep(0.02)
        tracker.record("app2", "2.2.2.2")
        time.sleep(0.02)
        tracker.record("app3", "3.3.3.3")
        time.sleep(0.02)
        tracker.record("app4", "4.4.4.4")
        assert len(tracker._events) <= 3
        assert ("app4", "4.4.4.4") in tracker._events

    def test_zero_max_keys_rejected(self) -> None:
        with pytest.raises(ValueError):
            ConnectionRateTracker(window_seconds=5.0, max_keys=0)
