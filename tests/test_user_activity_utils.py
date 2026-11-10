"""Unit tests for user_activity.utils."""

from __future__ import annotations

from user_activity.tracker import STATUS_ACTIVE, STATUS_IDLE, ActivityStatus
from user_activity.utils import format_duration, format_status_line


class TestFormatDuration:
    def test_zero_seconds(self) -> None:
        assert format_duration(0) == "00:00:00"

    def test_under_a_minute(self) -> None:
        assert format_duration(45) == "00:00:45"

    def test_over_an_hour(self) -> None:
        assert format_duration(3665) == "01:01:05"

    def test_negative_clamped_to_zero(self) -> None:
        assert format_duration(-10) == "00:00:00"

    def test_five_minutes_matches_idle_threshold(self) -> None:
        assert format_duration(300) == "00:05:00"


class TestFormatStatusLine:
    def test_active_status_line(self) -> None:
        status = ActivityStatus(
            status=STATUS_ACTIVE, idle_seconds=12.0, last_activity_time=0.0
        )
        line = format_status_line(status)
        assert "ACTIVE" in line
        assert "00:00:12" in line

    def test_idle_status_line(self) -> None:
        status = ActivityStatus(
            status=STATUS_IDLE, idle_seconds=320.0, last_activity_time=0.0
        )
        line = format_status_line(status)
        assert "IDLE" in line
        assert "00:05:20" in line
