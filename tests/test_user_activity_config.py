"""Unit tests for user_activity.config."""

from __future__ import annotations

from user_activity.config import IDLE_THRESHOLD_SECONDS, LOGS_DIR, ensure_runtime_directories


class TestEnsureRuntimeDirectories:
    def test_creates_logs_directory(self) -> None:
        ensure_runtime_directories()
        assert LOGS_DIR.exists()

    def test_idempotent(self) -> None:
        ensure_runtime_directories()
        ensure_runtime_directories()  # should not raise
        assert LOGS_DIR.exists()


class TestConfigValues:
    def test_idle_threshold_is_positive(self) -> None:
        assert IDLE_THRESHOLD_SECONDS > 0

    def test_idle_threshold_matches_project_spec(self) -> None:
        # Original spec: "no activity for 5 minutes => IDLE".
        assert IDLE_THRESHOLD_SECONDS == 300.0
