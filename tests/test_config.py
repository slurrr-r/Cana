"""Unit tests for packet_capture.config."""

from __future__ import annotations

import pytest

from packet_capture.config import (
    CaptureSettings,
    SUPPORTED_FILTERS,
    ensure_runtime_directories,
    LOGS_DIR,
    SESSIONS_DIR,
)


class TestEnsureRuntimeDirectories:
    def test_creates_directories(self) -> None:
        ensure_runtime_directories()
        assert LOGS_DIR.exists()
        assert SESSIONS_DIR.exists()

    def test_idempotent(self) -> None:
        ensure_runtime_directories()
        ensure_runtime_directories()  # should not raise
        assert LOGS_DIR.exists()


class TestCaptureSettings:
    def test_valid_filter_accepted(self) -> None:
        settings = CaptureSettings(
            interface_name="eth0", display_name="Ethernet", packet_filter="TCP"
        )
        assert settings.packet_filter == "TCP"

    def test_default_filter_is_all(self) -> None:
        settings = CaptureSettings(interface_name="eth0", display_name="Ethernet")
        assert settings.packet_filter == "ALL"

    def test_invalid_filter_rejected(self) -> None:
        with pytest.raises(ValueError):
            CaptureSettings(
                interface_name="eth0",
                display_name="Ethernet",
                packet_filter="FTP",
            )

    def test_settings_are_immutable(self) -> None:
        settings = CaptureSettings(interface_name="eth0", display_name="Ethernet")
        with pytest.raises(AttributeError):
            settings.interface_name = "eth1"  # type: ignore[misc]

    @pytest.mark.parametrize("supported", SUPPORTED_FILTERS)
    def test_all_supported_filters_accepted(self, supported: str) -> None:
        settings = CaptureSettings(
            interface_name="eth0",
            display_name="Ethernet",
            packet_filter=supported,
        )
        assert settings.packet_filter == supported
