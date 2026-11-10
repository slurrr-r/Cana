"""Unit tests for packet_capture.session."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packet_capture.session import SessionError, SessionInfo, SessionManager


class TestSessionManagerLifecycle:
    def test_start_session_creates_info(self) -> None:
        manager = SessionManager()
        session = manager.start_session("Wi-Fi", "TCP")
        assert session.session_id
        assert session.interface_display_name == "Wi-Fi"
        assert session.applied_filter == "TCP"
        assert session.end_time is None

    def test_end_session_without_start_raises(self) -> None:
        manager = SessionManager()
        with pytest.raises(SessionError):
            manager.end_session(total_packets=10)

    def test_end_session_sets_end_time_and_total(self) -> None:
        manager = SessionManager()
        manager.start_session("Ethernet", "ALL")
        finalized = manager.end_session(total_packets=42)
        assert finalized.end_time is not None
        assert finalized.total_packets == 42

    def test_current_session_property(self) -> None:
        manager = SessionManager()
        assert manager.current_session is None
        manager.start_session("Wi-Fi", "ALL")
        assert manager.current_session is not None


class TestSessionManagerPersistence:
    def test_save_without_session_raises(self, tmp_path: Path) -> None:
        manager = SessionManager()
        with pytest.raises(SessionError):
            manager.save(directory=tmp_path)

    def test_save_writes_valid_json(self, tmp_path: Path) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "TCP")
        manager.end_session(total_packets=5)
        file_path = manager.save(directory=tmp_path)

        assert file_path.exists()
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        assert data["applied_filter"] == "TCP"
        assert data["total_packets"] == 5
        assert data["interface_display_name"] == "Wi-Fi"

    def test_save_creates_directory_if_missing(self, tmp_path: Path) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.end_session(total_packets=0)
        nested_dir = tmp_path / "nested" / "sessions"
        file_path = manager.save(directory=nested_dir)
        assert file_path.exists()

    def test_custom_directory_does_not_ensure_default_sessions(self, tmp_path: Path, monkeypatch) -> None:
        called = []

        def boom() -> None:
            called.append("ensure")
            raise AssertionError("custom save must not create default sessions/")

        monkeypatch.setattr("packet_capture.session.ensure_runtime_directories", boom)
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.end_session(total_packets=0)
        file_path = manager.save(directory=tmp_path / "custom")
        assert file_path.exists()
        assert called == []

    def test_saved_file_named_with_session_id(self, tmp_path: Path) -> None:
        manager = SessionManager()
        session = manager.start_session("Wi-Fi", "ALL")
        manager.end_session(total_packets=0)
        file_path = manager.save(directory=tmp_path)
        assert session.session_id in file_path.name


class TestSessionInfoDataclass:
    def test_to_dict_roundtrip(self) -> None:
        info = SessionInfo(
            session_id="abc123",
            start_time="2026-07-17T10:00:00+00:00",
            interface_display_name="Wi-Fi",
            applied_filter="ALL",
        )
        data = info.to_dict()
        assert data["session_id"] == "abc123"
        assert data["applied_filter"] == "ALL"

    def test_actions_and_packets_default_to_empty_list(self) -> None:
        info = SessionInfo(
            session_id="abc123", start_time="2026-07-17T10:00:00+00:00"
        )
        assert info.actions == []
        assert info.packets == []


class TestSessionManagerActionLog:
    def test_start_session_logs_first_action(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "TCP")
        assert len(manager.current_session.actions) == 1
        assert "Session started" in manager.current_session.actions[0]

    def test_add_action_appends_timestamped_entry(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.add_action("Capture started")
        actions = manager.current_session.actions
        assert len(actions) == 2
        assert "Capture started" in actions[1]
        # Each entry is timestamp-prefixed.
        assert actions[1].startswith("[")

    def test_add_action_before_session_started_raises(self) -> None:
        manager = SessionManager()
        with pytest.raises(SessionError):
            manager.add_action("Should fail")

    def test_end_session_logs_final_action(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.end_session(total_packets=5)
        actions = manager.current_session.actions
        assert any("Session ended" in a for a in actions)

    def test_multiple_actions_preserve_order(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.add_action("Step 2")
        manager.add_action("Step 3")
        actions = manager.current_session.actions
        assert "Step 2" in actions[1]
        assert "Step 3" in actions[2]


class TestSessionManagerPacketAttachment:
    def test_attach_packets_stores_full_data(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        packets = [
            {"protocol": "TCP", "source_ip": "192.168.1.5", "packet_size": 1500},
            {"protocol": "UDP", "source_ip": "192.168.1.6", "packet_size": 512},
        ]
        manager.attach_packets(packets)
        assert manager.current_session.packets == packets
        assert manager.current_session.total_packets == 2

    def test_attach_packets_before_session_started_raises(self) -> None:
        manager = SessionManager()
        with pytest.raises(SessionError):
            manager.attach_packets([{"protocol": "TCP"}])

    def test_attach_packets_can_be_called_twice_replacing_data(self) -> None:
        """Simulates Module 1 attaching raw packets, then Module 2's
        app-mapping enrichment overwriting with enriched packets."""
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.attach_packets([{"protocol": "TCP"}])
        manager.attach_packets(
            [{"protocol": "TCP", "application_name": "chrome.exe"}]
        )
        assert manager.current_session.packets == [
            {"protocol": "TCP", "application_name": "chrome.exe"}
        ]

    def test_true_total_preserved_under_the_storage_cap(self) -> None:
        from packet_capture.config import SESSION_MAX_STORED_PACKETS

        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        small_list = [{"protocol": "TCP", "n": i} for i in range(10)]
        manager.attach_packets(small_list)
        assert manager.current_session.total_packets == 10
        assert len(manager.current_session.packets) == 10
        assert 10 <= SESSION_MAX_STORED_PACKETS

    def test_packets_truncated_when_exceeding_storage_cap(self) -> None:
        from packet_capture.config import SESSION_MAX_STORED_PACKETS

        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        huge_count = SESSION_MAX_STORED_PACKETS + 500
        huge_list = [{"protocol": "TCP", "n": i} for i in range(huge_count)]
        manager.attach_packets(huge_list)

        # Stored list is capped...
        assert len(manager.current_session.packets) == SESSION_MAX_STORED_PACKETS
        # ...but the true total is preserved accurately.
        assert manager.current_session.total_packets == huge_count

    def test_truncation_logged_as_an_explicit_action(self) -> None:
        from packet_capture.config import SESSION_MAX_STORED_PACKETS

        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        huge_list = [
            {"protocol": "TCP", "n": i}
            for i in range(SESSION_MAX_STORED_PACKETS + 1)
        ]
        manager.attach_packets(huge_list)

        assert any("truncated" in a for a in manager.current_session.actions)

    def test_no_truncation_action_logged_when_under_cap(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.attach_packets([{"protocol": "TCP"}])
        assert not any("truncated" in a for a in manager.current_session.actions)

    def test_saved_json_file_contains_full_packet_data(self, tmp_path: Path) -> None:
        manager = SessionManager()
        manager.start_session("Ethernet 3", "ALL")
        packets = [
            {
                "protocol": "TCP",
                "source_ip": "192.168.1.5",
                "destination_ip": "93.184.216.34",
                "source_port": 52345,
                "destination_port": 443,
                "packet_size": 1500,
                "application_name": "chrome.exe",
                "process_id": 1234,
            }
        ]
        manager.attach_packets(packets)
        manager.add_action("Application mapping performed: 1 mapped, 0 unknown")
        manager.end_session()
        file_path = manager.save(directory=tmp_path)

        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        assert data["packets"] == packets
        assert data["total_packets"] == 1
        assert any("Application mapping performed" in a for a in data["actions"])
        assert any("Session started" in a for a in data["actions"])
        assert any("Session ended" in a for a in data["actions"])

    def test_end_session_without_explicit_total_uses_attached_count(self) -> None:
        manager = SessionManager()
        manager.start_session("Wi-Fi", "ALL")
        manager.attach_packets([{"protocol": "TCP"}, {"protocol": "UDP"}])
        finalized = manager.end_session()
        assert finalized.total_packets == 2
