"""Unit tests for packet_capture.utils."""

from __future__ import annotations

from packet_capture.statistics import StatisticsManager
from packet_capture.utils import (
    format_duration,
    format_packet_block,
    format_packet_summary,
    format_statistics_line,
)


class TestFormatPacketSummary:
    def test_basic_tcp_summary(self) -> None:
        packet = {
            "timestamp": "2026-07-17 12:42:18",
            "protocol": "TCP",
            "source_ip": "192.168.1.5",
            "destination_ip": "142.250.1.1",
            "direction": "OUTGOING",
            "source_port": 52345,
            "destination_port": 443,
            "packet_size": 1514,
        }
        summary = format_packet_summary(packet)
        assert "TCP" in summary
        assert "192.168.1.5" in summary
        assert "142.250.1.1" in summary
        assert "52345->443" in summary
        assert "1514B" in summary
        assert "12:42:18" in summary

    def test_summary_without_ports(self) -> None:
        packet = {
            "timestamp": "2026-07-17 12:42:18",
            "protocol": "ICMP",
            "source_ip": "192.168.1.5",
            "destination_ip": "192.168.1.1",
            "direction": "OUTGOING",
            "packet_size": 64,
        }
        summary = format_packet_summary(packet)
        assert "Port" not in summary

    def test_summary_missing_ips_uses_placeholder(self) -> None:
        packet = {"timestamp": "", "protocol": "UNKNOWN", "packet_size": 0}
        summary = format_packet_summary(packet)
        assert "?" in summary


class TestFormatPacketBlock:
    def test_matches_requested_multiline_format(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": "chrome.exe",
            "protocol": "TCP",
            "direction": "OUTGOING",
            "source_ip": "10.48.1.5",
            "destination_ip": "142.250.1.1",
            "source_port": 41807,
            "destination_port": 443,
        }
        block = format_packet_block(packet)
        lines = block.split("\n")

        assert lines[0] == "[12:17:41]"
        assert lines[1] == "chrome.exe"
        assert lines[2] == "TCP (Outgoing)"
        assert lines[3] == "10.48.1.5 \u2192 142.250.1.1"
        assert lines[4] == "Port 41807 \u2192 443"

    def test_incoming_direction_labeled(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": "chrome.exe",
            "protocol": "TCP",
            "direction": "INCOMING",
            "source_ip": "142.250.1.1",
            "destination_ip": "10.48.1.5",
        }
        block = format_packet_block(packet)
        assert "Incoming" in block
        assert "Outgoing" not in block

    def test_unknown_direction_labeled_clearly(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": "UNKNOWN",
            "protocol": "ICMPV6",
            "direction": "UNKNOWN",
            "source_ip": "fe80::1",
            "destination_ip": "fe80::abcd",
        }
        block = format_packet_block(packet)
        assert "Direction unknown" in block

    def test_missing_direction_field_defaults_to_unknown(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": "chrome.exe",
            "protocol": "TCP",
            "source_ip": "10.48.1.5",
            "destination_ip": "142.250.1.1",
        }
        block = format_packet_block(packet)
        assert "Direction unknown" in block

    def test_unknown_application_shown_as_unknown(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": None,
            "protocol": "UDP",
            "direction": "OUTGOING",
            "source_ip": "10.0.0.5",
            "destination_ip": "8.8.8.8",
        }
        block = format_packet_block(packet)
        assert "UNKNOWN" in block

    def test_no_ports_omits_port_line(self) -> None:
        packet = {
            "timestamp": "2026-07-25 12:17:41",
            "application_name": "System",
            "protocol": "ICMP",
            "direction": "OUTGOING",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
        }
        block = format_packet_block(packet)
        assert "Port" not in block

    def test_missing_ips_use_placeholder(self) -> None:
        packet = {
            "timestamp": "", "application_name": "UNKNOWN", "protocol": "UNKNOWN",
            "direction": "UNKNOWN",
        }
        block = format_packet_block(packet)
        assert "?" in block


class TestFormatStatisticsLine:
    def test_contains_key_metrics(self) -> None:
        stats = StatisticsManager()
        stats.update(
            {"protocol": "TCP", "direction": "OUTGOING", "packet_size": 100}
        )
        snapshot = stats.snapshot()
        line = format_statistics_line(snapshot)
        assert "Total: 1" in line
        assert "TCP: 1" in line


class TestFormatDuration:
    def test_zero_seconds(self) -> None:
        assert format_duration(0) == "00:00:00"

    def test_under_a_minute(self) -> None:
        assert format_duration(45) == "00:00:45"

    def test_over_an_hour(self) -> None:
        assert format_duration(3665) == "01:01:05"

    def test_negative_clamped_to_zero(self) -> None:
        assert format_duration(-10) == "00:00:00"
