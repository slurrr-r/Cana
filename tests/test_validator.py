"""Unit tests for packet_capture.validator."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from packet_capture.validator import ValidationResult, is_valid_packet, validate_packet


def _base_packet(**overrides: Any) -> Dict[str, Any]:
    packet = {
        "timestamp": "2026-07-17 10:00:00",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "destination_mac": "11:22:33:44:55:66",
        "source_ip": "192.168.1.5",
        "destination_ip": "93.184.216.34",
        "ip_version": 4,
        "protocol": "TCP",
        "source_port": 52345,
        "destination_port": 443,
        "packet_size": 1514,
        "packet_length": 1514,
        "ttl": 64,
        "tcp_flags": "S",
        "sequence_number": 1000,
        "ack_number": 0,
    }
    packet.update(overrides)
    return packet


class TestValidatePacket:
    def test_none_packet_invalid(self) -> None:
        result = validate_packet(None)
        assert result.is_valid is False
        assert "empty" in result.reason.lower()

    def test_empty_dict_invalid(self) -> None:
        result = validate_packet({})
        assert result.is_valid is False

    def test_valid_tcp_packet(self) -> None:
        result = validate_packet(_base_packet())
        assert result.is_valid is True
        assert result.reason is None

    def test_zero_packet_size_invalid(self) -> None:
        result = validate_packet(_base_packet(packet_size=0))
        assert result.is_valid is False
        assert "corrupted" in result.reason.lower()

    def test_negative_packet_size_invalid(self) -> None:
        result = validate_packet(_base_packet(packet_size=-10))
        assert result.is_valid is False

    def test_missing_packet_size_invalid(self) -> None:
        result = validate_packet(_base_packet(packet_size=None))
        assert result.is_valid is False

    def test_tcp_missing_ports_invalid(self) -> None:
        result = validate_packet(
            _base_packet(source_port=None, destination_port=None)
        )
        assert result.is_valid is False
        assert "port" in result.reason.lower()

    def test_udp_packet_valid_without_ports_check_bypass(self) -> None:
        packet = _base_packet(
            protocol="UDP", source_port=5000, destination_port=53,
            tcp_flags=None, sequence_number=None, ack_number=None,
        )
        result = validate_packet(packet)
        assert result.is_valid is True

    def test_no_ip_and_unknown_protocol_invalid(self) -> None:
        packet = _base_packet(
            source_ip=None, destination_ip=None, protocol="ARP"
        )
        result = validate_packet(packet)
        assert result.is_valid is False
        assert "unsupported" in result.reason.lower()

    def test_no_ip_but_known_protocol_valid(self) -> None:
        # Edge case: protocol known even if IP extraction failed somehow.
        packet = _base_packet(
            source_ip=None, destination_ip=None, protocol="ICMP",
            source_port=None, destination_port=None,
        )
        result = validate_packet(packet)
        assert result.is_valid is True


class TestIsValidPacket:
    def test_returns_true_for_valid(self) -> None:
        assert is_valid_packet(_base_packet()) is True

    def test_returns_false_for_invalid_and_logs(self, caplog) -> None:
        assert is_valid_packet(None) is False

    def test_returns_false_for_corrupted(self) -> None:
        assert is_valid_packet(_base_packet(packet_size=0)) is False


class TestValidationResultDataclass:
    def test_default_reason_is_none(self) -> None:
        result = ValidationResult(is_valid=True)
        assert result.reason is None

    def test_frozen(self) -> None:
        result = ValidationResult(is_valid=True)
        with pytest.raises(AttributeError):
            result.is_valid = False  # type: ignore[misc]
