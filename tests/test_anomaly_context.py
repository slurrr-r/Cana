"""Unit tests for anomaly_detection.context."""

from __future__ import annotations

import time

from anomaly_detection.context import build_context_record


def _packet(**overrides):
    packet = {
        "protocol": "TCP",
        "source_ip": "192.168.1.5",
        "destination_ip": "93.184.216.34",
        "direction": "OUTGOING",
        "packet_size": 1500,
        "application_name": "chrome.exe",
        "process_id": 1234,
    }
    packet.update(overrides)
    return packet


def _activity_status(**overrides):
    status = {"status": "ACTIVE", "idle_seconds": 5.0}
    status.update(overrides)
    return status


class TestBuildContextRecord:
    def test_builds_full_record_with_activity(self) -> None:
        record = build_context_record(_packet(), _activity_status())
        assert record.protocol == "TCP"
        assert record.application_name == "chrome.exe"
        assert record.process_id == 1234
        assert record.user_status == "ACTIVE"
        assert record.idle_seconds == 5.0
        assert 0 <= record.hour_of_day <= 23

    def test_missing_activity_status_defaults_to_unknown(self) -> None:
        record = build_context_record(_packet(), activity_status=None)
        assert record.user_status == "UNKNOWN"
        assert record.idle_seconds == 0.0

    def test_missing_application_fields_default_gracefully(self) -> None:
        packet = _packet()
        del packet["application_name"]
        del packet["process_id"]
        record = build_context_record(packet, _activity_status())
        assert record.application_name == "UNKNOWN"
        assert record.process_id is None

    def test_none_application_name_becomes_unknown(self) -> None:
        record = build_context_record(
            _packet(application_name=None), _activity_status()
        )
        assert record.application_name == "UNKNOWN"

    def test_missing_packet_size_defaults_to_zero(self) -> None:
        packet = _packet()
        del packet["packet_size"]
        record = build_context_record(packet, _activity_status())
        assert record.packet_size == 0

    def test_idle_status_preserved(self) -> None:
        record = build_context_record(
            _packet(), _activity_status(status="IDLE", idle_seconds=400.0)
        )
        assert record.user_status == "IDLE"
        assert record.idle_seconds == 400.0

    def test_timestamp_is_recent(self) -> None:
        before = time.time()
        record = build_context_record(_packet(), _activity_status())
        after = time.time()
        assert before <= record.timestamp <= after

    def test_hour_of_day_matches_current_local_hour(self) -> None:
        record = build_context_record(_packet(), _activity_status())
        expected_hour = time.localtime(record.timestamp).tm_hour
        assert record.hour_of_day == expected_hour


class TestApplicationProtocolField:
    """Regression tests for P2 Bug #3 (DNS transport vs application protocol)."""

    def test_defaults_to_none_when_absent_from_packet(self) -> None:
        record = build_context_record(_packet(), _activity_status())
        assert record.application_protocol is None

    def test_dns_over_udp_keeps_udp_as_the_transport_protocol(self) -> None:
        record = build_context_record(
            _packet(protocol="UDP", application_protocol="DNS"),
            _activity_status(),
        )
        assert record.protocol == "UDP"
        assert record.application_protocol == "DNS"

    def test_dns_over_tcp_keeps_tcp_as_the_transport_protocol(self) -> None:
        record = build_context_record(
            _packet(protocol="TCP", application_protocol="DNS"),
            _activity_status(),
        )
        assert record.protocol == "TCP"
        assert record.application_protocol == "DNS"


class TestContextRecordToDict:
    def test_to_dict_contains_all_fields(self) -> None:
        record = build_context_record(_packet(), _activity_status())
        data = record.to_dict()
        expected_keys = {
            "timestamp", "hour_of_day", "protocol", "application_protocol",
            "source_ip", "destination_ip", "direction", "communication_type",
            "packet_size", "application_name", "process_id",
            "user_status", "idle_seconds", "destination_port", "tcp_flags",
            "dns_query_name", "dns_is_response",
            "source_port", "dns_id", "dns_rcode",
            "dns_qtype", "dns_qclass",
        }
        assert set(data.keys()) == expected_keys

    def test_to_dict_is_json_serializable(self) -> None:
        import json

        record = build_context_record(_packet(), _activity_status())
        json.dumps(record.to_dict())  # should not raise


class TestContextRecordFrozen:
    def test_frozen(self) -> None:
        import pytest

        record = build_context_record(_packet(), _activity_status())
        with pytest.raises(AttributeError):
            record.protocol = "UDP"  # type: ignore[misc]
