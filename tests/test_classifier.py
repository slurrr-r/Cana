"""Unit tests for packet_capture.classifier."""

from __future__ import annotations

from typing import Any, Dict

from packet_capture.classifier import (
    COMM_BROADCAST,
    COMM_INTERNET,
    COMM_LOCAL_NETWORK,
    COMM_MULTICAST,
    DIRECTION_INCOMING,
    DIRECTION_OUTGOING,
    DIRECTION_UNKNOWN,
    classify_communication_type,
    classify_direction,
    classify_packet,
)


def _packet(source_ip: str, destination_ip: str, **overrides: Any) -> Dict[str, Any]:
    packet = {
        "protocol": "TCP",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "application_protocol": None,
    }
    packet.update(overrides)
    return packet


class TestClassifyDirection:
    def test_outgoing_when_source_matches_local(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        assert classify_direction(packet, "192.168.1.5") == DIRECTION_OUTGOING

    def test_incoming_when_destination_matches_local(self) -> None:
        packet = _packet("93.184.216.34", "192.168.1.5")
        assert classify_direction(packet, "192.168.1.5") == DIRECTION_INCOMING

    def test_unknown_when_local_ip_missing(self) -> None:
        packet = _packet("93.184.216.34", "192.168.1.5")
        assert classify_direction(packet, None) == DIRECTION_UNKNOWN

    def test_unknown_when_neither_matches(self) -> None:
        packet = _packet("10.0.0.1", "10.0.0.2")
        assert classify_direction(packet, "192.168.1.5") == DIRECTION_UNKNOWN

    def test_accepts_iterable_of_local_ips(self) -> None:
        """
        A dual-stack interface has both an IPv4 and IPv6 address - the
        caller should be able to pass both, and a packet using either
        family should still be classified correctly.
        """
        ipv4_packet = _packet("192.168.1.5", "93.184.216.34")
        ipv6_packet = _packet("2401:4900::1", "2600:140f::1")

        local_ips = ["192.168.1.5", "2401:4900::1"]

        assert classify_direction(ipv4_packet, local_ips) == DIRECTION_OUTGOING
        assert classify_direction(ipv6_packet, local_ips) == DIRECTION_OUTGOING

    def test_ipv6_packet_unknown_when_only_ipv4_local_ip_given(self) -> None:
        """
        Reproduces the real-world bug: if only the IPv4 local address
        is known, IPv6 traffic can never match and direction (and thus
        application mapping) falls back to UNKNOWN.
        """
        ipv6_packet = _packet("2401:4900::1", "2600:140f::1")
        assert classify_direction(ipv6_packet, "192.168.1.5") == DIRECTION_UNKNOWN

    def test_empty_iterable_returns_unknown(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        assert classify_direction(packet, []) == DIRECTION_UNKNOWN

    def test_set_of_local_ips_also_accepted(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        assert (
            classify_direction(packet, {"192.168.1.5", "2401:4900::1"})
            == DIRECTION_OUTGOING
        )


class TestClassifyCommunicationType:
    def test_local_network_both_private(self) -> None:
        packet = _packet("192.168.1.5", "192.168.1.10")
        assert classify_communication_type(packet) == COMM_LOCAL_NETWORK

    def test_internet_public_destination(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        assert classify_communication_type(packet) == COMM_INTERNET

    def test_broadcast_limited(self) -> None:
        packet = _packet("192.168.1.5", "255.255.255.255")
        assert classify_communication_type(packet) == COMM_BROADCAST

    def test_broadcast_subnet_heuristic(self) -> None:
        packet = _packet("192.168.1.5", "192.168.1.255")
        assert classify_communication_type(packet) == COMM_BROADCAST

    def test_multicast_destination(self) -> None:
        packet = _packet("192.168.1.5", "224.0.0.1")
        assert classify_communication_type(packet) == COMM_MULTICAST

    def test_unknown_when_no_ips(self) -> None:
        packet = _packet(None, None)
        from packet_capture.classifier import COMM_UNKNOWN

        assert classify_communication_type(packet) == COMM_UNKNOWN

    def test_malformed_ip_treated_as_absent(self) -> None:
        packet = _packet("not-an-ip", "also-not-an-ip")
        from packet_capture.classifier import COMM_UNKNOWN

        assert classify_communication_type(packet) == COMM_UNKNOWN


class TestClassifyPacket:
    def test_adds_direction_and_communication_type(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        enriched = classify_packet(packet, local_ip="192.168.1.5")
        assert enriched["direction"] == DIRECTION_OUTGOING
        assert enriched["communication_type"] == COMM_INTERNET

    def test_does_not_mutate_original(self) -> None:
        packet = _packet("192.168.1.5", "93.184.216.34")
        classify_packet(packet, local_ip="192.168.1.5")
        assert "direction" not in packet

    def test_preserves_existing_fields(self) -> None:
        packet = _packet(
            "192.168.1.5", "93.184.216.34", application_protocol="HTTPS"
        )
        enriched = classify_packet(packet, local_ip="192.168.1.5")
        assert enriched["application_protocol"] == "HTTPS"
        assert enriched["protocol"] == "TCP"
