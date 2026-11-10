"""Unit tests for packet_capture.parser, using synthetic Scapy packets."""

from __future__ import annotations

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether

from packet_capture.parser import PacketParsingError, parse_packet


def _tcp_packet(sport: int = 52345, dport: int = 443) -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="93.184.216.34", ttl=64)
        / TCP(sport=sport, dport=dport, flags="S", seq=1000, ack=0, window=8192)
    )


def _udp_packet(sport: int = 5000, dport: int = 53) -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="8.8.8.8", ttl=64)
        / UDP(sport=sport, dport=dport)
    )


def _dns_packet() -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="8.8.8.8", ttl=64)
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )


def _dns_over_tcp_packet() -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="8.8.8.8", ttl=64)
        / TCP(sport=54321, dport=53, flags="S", seq=1, ack=0, window=8192)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )


def _icmp_packet() -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="192.168.1.5", dst="192.168.1.1", ttl=64)
        / ICMP()
    )


def _icmpv6_packet() -> object:
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IPv6(src="fe80::1", dst="fe80::abcd")
        / ICMPv6EchoRequest()
    )


class TestParsePacketBasics:
    def test_none_packet_raises(self) -> None:
        with pytest.raises(PacketParsingError):
            parse_packet(None)

    def test_tcp_packet_parses_all_expected_fields(self) -> None:
        parsed = parse_packet(_tcp_packet())
        assert parsed["protocol"] == "TCP"
        assert parsed["source_ip"] == "192.168.1.5"
        assert parsed["destination_ip"] == "93.184.216.34"
        assert parsed["source_mac"] == "aa:bb:cc:dd:ee:ff"
        assert parsed["destination_mac"] == "11:22:33:44:55:66"
        assert parsed["source_port"] == 52345
        assert parsed["destination_port"] == 443
        assert parsed["ttl"] == 64
        assert parsed["ip_version"] == 4
        assert parsed["sequence_number"] == 1000
        assert parsed["ack_number"] == 0
        assert parsed["window_size"] == 8192
        assert "S" in parsed["tcp_flags"]
        assert parsed["packet_size"] > 0
        assert parsed["application_protocol"] == "HTTPS"  # port 443

    def test_udp_packet_parses(self) -> None:
        parsed = parse_packet(_udp_packet(sport=6000, dport=8080))
        assert parsed["protocol"] == "UDP"
        assert parsed["source_port"] == 6000
        assert parsed["destination_port"] == 8080
        assert parsed["application_protocol"] == "HTTP"  # port 8080
        # TCP-only fields must be None, not missing, for schema stability.
        assert parsed["sequence_number"] is None
        assert parsed["tcp_flags"] is None

    def test_dns_packet_extracts_query_name(self) -> None:
        parsed = parse_packet(_dns_packet())
        assert parsed["dns_query_name"] == "example.com"

    def test_icmp_packet_classified(self) -> None:
        parsed = parse_packet(_icmp_packet())
        assert parsed["protocol"] == "ICMP"
        assert parsed["source_port"] is None

    def test_icmpv6_packet_classified(self) -> None:
        parsed = parse_packet(_icmpv6_packet())
        assert parsed["protocol"] == "ICMPV6"
        assert parsed["source_port"] is None
        assert parsed["ip_version"] == 6

    def test_timestamp_field_present_and_formatted(self) -> None:
        parsed = parse_packet(_tcp_packet())
        assert parsed["timestamp"]
        # Basic sanity: format should look like YYYY-MM-DD HH:MM:SS.
        assert len(parsed["timestamp"]) == 19

    def test_application_protocol_none_for_unrelated_ports(self) -> None:
        parsed = parse_packet(_tcp_packet(sport=51000, dport=22))
        assert parsed["application_protocol"] is None

    def test_packet_size_matches_len(self) -> None:
        pkt = _tcp_packet()
        parsed = parse_packet(pkt)
        assert parsed["packet_size"] == len(pkt)
        assert parsed["packet_length"] == len(pkt)


class TestDnsTransportVsApplicationProtocol:
    """
    Regression tests for P2 Bug #3: DNS is an application-layer
    label, not a transport protocol - it must never overwrite the
    packet's transport ``protocol`` (TCP/UDP), because downstream
    application/process mapping matches against the OS socket table,
    which never reports a socket's protocol as "DNS".
    """

    def test_dns_over_udp_keeps_udp_as_transport_protocol(self) -> None:
        parsed = parse_packet(_dns_packet())
        assert parsed["protocol"] == "UDP"
        assert parsed["application_protocol"] == "DNS"

    def test_dns_over_tcp_keeps_tcp_as_transport_protocol(self) -> None:
        parsed = parse_packet(_dns_over_tcp_packet())
        assert parsed["protocol"] == "TCP"
        assert parsed["application_protocol"] == "DNS"

    def test_non_dns_udp_traffic_remains_udp(self) -> None:
        parsed = parse_packet(_udp_packet(sport=6000, dport=8080))
        assert parsed["protocol"] == "UDP"
        assert parsed["application_protocol"] != "DNS"

    def test_non_dns_tcp_traffic_remains_tcp(self) -> None:
        parsed = parse_packet(_tcp_packet())
        assert parsed["protocol"] == "TCP"
        assert parsed["application_protocol"] != "DNS"


class TestParsePacketMalformedInput:
    def test_object_without_len_raises_parsing_error(self) -> None:
        class Bogus:
            pass

        with pytest.raises(PacketParsingError):
            parse_packet(Bogus())

    def test_object_with_zero_length_raises(self) -> None:
        class ZeroLen:
            def __len__(self) -> int:
                return 0

        with pytest.raises(PacketParsingError):
            parse_packet(ZeroLen())

    def test_object_with_negative_length_raises(self) -> None:
        class NegLen:
            def __len__(self) -> int:
                return -1

        with pytest.raises(PacketParsingError):
            parse_packet(NegLen())
