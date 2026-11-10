"""
parser.py
=========

Packet parsing: converts raw Scapy packet objects into the structured
Python dictionary format that is this module's public data contract.

This module is intentionally pure/stateless - given a Scapy packet, it
returns a dict or raises a ``PacketParsingError``. It performs no I/O,
no logging side effects beyond error logging, and no classification
(that is ``classifier.py``'s job) - only field extraction.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from packet_capture.config import HTTP_PORTS, HTTPS_PORTS
from packet_capture.logger import get_logger

logger = get_logger(__name__)


class PacketParsingError(Exception):
    """Raised when a packet cannot be parsed into the structured format."""


def _infer_application_protocol(
    src_port: Optional[int], dst_port: Optional[int]
) -> Optional[str]:
    """
    Infer an application-layer label (HTTP/HTTPS) from well-known ports.

    This is explicitly a heuristic, metadata-only inference: Scapy has
    no reliable native HTTP parsing layer, and HTTPS payloads are
    encrypted, so port number is the only practical signal available
    at this layer.

    Args:
        src_port: Source TCP port, if any.
        dst_port: Destination TCP port, if any.

    Returns:
        "HTTP", "HTTPS", or None if neither port matches a known
        application port.
    """
    ports = {p for p in (src_port, dst_port) if p is not None}
    if ports & HTTPS_PORTS:
        return "HTTPS"
    if ports & HTTP_PORTS:
        return "HTTP"
    return None


def parse_packet(raw_packet: Any) -> Dict[str, Any]:
    """
    Parse a raw Scapy packet into the module's structured dictionary
    format.

    Args:
        raw_packet: A Scapy ``Packet`` instance as delivered by
            ``sniff()``'s callback.

    Returns:
        A dictionary with (at minimum) the following keys:
        ``timestamp``, ``source_mac``, ``destination_mac``,
        ``source_ip``, ``destination_ip``, ``ip_version``,
        ``protocol``, ``source_port``, ``destination_port``,
        ``packet_size``, ``packet_length``, ``ttl``, ``tcp_flags``,
        ``sequence_number``, ``ack_number``, ``window_size``,
        ``application_protocol``, ``dns_query_name``.

        Fields that do not apply to a given packet (e.g. TCP-only
        fields on a UDP packet) are set to ``None`` rather than
        omitted, so downstream consumers can rely on a stable schema.

    Raises:
        PacketParsingError: If the packet is empty, malformed, or
            otherwise cannot be safely parsed.
    """
    if raw_packet is None:
        raise PacketParsingError("Cannot parse a None packet.")

    try:
        packet_size = len(raw_packet)
    except Exception as exc:  # noqa: BLE001
        raise PacketParsingError(f"Could not determine packet length: {exc}") from exc

    if packet_size <= 0:
        raise PacketParsingError("Packet has zero or negative length.")

    parsed: Dict[str, Any] = {
        "timestamp": _extract_timestamp(raw_packet),
        "source_mac": None,
        "destination_mac": None,
        "ether_type": None,
        "source_ip": None,
        "destination_ip": None,
        "ip_version": None,
        "ttl": None,
        "protocol": "UNKNOWN",
        "source_port": None,
        "destination_port": None,
        "tcp_flags": None,
        "sequence_number": None,
        "ack_number": None,
        "window_size": None,
        "packet_size": packet_size,
        "packet_length": packet_size,
        "application_protocol": None,
        "dns_query_name": None,
        "dns_is_response": None,
        "dns_id": None,
        "dns_rcode": None,
        "dns_qtype": None,
        "dns_qclass": None,
    }

    try:
        _parse_ethernet_layer(raw_packet, parsed)
        _parse_ip_layer(raw_packet, parsed)
        _parse_transport_layer(raw_packet, parsed)
        _parse_dns_layer(raw_packet, parsed)
        _parse_icmp_layer(raw_packet, parsed)
    except PacketParsingError:
        raise
    except Exception as exc:  # noqa: BLE001 - defensive: never crash the capture loop
        raise PacketParsingError(
            f"Unexpected error while parsing packet: {exc}"
        ) from exc

    # DNS parsing (above) is more specific than the port heuristic - do
    # not overwrite that label (e.g. with None for a non-standard DNS
    # port) once it has already identified the packet as DNS.
    if parsed["application_protocol"] is None:
        parsed["application_protocol"] = _infer_application_protocol(
            parsed["source_port"], parsed["destination_port"]
        )

    return parsed


def _extract_timestamp(raw_packet: Any) -> str:
    """Extract the packet's capture timestamp, falling back to now()."""
    ts = getattr(raw_packet, "time", None)
    try:
        epoch = float(ts) if ts is not None else time.time()
    except (TypeError, ValueError):
        epoch = time.time()
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def _parse_ethernet_layer(raw_packet: Any, parsed: Dict[str, Any]) -> None:
    """Populate Ethernet-layer fields, if the layer is present."""
    from scapy.layers.l2 import Ether

    if raw_packet.haslayer(Ether):
        eth = raw_packet[Ether]
        parsed["source_mac"] = getattr(eth, "src", None)
        parsed["destination_mac"] = getattr(eth, "dst", None)
        parsed["ether_type"] = getattr(eth, "type", None)


def _parse_ip_layer(raw_packet: Any, parsed: Dict[str, Any]) -> None:
    """Populate IPv4/IPv6-layer fields, if present."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if raw_packet.haslayer(IP):
        ip_layer = raw_packet[IP]
        parsed["source_ip"] = getattr(ip_layer, "src", None)
        parsed["destination_ip"] = getattr(ip_layer, "dst", None)
        parsed["ip_version"] = 4
        parsed["ttl"] = getattr(ip_layer, "ttl", None)
        proto_num = getattr(ip_layer, "proto", None)
        parsed["protocol"] = _protocol_number_to_name(proto_num)
    elif raw_packet.haslayer(IPv6):
        ip6_layer = raw_packet[IPv6]
        parsed["source_ip"] = getattr(ip6_layer, "src", None)
        parsed["destination_ip"] = getattr(ip6_layer, "dst", None)
        parsed["ip_version"] = 6
        parsed["ttl"] = getattr(ip6_layer, "hlim", None)
        proto_num = getattr(ip6_layer, "nh", None)
        parsed["protocol"] = _protocol_number_to_name(proto_num)


def _protocol_number_to_name(proto_num: Optional[int]) -> str:
    """Map an IP protocol number to a readable name."""
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPV6"}
    if proto_num is None:
        return "UNKNOWN"
    return mapping.get(int(proto_num), f"PROTO_{proto_num}")


def _parse_transport_layer(raw_packet: Any, parsed: Dict[str, Any]) -> None:
    """Populate TCP or UDP layer fields, if present."""
    from scapy.layers.inet import TCP, UDP

    if raw_packet.haslayer(TCP):
        tcp_layer = raw_packet[TCP]
        parsed["protocol"] = "TCP"
        parsed["source_port"] = getattr(tcp_layer, "sport", None)
        parsed["destination_port"] = getattr(tcp_layer, "dport", None)
        parsed["tcp_flags"] = str(getattr(tcp_layer, "flags", "") or "")
        parsed["sequence_number"] = getattr(tcp_layer, "seq", None)
        parsed["ack_number"] = getattr(tcp_layer, "ack", None)
        parsed["window_size"] = getattr(tcp_layer, "window", None)
    elif raw_packet.haslayer(UDP):
        udp_layer = raw_packet[UDP]
        parsed["protocol"] = "UDP"
        parsed["source_port"] = getattr(udp_layer, "sport", None)
        parsed["destination_port"] = getattr(udp_layer, "dport", None)


def _parse_dns_layer(raw_packet: Any, parsed: Dict[str, Any]) -> None:
    """
    Populate DNS application-layer metadata, if this is a DNS packet.

    DNS is an application-layer protocol, carried over a TCP or UDP
    transport - it must not overwrite ``parsed["protocol"]``, which is
    the transport protocol that application/process mapping matches
    against the OS socket table. Setting ``protocol`` to "DNS" here
    would make DNS traffic unmatchable against that table (sockets are
    never reported as protocol "DNS") and would silently merge DNS
    packet-size/rate statistics into a protocol bucket that transport-
    level code (rate tracking, stats) does not expect to see.
    """
    from scapy.layers.dns import DNS, DNSQR

    if raw_packet.haslayer(DNS):
        parsed["application_protocol"] = "DNS"
        dns_layer = raw_packet[DNS]
        parsed["dns_is_response"] = bool(dns_layer.qr)
        parsed["dns_id"] = int(dns_layer.id)
        parsed["dns_rcode"] = int(dns_layer.rcode)
        if dns_layer.haslayer(DNSQR):
            parsed["dns_qtype"] = int(dns_layer[DNSQR].qtype)
            parsed["dns_qclass"] = int(dns_layer[DNSQR].qclass)
            qname = getattr(dns_layer[DNSQR], "qname", None)
            if qname is not None:
                try:
                    parsed["dns_query_name"] = qname.decode(
                        "utf-8", errors="replace"
                    ).rstrip(".")
                except AttributeError:
                    parsed["dns_query_name"] = str(qname).rstrip(".")


def _parse_icmp_layer(raw_packet: Any, parsed: Dict[str, Any]) -> None:
    """Tag protocol as ICMP if the layer is present and not yet set."""
    from scapy.layers.inet import ICMP

    if raw_packet.haslayer(ICMP):
        parsed["protocol"] = "ICMP"
