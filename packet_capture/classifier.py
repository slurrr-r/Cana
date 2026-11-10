"""
classifier.py
=============

Packet classification: given a parsed (and validated) packet
dictionary, determine its:

    * Protocol classification (already largely set by the parser;
      this module normalizes/confirms it, including HTTP/HTTPS
      application-layer tagging).
    * Traffic direction (Incoming / Outgoing), relative to the local
      machine's IP address on the capturing interface.
    * Communication type (Local Network / Internet / Broadcast /
      Multicast), based on IP address range checks.

This module is pure and stateless: it never mutates capture state and
has no I/O beyond logging.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, Optional, Union

from packet_capture.logger import get_logger

logger = get_logger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
LocalIPs = Union[str, Iterable[str], None]

DIRECTION_INCOMING = "INCOMING"
DIRECTION_OUTGOING = "OUTGOING"
DIRECTION_UNKNOWN = "UNKNOWN"

COMM_LOCAL_NETWORK = "LOCAL_NETWORK"
COMM_INTERNET = "INTERNET"
COMM_BROADCAST = "BROADCAST"
COMM_MULTICAST = "MULTICAST"
COMM_UNKNOWN = "UNKNOWN"


def _safe_ip_address(value: Optional[str]) -> Optional[IPAddress]:
    """Parse a string into an ``ipaddress`` object, tolerating bad input."""
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _normalize_local_ips(local_ip: LocalIPs) -> frozenset:
    """
    Normalize the ``local_ip`` argument into a set of address strings.

    Accepts either a single IP string (the historical, simplest case -
    an interface with only an IPv4 address) or an iterable of IP
    strings (e.g. both an IPv4 and an IPv6 address on the same
    dual-stack interface), so direction classification works
    regardless of which IP family a given packet uses.
    """
    if not local_ip:
        return frozenset()
    if isinstance(local_ip, str):
        return frozenset({local_ip})
    return frozenset(ip for ip in local_ip if ip)


def classify_direction(parsed_packet: Dict[str, Any], local_ip: LocalIPs) -> str:
    """
    Determine whether a packet is incoming or outgoing relative to the
    local machine.

    Args:
        parsed_packet: A parsed packet dictionary (see ``parser.py``).
        local_ip: The IP address(es) bound to the interface capture is
            running on - a single string, or an iterable of strings if
            the interface has more than one (e.g. IPv4 and IPv6). If
            ``None``/empty (e.g. interface has no IP, or running in a
            test/mock context), direction cannot be determined.

    Returns:
        One of ``DIRECTION_OUTGOING``, ``DIRECTION_INCOMING``, or
        ``DIRECTION_UNKNOWN``.
    """
    local_ips = _normalize_local_ips(local_ip)
    if not local_ips:
        return DIRECTION_UNKNOWN

    source_ip = parsed_packet.get("source_ip")
    destination_ip = parsed_packet.get("destination_ip")

    if source_ip in local_ips:
        return DIRECTION_OUTGOING
    if destination_ip in local_ips:
        return DIRECTION_INCOMING
    return DIRECTION_UNKNOWN


def classify_communication_type(parsed_packet: Dict[str, Any]) -> str:
    """
    Determine the communication type of a packet: local network,
    internet, broadcast, or multicast.

    Broadcast/multicast are checked on the destination address first,
    since those are defined by destination-address semantics. Failing
    that, both addresses are checked for private-range membership to
    decide Local Network vs Internet.

    Args:
        parsed_packet: A parsed packet dictionary (see ``parser.py``).

    Returns:
        One of ``COMM_BROADCAST``, ``COMM_MULTICAST``,
        ``COMM_LOCAL_NETWORK``, ``COMM_INTERNET``, or ``COMM_UNKNOWN``.
    """
    destination_ip = _safe_ip_address(parsed_packet.get("destination_ip"))
    source_ip = _safe_ip_address(parsed_packet.get("source_ip"))

    if destination_ip is not None:
        if str(destination_ip) == "255.255.255.255":
            return COMM_BROADCAST
        if isinstance(destination_ip, ipaddress.IPv4Address):
            # Limited/subnet broadcast heuristic: last octet 255 within
            # a private network context is treated as broadcast too.
            if str(destination_ip).endswith(".255"):
                return COMM_BROADCAST
        if destination_ip.is_multicast:
            return COMM_MULTICAST

    if source_ip is not None and source_ip.is_multicast:
        return COMM_MULTICAST

    candidates = [ip for ip in (source_ip, destination_ip) if ip is not None]
    if not candidates:
        return COMM_UNKNOWN

    if any(ip.is_private for ip in candidates) and all(
        ip.is_private or ip.is_loopback or ip.is_link_local for ip in candidates
    ):
        return COMM_LOCAL_NETWORK

    return COMM_INTERNET


def classify_packet(
    parsed_packet: Dict[str, Any], local_ip: LocalIPs = None
) -> Dict[str, Any]:
    """
    Enrich a parsed packet dictionary with classification fields.

    This returns a *new* dictionary (does not mutate the input) with
    two additional keys: ``direction`` and ``communication_type``. The
    ``protocol`` and ``application_protocol`` fields set by the parser
    are passed through unchanged, since protocol classification is
    already performed during parsing.

    Args:
        parsed_packet: A parsed packet dictionary.
        local_ip: The local machine's IP(s) on the capturing interface -
            a single string, or an iterable of strings for a dual-stack
            (IPv4 + IPv6) interface - used for direction classification.

    Returns:
        A new dictionary equal to ``parsed_packet`` plus ``direction``
        and ``communication_type`` keys.
    """
    enriched = dict(parsed_packet)
    enriched["direction"] = classify_direction(parsed_packet, local_ip)
    enriched["communication_type"] = classify_communication_type(parsed_packet)
    return enriched
