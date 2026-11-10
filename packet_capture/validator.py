"""
validator.py
============

Packet validation: decides whether a parsed packet dictionary is
well-formed enough to proceed further into classification, statistics,
and display.

This module operates on the *already-parsed* dictionary (see
``parser.py``), not raw Scapy packets - parsing failures are handled
separately as ``PacketParsingError`` at the parser layer. Validation
here is about semantic sanity (e.g. "does this have enough information
to be useful?"), not structural parseability.

The guiding principle: the capture pipeline must NEVER crash because of
a malformed or unsupported packet. Invalid packets are rejected with a
clear reason and logged, never raised as uncaught exceptions upstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from packet_capture.logger import get_logger

logger = get_logger(__name__)

_KNOWN_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPV6", "DNS"}


@dataclass(frozen=True)
class ValidationResult:
    """
    Outcome of validating a single parsed packet.

    Attributes:
        is_valid: Whether the packet passed validation.
        reason: Human-readable reason for rejection, or ``None`` if
            valid.
    """

    is_valid: bool
    reason: Optional[str] = None


def validate_packet(parsed_packet: Optional[Dict[str, Any]]) -> ValidationResult:
    """
    Validate a parsed packet dictionary against basic sanity rules.

    Rejects:
        * ``None`` or empty dictionaries ("empty packets").
        * Packets with a non-positive ``packet_size`` ("corrupted").
        * Packets with neither a source nor destination IP AND an
          unrecognized protocol (very likely a non-IP, non-supported
          link-layer frame we have no use for, e.g. ARP/STP).

    Args:
        parsed_packet: The dictionary produced by
            :func:`packet_capture.parser.parse_packet`.

    Returns:
        A :class:`ValidationResult` describing the outcome.
    """
    if not parsed_packet:
        return ValidationResult(is_valid=False, reason="Packet is empty or None.")

    packet_size = parsed_packet.get("packet_size")
    if packet_size is None or packet_size <= 0:
        return ValidationResult(
            is_valid=False,
            reason=f"Invalid packet_size: {packet_size!r} (corrupted packet).",
        )

    source_ip = parsed_packet.get("source_ip")
    destination_ip = parsed_packet.get("destination_ip")
    protocol = (parsed_packet.get("protocol") or "UNKNOWN").upper()

    if source_ip is None and destination_ip is None and protocol not in _KNOWN_PROTOCOLS:
        return ValidationResult(
            is_valid=False,
            reason=(
                f"Unsupported packet: no IP layer and unrecognized "
                f"protocol '{protocol}'."
            ),
        )

    if protocol == "TCP":
        if parsed_packet.get("source_port") is None or (
            parsed_packet.get("destination_port") is None
        ):
            return ValidationResult(
                is_valid=False,
                reason="TCP packet missing required port information.",
            )

    return ValidationResult(is_valid=True)


def is_valid_packet(parsed_packet: Optional[Dict[str, Any]]) -> bool:
    """
    Convenience boolean wrapper around :func:`validate_packet`, logging
    a warning whenever a packet is rejected.

    Args:
        parsed_packet: The dictionary produced by
            :func:`packet_capture.parser.parse_packet`.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    result = validate_packet(parsed_packet)
    if not result.is_valid:
        logger.warning("Packet rejected during validation: %s", result.reason)
    return result.is_valid
