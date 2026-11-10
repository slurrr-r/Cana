"""
context.py
==========

The "Context Record" - the unified data structure combining a
network packet's information with the application that generated it
and the user's activity status at that moment. This is the core data
unit that rules and the baseline tracker operate on.

This module has no dependency on packet_capture or user_activity
directly - it accepts plain dictionaries (matching the shapes those
modules already produce) so it stays independently testable and
loosely coupled.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ContextRecord:
    """
    A single, unified snapshot combining network + application + user
    activity context for one packet.

    Attributes:
        timestamp: Epoch timestamp this record was built.
        hour_of_day: 0-23, derived from ``timestamp`` - used for
            hour-bucketed baseline lookups.
        protocol: Transport protocol, e.g. "TCP", "UDP", "ICMP".
        application_protocol: Optional application-layer label, e.g.
            "DNS", "HTTP", "HTTPS". This is independent of, and never
            replaces, the transport ``protocol`` above - DNS traffic
            is still carried over TCP or UDP at the transport layer,
            and downstream application/process mapping needs that
            transport protocol intact.
        source_ip: Packet source IP.
        destination_ip: Packet destination IP.
        direction: "INCOMING", "OUTGOING", or "UNKNOWN".
        communication_type: "LOCAL_NETWORK", "INTERNET", "BROADCAST",
            "MULTICAST", or "UNKNOWN" - see
            ``packet_capture.classifier.classify_communication_type``.
        packet_size: Size of the packet in bytes.
        application_name: Owning application, or "UNKNOWN".
        process_id: Owning process ID, or ``None``.
        user_status: "ACTIVE" or "IDLE" (or "UNKNOWN" if not
            available).
        idle_seconds: How long the user has been idle, if known.
    """

    timestamp: float
    hour_of_day: int
    protocol: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    direction: str
    communication_type: str
    packet_size: int
    application_name: str
    process_id: Optional[int]
    user_status: str
    idle_seconds: float
    # Default of None (rather than a required field) keeps every
    # existing positional/keyword ContextRecord(...) call site in this
    # codebase (tests, demos) working unchanged - this field is new,
    # so it must not force every caller to be updated.
    application_protocol: Optional[str] = None
    destination_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    dns_query_name: Optional[str] = None
    dns_is_response: Optional[bool] = None
    source_port: Optional[int] = None
    dns_id: Optional[int] = None
    dns_rcode: Optional[int] = None
    dns_qtype: Optional[int] = None
    dns_qclass: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation, suitable for JSON export."""
        return {
            "timestamp": self.timestamp,
            "hour_of_day": self.hour_of_day,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "destination_port": self.destination_port,
            "tcp_flags": self.tcp_flags,
            "dns_query_name": self.dns_query_name,
            "dns_is_response": self.dns_is_response,
            "source_port": self.source_port,
            "dns_id": self.dns_id,
            "dns_rcode": self.dns_rcode,
            "dns_qtype": self.dns_qtype,
            "dns_qclass": self.dns_qclass,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "direction": self.direction,
            "communication_type": self.communication_type,
            "packet_size": self.packet_size,
            "application_name": self.application_name,
            "process_id": self.process_id,
            "user_status": self.user_status,
            "idle_seconds": self.idle_seconds,
        }


def build_context_record(
    packet: Dict[str, Any],
    activity_status: Optional[Dict[str, Any]] = None,
) -> ContextRecord:
    """
    Combine a classified (and, ideally, application-mapped) packet
    dictionary from Module 1/2 with a user activity status dictionary
    from Module 3 into a single :class:`ContextRecord`.

    Args:
        packet: A packet dictionary as produced by
            ``packet_capture.classifier.classify_packet`` (optionally
            further enriched by
            ``packet_capture.app_mapper.ApplicationMapper``). Expected
            keys: ``protocol``, ``source_ip``, ``destination_ip``,
            ``direction``, ``packet_size``. Optional keys:
            ``application_name``, ``process_id``,
            ``application_protocol`` (e.g. "DNS" - an application-layer
            label separate from the transport ``protocol``).
        activity_status: A dict shaped like
            ``user_activity.tracker.ActivityStatus.__dict__`` (or
            simply omitted if activity tracking isn't running) -
            expected keys: ``status``, ``idle_seconds``. If omitted,
            user context defaults to "UNKNOWN".

    Returns:
        A populated :class:`ContextRecord`.
    """
    now = time.time()
    hour_of_day = time.localtime(now).tm_hour

    user_status = "UNKNOWN"
    idle_seconds = 0.0
    if activity_status:
        user_status = str(activity_status.get("status", "UNKNOWN"))
        idle_seconds = float(activity_status.get("idle_seconds", 0.0))

    return ContextRecord(
        timestamp=now,
        hour_of_day=hour_of_day,
        protocol=str(packet.get("protocol", "UNKNOWN")),
        application_protocol=packet.get("application_protocol"),
        destination_port=packet.get("destination_port"),
        tcp_flags=packet.get("tcp_flags"),
        dns_query_name=packet.get("dns_query_name"),
        dns_is_response=packet.get("dns_is_response"),
        source_port=packet.get("source_port"),
        dns_id=packet.get("dns_id"),
        dns_rcode=packet.get("dns_rcode"),
        dns_qtype=packet.get("dns_qtype"),
        dns_qclass=packet.get("dns_qclass"),
        source_ip=packet.get("source_ip"),
        destination_ip=packet.get("destination_ip"),
        direction=str(packet.get("direction", "UNKNOWN")),
        communication_type=str(packet.get("communication_type", "UNKNOWN")),
        packet_size=int(packet.get("packet_size") or 0),
        application_name=str(packet.get("application_name") or "UNKNOWN"),
        process_id=packet.get("process_id"),
        user_status=user_status,
        idle_seconds=idle_seconds,
    )
