"""
interface.py
============

Network interface detection and selection.

On Windows, Scapy's raw interface identifiers (e.g.
``\\Device\\NPF_{GUID}``) are not human-friendly. This module maps raw
Scapy interface objects to a clean, numbered, human-readable menu and
validates user selections defensively.

This module has no dependency on any capture logic - it can be tested
completely independently of a live capture session.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import List, Optional

from packet_capture.logger import get_logger, log_module_event

logger = get_logger(__name__)


class InterfaceDetectionError(Exception):
    """Raised when network interfaces cannot be enumerated at all."""


class InterfaceSelectionError(Exception):
    """Raised when a user-provided interface selection is invalid."""


def get_all_local_ips() -> List[str]:
    """
    Collect every non-link-local, non-loopback IP address (v4 and v6)
    bound to *any* interface on this machine.

    This exists to work around a genuine, common practical problem:
    correlating a specific network interface's "friendly name" between
    Scapy/Npcap and psutil is fragile on Windows, since the two
    libraries read from different underlying system APIs and often
    report slightly different names for the same physical adapter.
    Rather than trying to match names, this collects the machine's
    *entire* set of real addresses system-wide - since for direction
    classification, all that matters is "is this address mine?", not
    which specific adapter officially owns it. A machine's own
    addresses essentially never collide with a remote peer's, so this
    is safe even though it isn't scoped to one interface.

    Returns:
        A deduplicated list of address strings. Empty if psutil is
        unavailable or no real addresses could be found.
    """
    try:
        import psutil
    except ImportError:
        return []

    try:
        addrs_by_iface = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001 - platform-specific psutil errors
        return []

    collected: List[str] = []
    seen: set = set()

    for addr_list in addrs_by_iface.values():
        for addr in addr_list:
            family = getattr(addr, "family", None)
            raw_address = getattr(addr, "address", None)
            if not raw_address:
                continue

            if family == socket.AF_INET:
                if raw_address.startswith("169.254.") or raw_address == "127.0.0.1":
                    continue
                if raw_address not in seen:
                    seen.add(raw_address)
                    collected.append(raw_address)
            elif family == socket.AF_INET6:
                cleaned = _clean_ipv6_candidate(raw_address)
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    collected.append(cleaned)

    return collected


@dataclass(frozen=True)
class NetworkInterface:
    """
    A normalized, human-friendly representation of a network interface.

    Attributes:
        index: 1-based position in the displayed menu.
        name: The raw OS/Scapy-level interface identifier used for
            actual packet capture (e.g. ``\\Device\\NPF_{GUID}`` on
            Windows, or ``eth0`` on Linux).
        display_name: A friendly label suitable for showing to a user
            (e.g. "Wi-Fi", "Ethernet").
        description: Optional extra description (driver name, etc.).
        ip_address: Optional IPv4 address bound to this interface, used
            later for direction classification.
        ipv6_address: Optional non-link-local IPv6 address bound to
            this interface, also used for direction classification.
            Without this, IPv6 traffic (increasingly common even on
            "IPv4" networks via dual-stack) can never be matched
            against the local machine, since it would only ever be
            compared against the IPv4 address.
        is_likely_active: True if this interface has a "real" IP
            address (not APIPA/169.254.x.x, not loopback, not None) -
            i.e. it looks like the genuine, currently connected
            interface a user probably wants, rather than an idle or
            disconnected adapter.
    """

    index: int
    name: str
    display_name: str
    description: str = ""
    ip_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    is_likely_active: bool = False

    def __str__(self) -> str:  # pragma: no cover - purely cosmetic
        ip_part = f" ({self.ip_address})" if self.ip_address else ""
        ipv6_part = f" [IPv6: {self.ipv6_address}]" if self.ipv6_address else ""
        tag = "  <-- recommended" if self.is_likely_active else ""
        return f"[{self.index}] {self.display_name}{ip_part}{ipv6_part}{tag}"

    @property
    def all_local_ips(self) -> List[str]:
        """All local IP addresses (v4 and/or v6) bound to this interface."""
        return [ip for ip in (self.ip_address, self.ipv6_address) if ip]


def _extract_display_name(raw_iface: object) -> str:
    """
    Best-effort extraction of a friendly name from a Scapy interface
    object, falling back gracefully across platforms.

    Scapy's ``NetworkInterface`` objects differ between platforms:
    Windows objects typically expose ``.name`` (friendly, e.g. "Wi-Fi")
    and ``.network_name`` (raw NPF path), while POSIX objects usually
    only expose ``.name`` as the raw device (e.g. "eth0"). We try the
    friendliest available attribute first.
    """
    for attr in ("name", "description"):
        value = getattr(raw_iface, attr, None)
        if value:
            return str(value)
    return "Unknown Interface"


def _extract_raw_name(raw_iface: object) -> str:
    """
    Extract the low-level identifier Scapy needs to actually open the
    interface for sniffing (as opposed to the friendly display name).
    """
    for attr in ("network_name", "guid", "name"):
        value = getattr(raw_iface, attr, None)
        if value:
            return str(value)
    raise InterfaceDetectionError(
        "Could not determine a usable device identifier for interface."
    )


def _extract_ip(raw_iface: object) -> Optional[str]:
    """Best-effort extraction of a bound IPv4 address, if any."""
    ip = getattr(raw_iface, "ip", None)
    return str(ip) if ip else None


def _clean_ipv6_candidate(addr_str: str) -> Optional[str]:
    """
    Normalize and filter a raw IPv6 address string.

    Strips any Windows zone/scope-id suffix (e.g. ``fe80::1%12``), and
    rejects link-local (``fe80::...``) and loopback (``::1``)
    addresses, since those aren't useful for matching real traffic - a
    genuine routable or unique-local address is what we want.
    """
    if not addr_str:
        return None
    cleaned = addr_str.split("%")[0]
    lowered = cleaned.lower()
    if not cleaned or lowered.startswith("fe80") or lowered == "::1":
        return None
    return cleaned


def _extract_ipv6(raw_iface: object) -> Optional[str]:
    """
    Best-effort extraction of a bound, non-link-local, non-loopback
    IPv6 address, if any.

    Two strategies are tried, in order:

    1. Scapy's own interface object, if it happens to expose an
       ``.ips`` dict (structure varies across Scapy versions - some
       key by IP version integer, some by ``socket.AF_INET6`` - both
       are tried defensively).
    2. ``psutil.net_if_addrs()``, matched by the interface's friendly
       name. This is the primary, reliable path: psutil's address
       enumeration API is stable and well-documented across versions,
       unlike Scapy's internal (and, in practice, inconsistent)
       representation of bound IPv6 addresses.

    Args:
        raw_iface: The raw Scapy interface object.

    Returns:
        A usable IPv6 address string, or ``None`` if none was found.
    """
    ips = getattr(raw_iface, "ips", None)
    if ips:
        for key in (6, "6", socket.AF_INET6):
            try:
                candidates = ips.get(key)
            except AttributeError:
                candidates = None
            if candidates:
                for addr in candidates:
                    resolved = _clean_ipv6_candidate(str(addr))
                    if resolved:
                        return resolved

    friendly_name = _extract_display_name(raw_iface)
    try:
        import psutil

        addrs_by_iface = psutil.net_if_addrs()
    except Exception:  # noqa: BLE001 - psutil unavailable/platform error
        return None

    for iface_name, addr_list in addrs_by_iface.items():
        if iface_name != friendly_name:
            continue
        for addr in addr_list:
            if getattr(addr, "family", None) == socket.AF_INET6:
                resolved = _clean_ipv6_candidate(getattr(addr, "address", ""))
                if resolved:
                    return resolved

    return None


_NOISE_NAME_MARKERS = (
    "wfp",
    "qos packet scheduler",
    "lightweight filter",
    "light-weight filter",
    "native wifi filter driver",
    "virtual wifi filter driver",
    "kernel debugger",
    "teredo",
    "ip-https",
    "6to4",
)


def _looks_like_noise(display_name: str) -> bool:
    """
    Heuristically identify NDIS binding/filter pseudo-interfaces that
    Npcap enumerates alongside real adapters (QoS scheduler bindings,
    WFP lightweight filters, VirtualBox's filter driver, etc.).

    These are not independently capturable interfaces - they are
    internal Windows driver-stack entries tied to a *real* adapter
    that is listed separately. Showing them to the user creates a
    confusing, oversized menu with no practical benefit.

    Args:
        display_name: The friendly name Scapy reports for the
            interface.

    Returns:
        True if this interface looks like driver-stack noise rather
        than a genuine, independently usable network adapter.
    """
    lowered = display_name.lower()
    return any(marker in lowered for marker in _NOISE_NAME_MARKERS)


def _is_real_usable_ip(ip_address: Optional[str]) -> bool:
    """
    Determine whether an IP looks like a genuinely active connection,
    as opposed to APIPA self-assignment (169.254.x.x, meaning the
    adapter never got a real address from DHCP) or loopback.

    Used only to choose which interface to mark "recommended" in the
    menu - it does not exclude any interface from being selectable.
    """
    if not ip_address:
        return False
    if ip_address.startswith("169.254."):
        return False
    if ip_address == "127.0.0.1":
        return False
    return True


def detect_interfaces(include_all: bool = False) -> List[NetworkInterface]:
    """
    Detect available network interfaces on the current machine.

    By default, this filters out two categories of clutter that Npcap
    enumerates alongside genuine, independently usable adapters:

    1. NDIS driver-stack "noise" (QoS scheduler bindings, WFP
       lightweight filters, VirtualBox's filter driver, etc.) - these
       are internal Windows plumbing entries, not real interfaces.
    2. Interfaces with **no IP address at all** - these are inactive
       pseudo-adapters (e.g. disabled or never-configured virtual
       adapters) that cannot usefully capture traffic.

    The single interface most likely to be the user's genuine, active
    connection (a real, non-APIPA, non-loopback IP) is marked
    ``is_likely_active=True`` and shown with a "recommended" tag in
    the menu, so a non-technical user isn't left guessing which of
    several remaining entries to pick.

    Args:
        include_all: If True, skip all filtering and return every
            interface Npcap/Scapy reports, unfiltered. Useful for
            advanced users or troubleshooting.

    Returns:
        A list of :class:`NetworkInterface` objects, numbered starting
        at 1 for display purposes.

    Raises:
        InterfaceDetectionError: If Scapy is unavailable, if Npcap is
            missing on Windows, or if no interfaces could be enumerated
            for any other reason.
    """
    try:
        from scapy.all import conf  # local import: heavy, optional at test time
    except ImportError as exc:
        raise InterfaceDetectionError(
            "Scapy is not installed or failed to import."
        ) from exc

    try:
        ifaces = getattr(conf, "ifaces", None)
        reload_ifaces = getattr(ifaces, "reload", None)
        if callable(reload_ifaces):
            reload_ifaces()
        raw_interfaces = list(getattr(ifaces, "data", {}).values())
    except Exception as exc:  # noqa: BLE001 - Scapy raises varied errors
        raise InterfaceDetectionError(
            "Failed to enumerate network interfaces. On Windows this "
            "usually means Npcap is not installed or not running. "
            f"Original error: {exc}"
        ) from exc

    if not raw_interfaces:
        raise InterfaceDetectionError(
            "No network interfaces were detected on this system."
        )

    candidates: List[NetworkInterface] = []
    next_index = 1
    for raw_iface in raw_interfaces:
        try:
            display_name = _extract_display_name(raw_iface)
            ip_address = _extract_ip(raw_iface)
            ipv6_address = _extract_ipv6(raw_iface)

            if not include_all:
                if _looks_like_noise(display_name):
                    continue
                if ip_address is None:
                    continue

            candidates.append(
                NetworkInterface(
                    index=next_index,
                    name=_extract_raw_name(raw_iface),
                    display_name=display_name,
                    description=str(getattr(raw_iface, "description", "") or ""),
                    ip_address=ip_address,
                    ipv6_address=ipv6_address,
                    is_likely_active=_is_real_usable_ip(ip_address),
                )
            )
            next_index += 1
        except InterfaceDetectionError:
            # Skip interfaces we can't get a usable identifier for,
            # rather than failing the entire detection pass.
            logger.warning("Skipping an interface with no usable identifier.")
            continue

    if not candidates:
        if not include_all:
            # Filtering removed everything (unlikely, but possible on
            # unusual setups) - fall back to the unfiltered list rather
            # than leaving the user with nothing to select.
            logger.warning(
                "Filtering removed all interfaces; falling back to the "
                "unfiltered list."
            )
            return detect_interfaces(include_all=True)
        raise InterfaceDetectionError(
            "Interfaces were found but none had a usable identifier."
        )

    log_module_event(
        logger, "INTERFACES_DETECTED", detail=f"count={len(candidates)}"
    )
    return candidates


def format_interface_menu(interfaces: List[NetworkInterface]) -> str:
    """
    Build a numbered, human-readable menu string for display to the
    user before capture starts.

    Args:
        interfaces: Interfaces as returned by :func:`detect_interfaces`.

    Returns:
        A multi-line string ready to be printed to the console.
    """
    lines = ["Available Network Interfaces:", "-" * 40]
    for iface in interfaces:
        lines.append(str(iface))
    return "\n".join(lines)


def select_interface(
    interfaces: List[NetworkInterface], selection: str
) -> NetworkInterface:
    """
    Validate and resolve a user's raw menu selection into a concrete
    :class:`NetworkInterface`.

    Args:
        interfaces: The interfaces previously shown to the user.
        selection: Raw user input, expected to be the 1-based index
            as a string (e.g. from ``input()``).

    Returns:
        The selected :class:`NetworkInterface`.

    Raises:
        InterfaceSelectionError: If the selection is not a valid
            integer, or out of range of the displayed menu.
    """
    if not interfaces:
        raise InterfaceSelectionError("No interfaces available to select from.")

    selection = (selection or "").strip()
    if not selection:
        raise InterfaceSelectionError("No selection was provided.")

    try:
        selected_index = int(selection)
    except ValueError as exc:
        raise InterfaceSelectionError(
            f"'{selection}' is not a valid interface number."
        ) from exc

    matches = [iface for iface in interfaces if iface.index == selected_index]
    if not matches:
        raise InterfaceSelectionError(
            f"Selection {selected_index} is out of range. "
            f"Valid range is 1-{len(interfaces)}."
        )

    chosen = matches[0]
    log_module_event(
        logger, "INTERFACE_SELECTED", detail=f"{chosen.display_name}"
    )
    return chosen


def default_interface(interfaces: List[NetworkInterface]) -> NetworkInterface:
    """
    Pick the interface most likely to be the user's active connection.

    Prefers ``is_likely_active`` (a real non-APIPA address). If none is
    marked, returns the first detected interface.
    """
    if not interfaces:
        raise InterfaceSelectionError("No interfaces available to select from.")
    recommended = [iface for iface in interfaces if iface.is_likely_active]
    return recommended[0] if recommended else interfaces[0]


def resolve_interface(
    interfaces: List[NetworkInterface],
    configured_name: Optional[str] = None,
) -> NetworkInterface:
    """
    Resolve a configured interface name, falling back to the default.

    Matches against raw OS name and display name (case-insensitive).
    """
    if not interfaces:
        raise InterfaceSelectionError("No interfaces available to select from.")
    if not configured_name:
        return default_interface(interfaces)
    needle = configured_name.strip().lower()
    for iface in interfaces:
        if iface.name.lower() == needle or iface.display_name.lower() == needle:
            log_module_event(
                logger, "INTERFACE_SELECTED", detail=f"{iface.display_name}"
            )
            return iface
    raise InterfaceSelectionError(
        f"Configured interface '{configured_name}' was not found."
    )
