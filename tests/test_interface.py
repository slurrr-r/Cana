"""Unit tests for packet_capture.interface."""

from __future__ import annotations

from types import SimpleNamespace
from typing import List

import pytest

from packet_capture.interface import (
    InterfaceDetectionError,
    InterfaceSelectionError,
    NetworkInterface,
    default_interface,
    format_interface_menu,
    resolve_interface,
    select_interface,
)


def _make_interfaces() -> List[NetworkInterface]:
    return [
        NetworkInterface(
            index=1, name=r"\Device\NPF_{GUID1}", display_name="Wi-Fi",
            ip_address="192.168.1.10",
        ),
        NetworkInterface(
            index=2, name=r"\Device\NPF_{GUID2}", display_name="Ethernet",
            ip_address="10.0.0.5",
        ),
    ]


class TestGetAllLocalIps:
    def test_collects_v4_and_v6_across_interfaces(self, monkeypatch) -> None:
        import socket as socket_module
        from types import SimpleNamespace

        import psutil

        from packet_capture.interface import get_all_local_ips

        fake_addrs = {
            "Wi-Fi": [
                SimpleNamespace(
                    family=socket_module.AF_INET, address="10.81.61.39",
                    netmask=None, broadcast=None, ptp=None,
                ),
                SimpleNamespace(
                    family=socket_module.AF_INET6,
                    address="2401:4900:1c7e:b6cb:6d21:7c20:8b8b:ea6c",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
            "Ethernet": [
                SimpleNamespace(
                    family=socket_module.AF_INET, address="192.168.56.1",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
        }
        monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake_addrs)

        ips = get_all_local_ips()
        assert "10.81.61.39" in ips
        assert "2401:4900:1c7e:b6cb:6d21:7c20:8b8b:ea6c" in ips
        assert "192.168.56.1" in ips

    def test_filters_link_local_and_loopback(self, monkeypatch) -> None:
        import socket as socket_module
        from types import SimpleNamespace

        import psutil

        from packet_capture.interface import get_all_local_ips

        fake_addrs = {
            "Wi-Fi": [
                SimpleNamespace(
                    family=socket_module.AF_INET, address="169.254.1.1",
                    netmask=None, broadcast=None, ptp=None,
                ),
                SimpleNamespace(
                    family=socket_module.AF_INET, address="127.0.0.1",
                    netmask=None, broadcast=None, ptp=None,
                ),
                SimpleNamespace(
                    family=socket_module.AF_INET6, address="fe80::1234%12",
                    netmask=None, broadcast=None, ptp=None,
                ),
                SimpleNamespace(
                    family=socket_module.AF_INET6, address="::1",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
        }
        monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake_addrs)

        ips = get_all_local_ips()
        assert ips == []

    def test_deduplicates_addresses(self, monkeypatch) -> None:
        import socket as socket_module
        from types import SimpleNamespace

        import psutil

        from packet_capture.interface import get_all_local_ips

        fake_addrs = {
            "Wi-Fi": [
                SimpleNamespace(
                    family=socket_module.AF_INET, address="10.0.0.5",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
            "Virtual Adapter": [
                SimpleNamespace(
                    family=socket_module.AF_INET, address="10.0.0.5",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
        }
        monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake_addrs)

        ips = get_all_local_ips()
        assert ips.count("10.0.0.5") == 1

    def test_returns_empty_list_on_psutil_error(self, monkeypatch) -> None:
        import psutil

        from packet_capture.interface import get_all_local_ips

        def raise_error():
            raise RuntimeError("simulated platform error")

        monkeypatch.setattr(psutil, "net_if_addrs", raise_error)

        assert get_all_local_ips() == []

    def test_strips_zone_id_from_ipv6(self, monkeypatch) -> None:
        import socket as socket_module
        from types import SimpleNamespace

        import psutil

        from packet_capture.interface import get_all_local_ips

        fake_addrs = {
            "Wi-Fi": [
                SimpleNamespace(
                    family=socket_module.AF_INET6,
                    address="2401:4900:1c7e:b6cb::1%12",
                    netmask=None, broadcast=None, ptp=None,
                ),
            ],
        }
        monkeypatch.setattr(psutil, "net_if_addrs", lambda: fake_addrs)

        ips = get_all_local_ips()
        assert "2401:4900:1c7e:b6cb::1" in ips
        assert not any("%" in ip for ip in ips)


class TestNetworkInterfaceDataclass:
    def test_str_includes_display_name_and_ip(self) -> None:
        iface = _make_interfaces()[0]
        rendered = str(iface)
        assert "Wi-Fi" in rendered
        assert "192.168.1.10" in rendered
        assert rendered.startswith("[1]")

    def test_str_without_ip(self) -> None:
        iface = NetworkInterface(index=3, name="eth1", display_name="eth1")
        assert "None" not in str(iface)

    def test_all_local_ips_includes_both_v4_and_v6(self) -> None:
        iface = NetworkInterface(
            index=1, name="eth0", display_name="Ethernet",
            ip_address="10.81.61.39", ipv6_address="2401:4900::1",
        )
        assert iface.all_local_ips == ["10.81.61.39", "2401:4900::1"]

    def test_all_local_ips_v4_only(self) -> None:
        iface = NetworkInterface(
            index=1, name="eth0", display_name="Ethernet",
            ip_address="10.81.61.39",
        )
        assert iface.all_local_ips == ["10.81.61.39"]

    def test_all_local_ips_empty_when_no_addresses(self) -> None:
        iface = NetworkInterface(index=1, name="eth0", display_name="Ethernet")
        assert iface.all_local_ips == []


class TestFormatInterfaceMenu:
    def test_menu_lists_all_interfaces(self) -> None:
        interfaces = _make_interfaces()
        menu = format_interface_menu(interfaces)
        assert "Wi-Fi" in menu
        assert "Ethernet" in menu
        assert "[1]" in menu
        assert "[2]" in menu

    def test_menu_empty_list(self) -> None:
        menu = format_interface_menu([])
        assert "Available Network Interfaces" in menu


class TestSelectInterface:
    def test_valid_selection(self) -> None:
        interfaces = _make_interfaces()
        chosen = select_interface(interfaces, "2")
        assert chosen.display_name == "Ethernet"
        assert chosen.index == 2

    def test_selection_with_whitespace(self) -> None:
        interfaces = _make_interfaces()
        chosen = select_interface(interfaces, "  1  ")
        assert chosen.index == 1

    def test_invalid_non_numeric_selection(self) -> None:
        interfaces = _make_interfaces()
        with pytest.raises(InterfaceSelectionError):
            select_interface(interfaces, "wifi")

    def test_out_of_range_selection(self) -> None:
        interfaces = _make_interfaces()
        with pytest.raises(InterfaceSelectionError):
            select_interface(interfaces, "99")

    def test_zero_selection_out_of_range(self) -> None:
        interfaces = _make_interfaces()
        with pytest.raises(InterfaceSelectionError):
            select_interface(interfaces, "0")

    def test_empty_selection(self) -> None:
        interfaces = _make_interfaces()
        with pytest.raises(InterfaceSelectionError):
            select_interface(interfaces, "")

    def test_empty_interface_list(self) -> None:
        with pytest.raises(InterfaceSelectionError):
            select_interface([], "1")

    def test_negative_selection(self) -> None:
        interfaces = _make_interfaces()
        with pytest.raises(InterfaceSelectionError):
            select_interface(interfaces, "-1")


class TestDetectInterfacesErrorPaths:
    def test_detect_interfaces_raises_when_scapy_missing(self, monkeypatch) -> None:
        """
        Simulate Scapy import failure (e.g. not installed) and confirm
        we raise our own clean exception rather than crashing with a
        raw ImportError leaking out of the module boundary.
        """
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all":
                raise ImportError("simulated missing scapy")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        from packet_capture.interface import detect_interfaces

        with pytest.raises(InterfaceDetectionError):
            detect_interfaces()

    def test_detect_interfaces_raises_when_no_interfaces_found(
        self, monkeypatch
    ) -> None:
        """Simulate Npcap present but zero interfaces enumerated."""
        fake_conf = SimpleNamespace(ifaces=SimpleNamespace(data={}))

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        with pytest.raises(InterfaceDetectionError):
            detect_interfaces()

    def test_detect_interfaces_success_with_mocked_scapy(self, monkeypatch) -> None:
        """Simulate a healthy Scapy environment with two interfaces."""
        fake_raw_iface_1 = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{GUID1}", ip="192.168.1.10"
        )
        fake_raw_iface_2 = SimpleNamespace(
            name="Ethernet", network_name=r"\Device\NPF_{GUID2}", ip="10.0.0.5"
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(
                data={0: fake_raw_iface_1, 1: fake_raw_iface_2}
            )
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert len(interfaces) == 2
        assert interfaces[0].display_name == "Wi-Fi"
        assert interfaces[0].name == r"\Device\NPF_{GUID1}"
        assert interfaces[1].display_name == "Ethernet"

    def test_detect_interfaces_reloads_scapy_ifaces(self, monkeypatch) -> None:
        """Re-detect after Stop must refresh Scapy's cached iface table."""

        reloads: list = []
        fake_raw = SimpleNamespace(
            name="Ethernet",
            network_name=r"\Device\NPF_{GUID}",
            ip="10.0.0.1",
        )
        fake_ifaces = SimpleNamespace(
            data={0: fake_raw},
            reload=lambda: reloads.append(True),
        )
        fake_conf = SimpleNamespace(ifaces=fake_ifaces)

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert reloads == [True]
        assert len(interfaces) == 1
        assert interfaces[0].display_name == "Ethernet"

    def test_noise_interfaces_filtered_out_by_default(self, monkeypatch) -> None:
        """
        NDIS binding/filter pseudo-interfaces (QoS scheduler, WFP
        lightweight filters, VirtualBox filter driver, etc.) should be
        hidden by default, since they clutter the menu and are not
        independently usable capture targets.
        """
        real_iface = SimpleNamespace(
            name="Ethernet 3", network_name=r"\Device\NPF_{REAL}",
            ip="10.156.98.227",
        )
        noise_ifaces = [
            SimpleNamespace(
                name="Ethernet-QoS Packet Scheduler-0000",
                network_name=r"\Device\NPF_{N1}", ip=None,
            ),
            SimpleNamespace(
                name="Ethernet-WFP Native MAC Layer LightWeight Filter-0000",
                network_name=r"\Device\NPF_{N2}", ip=None,
            ),
            SimpleNamespace(
                name="Wi-Fi-Native WiFi Filter Driver-0000",
                network_name=r"\Device\NPF_{N3}", ip=None,
            ),
            SimpleNamespace(
                name="Ethernet 3-VirtualBox NDIS Light-Weight Filter-0000",
                network_name=r"\Device\NPF_{N4}", ip=None,
            ),
            SimpleNamespace(
                name="Teredo Tunneling Pseudo-Interface",
                network_name=r"\Device\NPF_{N5}", ip=None,
            ),
        ]
        all_raw = [real_iface] + noise_ifaces
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(
                data={i: iface for i, iface in enumerate(all_raw)}
            )
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert len(interfaces) == 1
        assert interfaces[0].display_name == "Ethernet 3"
        # Menu re-numbers cleanly starting at 1, regardless of raw position.
        assert interfaces[0].index == 1

    def test_include_all_bypasses_noise_filter(self, monkeypatch) -> None:
        real_iface = SimpleNamespace(
            name="Ethernet 3", network_name=r"\Device\NPF_{REAL}",
            ip="10.156.98.227",
        )
        noise_iface = SimpleNamespace(
            name="Ethernet-QoS Packet Scheduler-0000",
            network_name=r"\Device\NPF_{N1}", ip=None,
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(
                data={0: real_iface, 1: noise_iface}
            )
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces(include_all=True)
        assert len(interfaces) == 2

    def test_all_noise_falls_back_to_unfiltered(self, monkeypatch) -> None:
        """If filtering would remove every interface, fall back rather
        than leaving the user with an empty menu."""
        only_noise = SimpleNamespace(
            name="Ethernet-QoS Packet Scheduler-0000",
            network_name=r"\Device\NPF_{N1}", ip=None,
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: only_noise})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert len(interfaces) == 1
        assert interfaces[0].display_name == "Ethernet-QoS Packet Scheduler-0000"

    def test_interfaces_with_no_ip_filtered_out_by_default(self, monkeypatch) -> None:
        """
        Interfaces with no IP at all (e.g. 'Local Area Connection* 8')
        are inactive pseudo-adapters and should be hidden by default,
        since they cannot capture any real traffic.
        """
        real_iface = SimpleNamespace(
            name="Ethernet 3", network_name=r"\Device\NPF_{REAL}",
            ip="10.156.98.227",
        )
        no_ip_iface = SimpleNamespace(
            name="Local Area Connection* 8",
            network_name=r"\Device\NPF_{NOIP}", ip=None,
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: real_iface, 1: no_ip_iface})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert len(interfaces) == 1
        assert interfaces[0].display_name == "Ethernet 3"

    def test_include_all_shows_no_ip_interfaces_too(self, monkeypatch) -> None:
        real_iface = SimpleNamespace(
            name="Ethernet 3", network_name=r"\Device\NPF_{REAL}",
            ip="10.156.98.227",
        )
        no_ip_iface = SimpleNamespace(
            name="Local Area Connection* 8",
            network_name=r"\Device\NPF_{NOIP}", ip=None,
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: real_iface, 1: no_ip_iface})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces(include_all=True)
        assert len(interfaces) == 2

    def test_real_ip_interface_marked_likely_active(self, monkeypatch) -> None:
        real_iface = SimpleNamespace(
            name="Ethernet 3", network_name=r"\Device\NPF_{REAL}",
            ip="10.156.98.227",
        )
        apipa_iface = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{APIPA}",
            ip="169.254.224.49",
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: real_iface, 1: apipa_iface})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        by_name = {iface.display_name: iface for iface in interfaces}
        assert by_name["Ethernet 3"].is_likely_active is True
        assert by_name["Wi-Fi"].is_likely_active is False

    def test_loopback_not_marked_likely_active(self, monkeypatch) -> None:
        loopback_iface = SimpleNamespace(
            name="Loopback Pseudo-Interface 1",
            network_name=r"\Device\NPF_Loopback", ip="127.0.0.1",
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: loopback_iface})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].is_likely_active is False

    def test_str_shows_recommended_tag(self) -> None:
        from packet_capture.interface import NetworkInterface

        iface = NetworkInterface(
            index=1, name="eth0", display_name="Ethernet 3",
            ip_address="10.156.98.227", is_likely_active=True,
        )
        assert "recommended" in str(iface)

    def test_str_no_tag_when_not_active(self) -> None:
        from packet_capture.interface import NetworkInterface

        iface = NetworkInterface(
            index=1, name="eth0", display_name="Wi-Fi",
            ip_address="169.254.1.1", is_likely_active=False,
        )
        assert "recommended" not in str(iface)

    def test_ipv6_address_extracted_from_ips_dict(self, monkeypatch) -> None:
        import socket as socket_module

        dual_stack_iface = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{DUAL}",
            ip="10.81.61.39",
            ips={
                socket_module.AF_INET: ["10.81.61.39"],
                socket_module.AF_INET6: [
                    "fe80::1234",  # link-local, should be skipped
                    "2401:4900:57ab:eed1::1",  # real address, should be picked
                ],
            },
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: dual_stack_iface})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address == "2401:4900:57ab:eed1::1"

    def test_ipv6_absent_when_only_link_local_available(self, monkeypatch) -> None:
        import socket as socket_module

        iface_link_local_only = SimpleNamespace(
            name="Ethernet", network_name=r"\Device\NPF_{LL}",
            ip="10.0.0.5",
            ips={socket_module.AF_INET6: ["fe80::abcd", "::1"]},
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: iface_link_local_only})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address is None

    def test_ipv6_absent_when_no_ips_attribute(self, monkeypatch) -> None:
        iface_no_ips_attr = SimpleNamespace(
            name="Ethernet", network_name=r"\Device\NPF_{NOIPS}", ip="10.0.0.5"
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: iface_no_ips_attr})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address is None

    def test_ipv6_falls_back_to_psutil_when_scapy_has_no_ips(
        self, monkeypatch
    ) -> None:
        """
        This is the real-world fix: Scapy's own .ips structure varies
        by version and, on the reporter's actual machine, yielded
        nothing usable. psutil.net_if_addrs() - a stable, documented
        API - is used as the reliable fallback, matched by the
        interface's friendly name.
        """
        import socket as socket_module

        iface_no_scapy_ips = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{WIFI}", ip="10.81.61.39"
        )
        fake_conf = SimpleNamespace(
            ifaces=SimpleNamespace(data={0: iface_no_scapy_ips})
        )

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        import psutil

        fake_snic_v6 = SimpleNamespace(
            family=socket_module.AF_INET6,
            address="2401:4900:1c7e:b6cb:6d21:7c20:8b8b:ea6c",
            netmask=None,
            broadcast=None,
            ptp=None,
        )
        fake_snic_v4 = SimpleNamespace(
            family=socket_module.AF_INET,
            address="10.81.61.39",
            netmask="255.255.255.0",
            broadcast=None,
            ptp=None,
        )
        monkeypatch.setattr(
            psutil,
            "net_if_addrs",
            lambda: {"Wi-Fi": [fake_snic_v4, fake_snic_v6]},
        )

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address == "2401:4900:1c7e:b6cb:6d21:7c20:8b8b:ea6c"

    def test_ipv6_psutil_fallback_strips_zone_id_suffix(self, monkeypatch) -> None:
        import socket as socket_module

        iface = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{WIFI}", ip="10.81.61.39"
        )
        fake_conf = SimpleNamespace(ifaces=SimpleNamespace(data={0: iface}))

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        import psutil

        fake_snic_v6 = SimpleNamespace(
            family=socket_module.AF_INET6,
            address="2401:4900:1c7e:b6cb::1%12",
            netmask=None, broadcast=None, ptp=None,
        )
        monkeypatch.setattr(
            psutil, "net_if_addrs", lambda: {"Wi-Fi": [fake_snic_v6]}
        )

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address == "2401:4900:1c7e:b6cb::1"

    def test_ipv6_psutil_fallback_skips_link_local(self, monkeypatch) -> None:
        import socket as socket_module

        iface = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{WIFI}", ip="10.81.61.39"
        )
        fake_conf = SimpleNamespace(ifaces=SimpleNamespace(data={0: iface}))

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        import psutil

        fake_link_local = SimpleNamespace(
            family=socket_module.AF_INET6,
            address="fe80::ebc8:1021:2657:f8c4%12",
            netmask=None, broadcast=None, ptp=None,
        )
        monkeypatch.setattr(
            psutil, "net_if_addrs", lambda: {"Wi-Fi": [fake_link_local]}
        )

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address is None

    def test_ipv6_psutil_no_match_for_different_interface_name(
        self, monkeypatch
    ) -> None:
        import socket as socket_module

        iface = SimpleNamespace(
            name="Wi-Fi", network_name=r"\Device\NPF_{WIFI}", ip="10.81.61.39"
        )
        fake_conf = SimpleNamespace(ifaces=SimpleNamespace(data={0: iface}))

        import scapy.all as scapy_all

        monkeypatch.setattr(scapy_all, "conf", fake_conf)

        import psutil

        fake_snic_v6 = SimpleNamespace(
            family=socket_module.AF_INET6,
            address="2401:4900::1", netmask=None, broadcast=None, ptp=None,
        )
        # psutil's key is a DIFFERENT interface name than the one
        # selected - should not match.
        monkeypatch.setattr(
            psutil, "net_if_addrs", lambda: {"Ethernet": [fake_snic_v6]}
        )

        from packet_capture.interface import detect_interfaces

        interfaces = detect_interfaces()
        assert interfaces[0].ipv6_address is None

    def test_ipv6_menu_display_shows_detected_address(self) -> None:
        from packet_capture.interface import NetworkInterface

        iface = NetworkInterface(
            index=1, name="eth0", display_name="Wi-Fi",
            ip_address="10.81.61.39",
            ipv6_address="2401:4900:1c7e:b6cb::1",
        )
        rendered = str(iface)
        assert "2401:4900:1c7e:b6cb::1" in rendered


class TestDefaultAndResolveInterface:
    def test_default_prefers_likely_active(self) -> None:
        interfaces = [
            NetworkInterface(index=1, name="lo", display_name="Loopback"),
            NetworkInterface(
                index=2,
                name="eth0",
                display_name="Ethernet",
                ip_address="10.0.0.1",
                is_likely_active=True,
            ),
        ]
        chosen = default_interface(interfaces)
        assert chosen.name == "eth0"

    def test_default_falls_back_to_first(self) -> None:
        interfaces = _make_interfaces()
        chosen = default_interface(interfaces)
        assert chosen.index == 1

    def test_default_empty_raises(self) -> None:
        with pytest.raises(InterfaceSelectionError):
            default_interface([])

    def test_resolve_by_raw_name(self) -> None:
        interfaces = _make_interfaces()
        chosen = resolve_interface(interfaces, r"\Device\NPF_{GUID2}")
        assert chosen.display_name == "Ethernet"

    def test_resolve_by_display_name_case_insensitive(self) -> None:
        interfaces = _make_interfaces()
        chosen = resolve_interface(interfaces, "wi-fi")
        assert chosen.display_name == "Wi-Fi"

    def test_resolve_empty_uses_default(self) -> None:
        interfaces = [
            NetworkInterface(index=1, name="wlan0", display_name="Wi-Fi"),
            NetworkInterface(
                index=2,
                name="eth0",
                display_name="Ethernet",
                is_likely_active=True,
            ),
        ]
        chosen = resolve_interface(interfaces, "")
        assert chosen.name == "eth0"

    def test_resolve_unknown_raises(self) -> None:
        with pytest.raises(InterfaceSelectionError):
            resolve_interface(_make_interfaces(), "not-a-nic")
