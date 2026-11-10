"""
Unit tests for packet_capture.app_mapper.

psutil is fully mocked/monkeypatched so these tests run deterministically
without depending on real running processes or elevated privileges.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from packet_capture.app_mapper import (
    ApplicationMapper,
    ConnectionRecord,
    UNKNOWN_APPLICATION,
    _build_lookup_tables,
    _determine_local_side,
    get_active_connections,
    map_packets_to_applications,
)


def _fake_conn(
    protocol_type: int,
    laddr: Optional[tuple],
    raddr: Optional[tuple],
    pid: Optional[int],
) -> SimpleNamespace:
    """Build a fake psutil sconn-like object."""
    laddr_obj = SimpleNamespace(ip=laddr[0], port=laddr[1]) if laddr else None
    raddr_obj = SimpleNamespace(ip=raddr[0], port=raddr[1]) if raddr else None
    return SimpleNamespace(
        fd=1,
        family=socket.AF_INET,
        type=protocol_type,
        laddr=laddr_obj,
        raddr=raddr_obj,
        status="ESTABLISHED",
        pid=pid,
    )


class _FakeProcess:
    """A fake psutil.Process with a mutable, inspectable identity.

    ``name_calls``/``exe_calls`` let tests assert whether process
    resolution work was actually repeated, and the ``create_time``
    identity can be changed between refreshes to simulate the OS
    recycling a PID onto a different process.
    """

    def __init__(self, name: str, create_time: float) -> None:
        self._name = name
        self._create_time = create_time
        self.name_calls = 0
        self.exe_calls = 0

    def name(self) -> str:
        self.name_calls += 1
        return self._name

    def exe(self) -> str:
        self.exe_calls += 1
        return "/usr/bin/" + self._name

    def create_time(self) -> float:
        return self._create_time


def _packet(
    protocol: str = "TCP",
    direction: str = "OUTGOING",
    source_ip: str = "192.168.1.5",
    source_port: int = 52345,
    destination_ip: str = "93.184.216.34",
    destination_port: int = 443,
) -> Dict[str, Any]:
    return {
        "protocol": protocol,
        "direction": direction,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
    }


class TestGetActiveConnections:
    def test_returns_records_for_tcp_and_udp(self, monkeypatch) -> None:
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
            _fake_conn(socket.SOCK_DGRAM, ("192.168.1.5", 6000), None, 5678),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        records = get_active_connections()
        assert len(records) == 2
        assert records[0].protocol == "TCP"
        assert records[0].pid == 1234
        assert records[1].protocol == "UDP"
        assert records[1].remote_ip is None

    def test_access_denied_returns_empty_list(self, monkeypatch) -> None:
        import psutil

        def raise_access_denied(kind: str = "inet") -> List[Any]:
            raise psutil.AccessDenied(pid=None, name=None)

        monkeypatch.setattr(psutil, "net_connections", raise_access_denied)

        records = get_active_connections()
        assert records == []

    def test_unsupported_socket_type_skipped(self, monkeypatch) -> None:
        fake_connections = [
            _fake_conn(999, ("192.168.1.5", 1000), None, 111),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        records = get_active_connections()
        assert records == []

    def test_generic_exception_returns_empty_list(self, monkeypatch) -> None:
        import psutil

        def raise_generic(kind: str = "inet") -> List[Any]:
            raise RuntimeError("simulated platform error")

        monkeypatch.setattr(psutil, "net_connections", raise_generic)

        records = get_active_connections()
        assert records == []


class TestDetermineLocalSide:
    def test_outgoing_uses_source_as_local(self) -> None:
        packet = _packet(direction="OUTGOING")
        local_ip, local_port, remote_ip, remote_port = _determine_local_side(packet)
        assert local_ip == "192.168.1.5"
        assert local_port == 52345
        assert remote_ip == "93.184.216.34"
        assert remote_port == 443

    def test_incoming_uses_destination_as_local(self) -> None:
        packet = _packet(direction="INCOMING")
        local_ip, local_port, remote_ip, remote_port = _determine_local_side(packet)
        assert local_ip == "93.184.216.34"
        assert local_port == 443
        assert remote_ip == "192.168.1.5"
        assert remote_port == 52345

    def test_unknown_direction_returns_all_none(self) -> None:
        packet = _packet(direction="UNKNOWN")
        result = _determine_local_side(packet)
        assert result == (None, None, None, None)


class TestBuildLookupTables:
    def test_exact_and_port_only_lookups_populated(self) -> None:
        connections = [
            ConnectionRecord(
                protocol="TCP",
                local_ip="192.168.1.5",
                local_port=52345,
                remote_ip="93.184.216.34",
                remote_port=443,
                pid=1234,
            )
        ]
        exact, port_only = _build_lookup_tables(connections)
        assert exact[("TCP", "192.168.1.5", 52345, "93.184.216.34", 443)] == 1234
        assert port_only[("TCP", 52345)] == 1234

    def test_connections_without_pid_are_skipped(self) -> None:
        connections = [
            ConnectionRecord(
                protocol="TCP",
                local_ip="192.168.1.5",
                local_port=52345,
                remote_ip=None,
                remote_port=None,
                pid=None,
            )
        ]
        exact, port_only = _build_lookup_tables(connections)
        assert exact == {}
        assert port_only == {}

    def test_shared_local_port_across_distinct_pids_is_ambiguous(self) -> None:
        connections = [
            ConnectionRecord(
                protocol="TCP",
                local_ip="0.0.0.0",
                local_port=8080,
                remote_ip=None,
                remote_port=None,
                pid=111,
            ),
            ConnectionRecord(
                protocol="TCP",
                local_ip="192.168.1.9",
                local_port=8080,
                remote_ip=None,
                remote_port=None,
                pid=222,
            ),
        ]
        exact, port_only = _build_lookup_tables(connections)
        assert (("TCP", 8080)) not in port_only
        assert port_only == {}

    def test_shared_local_port_with_single_pid_is_not_ambiguous(self) -> None:
        connections = [
            ConnectionRecord(
                protocol="TCP",
                local_ip="0.0.0.0",
                local_port=8080,
                remote_ip=None,
                remote_port=None,
                pid=111,
            ),
            ConnectionRecord(
                protocol="TCP",
                local_ip="192.168.1.9",
                local_port=8080,
                remote_ip=None,
                remote_port=None,
                pid=111,
            ),
        ]
        exact, port_only = _build_lookup_tables(connections)
        assert port_only[("TCP", 8080)] == 111


class TestApplicationMapper:
    def _mapper_with_connection(self, monkeypatch) -> ApplicationMapper:
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        fake_process = SimpleNamespace(
            name=lambda: "chrome.exe", exe=lambda: r"C:\Program Files\Chrome\chrome.exe"
        )
        monkeypatch.setattr(psutil, "Process", lambda pid: fake_process)

        mapper = ApplicationMapper()
        mapper.refresh()
        return mapper

    def test_enrich_packet_finds_exact_match(self, monkeypatch) -> None:
        mapper = self._mapper_with_connection(monkeypatch)
        packet = _packet(direction="OUTGOING")
        enriched = mapper.enrich_packet(packet)

        assert enriched["application_name"] == "chrome.exe"
        assert enriched["process_id"] == 1234
        assert enriched["executable_path"] == r"C:\Program Files\Chrome\chrome.exe"

    def test_enrich_packet_no_match_returns_unknown(self, monkeypatch) -> None:
        mapper = self._mapper_with_connection(monkeypatch)
        packet = _packet(
            direction="OUTGOING", source_port=9999, destination_port=9999
        )
        enriched = mapper.enrich_packet(packet)

        assert enriched["application_name"] == UNKNOWN_APPLICATION
        assert enriched["process_id"] is None
        assert enriched["executable_path"] is None

    def test_enrich_packet_does_not_mutate_original(self, monkeypatch) -> None:
        mapper = self._mapper_with_connection(monkeypatch)
        packet = _packet(direction="OUTGOING")
        mapper.enrich_packet(packet)
        assert "application_name" not in packet

    def test_auto_refresh_when_not_yet_refreshed(self, monkeypatch) -> None:
        import psutil

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        mapper = ApplicationMapper()
        packet = _packet(direction="OUTGOING")
        enriched = mapper.enrich_packet(packet)
        assert enriched["application_name"] == UNKNOWN_APPLICATION

    def test_process_resolution_failure_falls_back_to_unknown(
        self, monkeypatch
    ) -> None:
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        def raise_no_such_process(pid: int) -> Any:
            raise psutil.NoSuchProcess(pid=pid)

        monkeypatch.setattr(psutil, "Process", raise_no_such_process)

        mapper = ApplicationMapper()
        mapper.refresh()
        enriched = mapper.enrich_packet(_packet(direction="OUTGOING"))

        assert enriched["application_name"] == UNKNOWN_APPLICATION

    def test_process_cache_avoids_repeated_resolution(self, monkeypatch) -> None:
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        call_count = {"count": 0}

        def counting_process(pid: int) -> Any:
            call_count["count"] += 1
            return SimpleNamespace(name=lambda: "chrome.exe", exe=lambda: "path")

        monkeypatch.setattr(psutil, "Process", counting_process)

        mapper = ApplicationMapper()
        mapper.refresh()
        mapper.enrich_packet(_packet(direction="OUTGOING"))
        mapper.enrich_packet(_packet(direction="OUTGOING"))

        assert call_count["count"] == 1

    def test_udp_packet_matching(self, monkeypatch) -> None:
        fake_connections = [
            _fake_conn(socket.SOCK_DGRAM, ("192.168.1.5", 6000), None, 999),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: SimpleNamespace(name=lambda: "discord.exe", exe=lambda: None),
        )

        mapper = ApplicationMapper()
        mapper.refresh()
        packet = _packet(
            protocol="UDP",
            direction="OUTGOING",
            source_port=6000,
            destination_port=53,
        )
        enriched = mapper.enrich_packet(packet)
        assert enriched["application_name"] == "discord.exe"

    def test_non_tcp_udp_protocol_returns_no_match(self, monkeypatch) -> None:
        mapper = self._mapper_with_connection(monkeypatch)
        packet = _packet(protocol="ICMP", direction="OUTGOING")
        pid = mapper.match_pid(packet)
        assert pid is None

    def test_ambiguous_shared_port_returns_unknown_not_a_guess(
        self, monkeypatch
    ) -> None:
        fake_connections = [
            _fake_conn(socket.SOCK_STREAM, ("0.0.0.0", 8080), None, 111),
            _fake_conn(socket.SOCK_STREAM, ("192.168.1.9", 8080), None, 222),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: _FakeProcess(f"proc{pid}", float(pid)),
        )

        mapper = ApplicationMapper()
        mapper.refresh()
        packet = _packet(
            direction="OUTGOING",
            source_ip="192.168.1.5",
            source_port=8080,
            destination_ip="10.0.0.1",
            destination_port=443,
        )
        enriched = mapper.enrich_packet(packet)

        assert enriched["application_name"] == UNKNOWN_APPLICATION
        assert enriched["process_id"] is None

    def test_single_pid_shared_port_still_maps_via_port_fallback(
        self, monkeypatch
    ) -> None:
        fake_connections = [
            _fake_conn(socket.SOCK_STREAM, ("0.0.0.0", 8080), None, 111),
            _fake_conn(socket.SOCK_STREAM, ("192.168.1.9", 8080), None, 111),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: _FakeProcess(f"proc{pid}", float(pid)),
        )

        mapper = ApplicationMapper()
        mapper.refresh()
        packet = _packet(
            direction="OUTGOING",
            source_ip="192.168.1.5",
            source_port=8080,
            destination_ip="10.0.0.1",
            destination_port=443,
        )
        enriched = mapper.enrich_packet(packet)

        assert enriched["application_name"] == "proc111"
        assert enriched["process_id"] == 111

    def test_recycled_pid_not_attributed_to_new_process(self, monkeypatch) -> None:
        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        processes = {1234: _FakeProcess("chrome", 1000.0)}
        construct_calls: List[int] = []

        def process_factory(pid: int) -> Any:
            construct_calls.append(pid)
            return processes[pid]

        monkeypatch.setattr(psutil, "Process", process_factory)
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        mapper = ApplicationMapper()
        mapper.refresh()
        enriched = mapper.enrich_packet(_packet(direction="OUTGOING"))
        assert enriched["application_name"] == "chrome"

        # The OS recycles PID 1234 onto a *different* process after the
        # snapshot was taken. Packets still matching that snapshot must
        # keep being attributed to the snapshot-time process, never the
        # current (recycled) owner - enrich must not consult the live
        # process table at all.
        processes[1234] = _FakeProcess("keylogger", 9000.0)
        enriched = mapper.enrich_packet(_packet(direction="OUTGOING"))
        assert enriched["application_name"] == "chrome"
        assert len(construct_calls) == 1

        # A fresh refresh detects the recycle via the changed start
        # time (identity probe + re-resolution) and remaps the PID.
        mapper.refresh()
        enriched = mapper.enrich_packet(_packet(direction="OUTGOING"))
        assert enriched["application_name"] == "keylogger"
        assert len(construct_calls) == 3

    def test_stable_pid_is_not_reresolved_across_refreshes(
        self, monkeypatch
    ) -> None:
        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        processes = {1234: _FakeProcess("chrome", 1000.0)}

        def process_factory(pid: int) -> Any:
            return processes[pid]

        monkeypatch.setattr(psutil, "Process", process_factory)
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )

        mapper = ApplicationMapper()
        mapper.refresh()
        mapper.refresh()
        enriched = mapper.enrich_packet(_packet(direction="OUTGOING"))

        assert enriched["application_name"] == "chrome"
        process = processes[1234]
        assert process.name_calls == 1
        assert process.exe_calls == 1


class TestApplicationMapperRefreshIfStale:
    def test_refreshes_when_cooldown_elapsed(self, monkeypatch) -> None:
        import time as time_module

        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        mapper = ApplicationMapper()
        mapper.refresh()
        # Force the last refresh time far enough into the past that
        # any reasonable cooldown will have "elapsed".
        mapper._last_refresh_time = time_module.time() - 10.0

        refreshed = mapper.refresh_if_stale(min_interval_seconds=0.01)
        assert refreshed is True

    def test_does_not_refresh_within_cooldown(self, monkeypatch) -> None:
        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        mapper = ApplicationMapper()
        mapper.refresh()  # sets _last_refresh_time to "now"

        refreshed = mapper.refresh_if_stale(min_interval_seconds=1000.0)
        assert refreshed is False

    def test_refresh_updates_last_refresh_time(self, monkeypatch) -> None:
        import psutil

        from packet_capture.app_mapper import ApplicationMapper

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])

        mapper = ApplicationMapper()
        assert mapper._last_refresh_time == 0.0
        mapper.refresh()
        assert mapper._last_refresh_time > 0.0


class TestMapPacketsToApplications:
    def test_maps_full_list(self, monkeypatch) -> None:
        fake_connections = [
            _fake_conn(
                socket.SOCK_STREAM,
                ("192.168.1.5", 52345),
                ("93.184.216.34", 443),
                1234,
            ),
        ]
        import psutil

        monkeypatch.setattr(
            psutil, "net_connections", lambda kind="inet": fake_connections
        )
        monkeypatch.setattr(
            psutil,
            "Process",
            lambda pid: SimpleNamespace(name=lambda: "chrome.exe", exe=lambda: "p"),
        )

        packets = [_packet(direction="OUTGOING"), _packet(direction="OUTGOING")]
        enriched = map_packets_to_applications(packets)

        assert len(enriched) == 2
        assert all(p["application_name"] == "chrome.exe" for p in enriched)

    def test_empty_packet_list_returns_empty(self, monkeypatch) -> None:
        import psutil

        monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [])
        assert map_packets_to_applications([]) == []
