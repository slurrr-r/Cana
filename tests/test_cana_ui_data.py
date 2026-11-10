"""
Tests for the read-only data derivations behind the native UI.

These cover ``cana_ui.traffic`` (per-app sessions), ``cana_ui.incidents``
(alert grouping/KPIs), and ``cana_ui.correlated`` (read-only correlation
windows). Nothing here touches the engine: every input is a file or a
row the engine already persisted.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from cana_ui.correlated import CorrelatedStore, load_correlated
from cana_ui.explain import explain_alert, known_application_name
from cana_ui.incidents import (
    NOT_TRACKED,
    auto_resolved,
    build_incidents,
    build_kpis,
    filter_incidents,
    severity_label,
)
from cana_ui.traffic import (
    RANGE_SPECS,
    SessionTrafficStore,
    format_bytes,
    parse_packet_epoch,
)


# ----------------------------------------------------------------------
# traffic.py
# ----------------------------------------------------------------------
def test_parse_packet_epoch_handles_local_iso_and_epoch() -> None:
    epoch = 1_700_000_000
    local = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))
    assert parse_packet_epoch(local) == epoch
    assert parse_packet_epoch(str(epoch)) == float(epoch)
    assert parse_packet_epoch("1970-01-01T00:00:00+00:00") == 0.0
    assert parse_packet_epoch("not a time") is None
    assert parse_packet_epoch(None) is None
    assert parse_packet_epoch("") is None


def test_format_bytes() -> None:
    assert format_bytes(0) == "0 B"
    assert format_bytes(999) == "999 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1024 ** 3) == "1.0 GB"
    assert format_bytes(None) == "0 B"
    assert format_bytes("nonsense") == "0 B"


def _write_session(path: Path, packets) -> None:
    path.write_text(json.dumps({"packets": packets}), encoding="utf-8")


def test_session_store_aggregates_and_buckets(tmp_path: Path) -> None:
    now = time.time()
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 30))
    _write_session(
        tmp_path / "session_a.json",
        [
            {"application_name": "Chrome", "packet_size": 1000, "direction": "INCOMING", "timestamp": stamp},
            {"application_name": "Chrome", "packet_size": 400, "direction": "OUTGOING", "timestamp": stamp},
            {"application_name": "", "packet_size": 50, "direction": "UNKNOWN", "timestamp": stamp},
        ],
    )
    store = SessionTrafficStore(tmp_path, ttl_seconds=0.0)

    apps = {app.name: app for app in store.apps("24 Hours", now=now)}
    assert apps["Chrome"].down_bytes == 1000
    assert apps["Chrome"].up_bytes == 400
    assert apps["Unknown"].down_bytes == 50
    # Largest total first.
    assert store.apps("24 Hours", now=now)[0].name == "Chrome"

    series = store.series("Chrome", "24 Hours", now=now)
    assert len(series.labels) == RANGE_SPECS["24 Hours"].buckets
    assert sum(series.down) == 1000
    assert sum(series.up) == 400
    assert not series.is_empty

    # An empty range reports empty rather than inventing traffic.
    empty = store.series("Chrome", "3 Hours", now=now - 30 * 86400)
    assert empty.is_empty


def test_session_store_filters_each_range_without_inventing_traffic(tmp_path: Path) -> None:
    now = time.time()
    recent = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 20 * 60))
    today = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 5 * 3600))
    last_week = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 3 * 86400))
    last_month = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 14 * 86400))
    too_old = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 40 * 86400))
    _write_session(
        tmp_path / "session_ranges.json",
        [
            {"application_name": "chrome.exe", "packet_size": 100, "direction": "INCOMING", "timestamp": recent},
            {"application_name": "chrome.exe", "packet_size": 200, "direction": "INCOMING", "timestamp": today},
            {"application_name": "chrome.exe", "packet_size": 400, "direction": "INCOMING", "timestamp": last_week},
            {"application_name": "chrome.exe", "packet_size": 800, "direction": "INCOMING", "timestamp": last_month},
            {"application_name": "chrome.exe", "packet_size": 1600, "direction": "INCOMING", "timestamp": too_old},
        ],
    )
    store = SessionTrafficStore(tmp_path, ttl_seconds=0.0)

    three = store.apps("3 Hours", now=now)
    assert three[0].down_bytes == 100
    day = store.apps("24 Hours", now=now)
    assert day[0].down_bytes == 300
    week = store.apps("Week", now=now)
    assert week[0].down_bytes == 700
    month = store.apps("Month", now=now)
    assert month[0].down_bytes == 1500

    for key, expected in (("3 Hours", 100), ("24 Hours", 300), ("Week", 700), ("Month", 1500)):
        series = store.series("chrome.exe", key, now=now)
        assert len(series.labels) == RANGE_SPECS[key].buckets
        assert sum(series.down) == expected
        assert sum(series.up) == 0
        assert not series.is_empty


def test_session_store_ignores_missing_dir_and_bad_json(tmp_path: Path) -> None:
    store = SessionTrafficStore(tmp_path / "missing", ttl_seconds=0.0)
    assert store.apps("24 Hours") == []

    bad = tmp_path / "session_bad.json"
    bad.write_text("{not json", encoding="utf-8")
    store = SessionTrafficStore(tmp_path, ttl_seconds=0.0)
    assert store.apps("24 Hours") == []


def test_session_store_lists_real_sessions(tmp_path: Path) -> None:
    payload = {
        "session_id": "abc-123",
        "start_time": "2026-09-16T19:34:53.498604+00:00",
        "interface_display_name": "Ethernet",
        "applied_filter": "ALL",
        "total_packets": 2,
        "packets": [{"packet_size": 54}],
    }
    (tmp_path / "session_abc-123.json").write_text(json.dumps(payload), encoding="utf-8")
    store = SessionTrafficStore(tmp_path, ttl_seconds=0.0)
    rows = store.sessions()
    assert len(rows) == 1
    assert rows[0]["session_id"] == "abc-123"
    assert rows[0]["interface"] == "Ethernet"
    assert rows[0]["packet_count"] == 2
    assert rows[0]["filter"] == "ALL"
    empty = SessionTrafficStore(tmp_path / "missing", ttl_seconds=0.0)
    assert empty.sessions() == []


# ----------------------------------------------------------------------
# incidents.py
# ----------------------------------------------------------------------
def _alert(rule: str, severity: str, epoch: float, **extra) -> dict:
    data = {
        "rule_name": rule,
        "severity": severity,
        "reason": extra.pop("reason", ""),
        "application_name": extra.pop("application_name", "chrome.exe"),
        "source_ip": extra.pop("source_ip", "10.0.0.51"),
        "triggered_at_epoch": epoch,
    }
    data.update(extra)
    return data


def test_severity_label_collapses_engine_levels() -> None:
    assert severity_label("CRITICAL") == "High"
    assert severity_label("HIGH") == "High"
    assert severity_label("MEDIUM") == "Medium"
    assert severity_label("INFO") == "Low"
    assert severity_label("") == "Low"


def test_build_incidents_groups_and_counts() -> None:
    now = time.time()
    alerts = [
        _alert("port_scan", "HIGH", now - 100, source_ip="10.0.0.7"),
        _alert("port_scan", "HIGH", now - 50, source_ip="10.0.0.7"),
        _alert("dns_volume", "MEDIUM", now - 200, source_ip="10.0.0.9"),
    ]
    incidents = build_incidents(alerts, [], now)
    assert len(incidents) == 2
    scan = next(i for i in incidents if i.rule_name == "port_scan")
    assert scan.count == 2
    assert scan.severity == "High"
    # Newest incident sorts first.
    assert incidents[0].first_seen_epoch >= incidents[-1].first_seen_epoch


def test_incident_status_from_correlation_windows() -> None:
    now = time.time()
    alerts = [
        _alert("active_rule", "HIGH", now - 10),
        _alert("closed_rule", "LOW", now - 5000),
        _alert("orphan_rule", "MEDIUM", now - 7000, source_ip="10.0.0.3"),
    ]
    correlated = [
        {"started_at_epoch": now - 60, "ended_at_epoch": now + 600, "rule_names": ["active_rule"]},
        {"started_at_epoch": now - 6000, "ended_at_epoch": now - 4000, "rule_names": ["closed_rule"]},
    ]
    for alert in alerts:
        alert.update(direction='OUTGOING', destination_ip='8.8.8.8')
    for window in correlated:
        window.update(application_name='chrome.exe', destination_ip='8.8.8.8')
    incidents = {i.rule_name: i for i in build_incidents(alerts, correlated, now)}
    assert incidents["active_rule"].status == "Unknown"
    assert incidents["closed_rule"].status == "Window closed"
    assert incidents["orphan_rule"].status == "Unknown"


def test_incident_grouping_keeps_remote_peers_separate() -> None:
    now = time.time()
    for direction in ("OUTGOING", "INCOMING", None):
        alerts = []
        for remote in ("1.1.1.1", "9.9.9.9", "1.1.1.1"):
            source, destination = (remote, "10.0.0.5") if direction == "INCOMING" else ("10.0.0.5", remote)
            alerts.append(_alert("unusual_tcp_flags", "MEDIUM", now,
                                 source_ip=source, destination_ip=destination,
                                 direction=direction))
        incidents = build_incidents(alerts, [], now)
        assert len(incidents) == 2
        assert sorted(incident.count for incident in incidents) == [1, 2]


def test_incident_grouping_uses_same_peer_across_directions() -> None:
    now = time.time()
    alerts = [
        _alert("unusual_tcp_flags", "MEDIUM", now, direction="OUTGOING",
               source_ip="10.0.0.5", destination_ip="1.1.1.1"),
        _alert("unusual_tcp_flags", "MEDIUM", now, direction="INCOMING",
               source_ip="1.1.1.1", destination_ip="10.0.0.5"),
    ]
    incidents = build_incidents(alerts, [], now)
    assert len(incidents) == 1
    assert incidents[0].count == 2


def test_filter_incidents() -> None:
    now = time.time()
    alerts = [
        _alert("port_scan", "HIGH", now - 10, reason="Port scan"),
        _alert("dns_volume", "MEDIUM", now - 20, reason="Unusual DNS"),
    ]
    incidents = build_incidents(alerts, [], now)
    assert len(filter_incidents(incidents, severity="High")) == 1
    assert len(filter_incidents(incidents, severity="All")) == 2
    assert filter_incidents(incidents, search="dns")[0].rule_name == "dns_volume"
    assert filter_incidents(incidents, status="Resolved") == []


def test_build_kpis_and_auto_resolved() -> None:
    now = time.time()
    alerts = [_alert("r1", "HIGH", now - 100), _alert("r2", "LOW", now - 8 * 86400)]
    correlated = [
        {"started_at_epoch": now - 200, "ended_at_epoch": now - 100},
        {"started_at_epoch": now - 200, "ended_at_epoch": now + 500},
    ]
    kpis = {k["label"]: k["value"] for k in build_kpis(alerts, correlated, now)}
    assert kpis["Alerts this week"] == "1"
    assert kpis["Auto-resolved"] == "1"
    assert kpis["Devices flagged"] == "1"
    assert kpis["Avg. time to detect"] == NOT_TRACKED
    assert auto_resolved(correlated, now) == 1


# ----------------------------------------------------------------------
# correlated.py
# ----------------------------------------------------------------------
def _correlated_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS correlated_alerts ("
        " id INTEGER PRIMARY KEY, alert_id TEXT, started_at TEXT,"
        " started_at_epoch REAL, ended_at TEXT, ended_at_epoch REAL,"
        " application_name TEXT, destination_ip TEXT, rule_names TEXT,"
        " signal_count INTEGER, severity TEXT, score REAL, confidence REAL,"
        " reason TEXT)"
    )
    connection.execute(
        "INSERT INTO correlated_alerts (alert_id, started_at_epoch, ended_at_epoch, rule_names)"
        " VALUES ('a', 100.0, 200.0, '[\"r1\"]')"
    )
    connection.commit()
    connection.close()


def test_load_correlated_missing_and_present(tmp_path: Path) -> None:
    assert load_correlated(tmp_path / "nope.db") == []

    db = tmp_path / "alerts.db"
    _correlated_db(db)
    rows = load_correlated(db)
    assert len(rows) == 1
    assert rows[0]["rule_names"] == '["r1"]'


def test_explain_alert_hides_engine_jargon() -> None:
    explained = explain_alert(
        {
            "rule_name": "packet_size_anomaly",
            "severity": "LOW",
            "reason": (
                "Packet size 342B is a statistical outlier for this hour "
                "(baseline mean=100B, std_dev=63B)."
            ),
            "application_name": "chrome.exe",
            "source_ip": "2401:4900:c0d9:21a5:7c30:d238:be33:11d7",
        },
        "Low",
    )
    assert explained["title"] == "Chrome: Packet size exceeded the learned range"
    assert "statistical" not in explained["title"].lower()
    assert "std_dev" not in explained["why"].lower()
    assert "baseline" not in explained["why"].lower()
    assert "342B" in explained["technical"]
    assert known_application_name("UNKNOWN") == ""
    assert known_application_name("chrome.exe") == "chrome"


def test_build_incidents_uses_user_facing_title() -> None:
    now = time.time()
    alerts = [
        _alert(
            "packet_size_anomaly",
            "LOW",
            now - 10,
            reason="Packet size 342B is a statistical outlier for this hour (baseline mean=100B, std_dev=63B).",
            application_name="chrome.exe",
            protocol="UDP",
            communication_type="LOCAL_NETWORK",
        ),
        _alert(
            "unknown_application_internet",
            "MEDIUM",
            now - 20,
            reason="TCP traffic to/from the internet has no identifiable owning application.",
            application_name="UNKNOWN",
        ),
    ]
    incidents = build_incidents(alerts, [], now)
    size = next(i for i in incidents if i.rule_name == "packet_size_anomaly")
    unknown = next(i for i in incidents if i.rule_name == "unknown_application_internet")
    assert "statistical" not in size.name.lower()
    assert "Chrome" in size.name
    assert size.reason.startswith("Packet size")
    assert "Local network" in size.tags or "UDP traffic" in size.tags
    assert "could not be linked" in unknown.name.lower()
    assert unknown.application_name == ""


def test_correlated_store_caches(tmp_path: Path) -> None:
    db = tmp_path / "alerts.db"
    _correlated_db(db)
    store = CorrelatedStore(db, ttl_seconds=60.0)
    first = store.rows(now=1000.0)
    assert len(first) == 1
    # Within the TTL the cached list is returned even if the file changes.
    _correlated_db(db)
    assert store.rows(now=1001.0) is first
