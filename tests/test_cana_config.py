"""Tests for shared CANA configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from cana_engine.config import CANAConfig, coerce_config_value, load_config, save_config


def test_default_config_enables_monitoring() -> None:
    config = CANAConfig()
    config.validate()
    assert config.monitoring_enabled is True
    assert config.automatic_startup is True


def test_round_trip_json(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    config = CANAConfig(capture_interface="eth0", logging_level="debug")
    save_config(config, path)
    loaded = load_config(path)
    assert loaded.capture_interface == "eth0"
    assert loaded.logging_level == "DEBUG"


def test_missing_file_returns_defaults(tmp_path: Path) -> None:
    loaded = load_config(tmp_path / "missing.json")
    assert loaded.packet_filter == "ALL"


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_text('{"packet_filter": "TCP", "eval": "nope", "extra": 1}\n')
    loaded = load_config(path)
    assert loaded.packet_filter == "TCP"


def test_invalid_filter_rejected() -> None:
    with pytest.raises(ValueError):
        CANAConfig(packet_filter="FTP").validate()


def test_atomic_save_replaces_complete_file(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_text('{"packet_filter": "ALL"}\n')
    save_config(CANAConfig(packet_filter="TCP"), path)
    loaded = load_config(path)
    assert loaded.packet_filter == "TCP"
    assert not path.with_suffix(".json.tmp").exists()


def test_with_updates_does_not_mutate_original() -> None:
    config = CANAConfig(packet_filter="ALL")
    try:
        config.with_updates({"packet_filter": "FTP"})
        assert False, "expected validation error"
    except ValueError:
        pass
    assert config.packet_filter == "ALL"
    updated = config.with_updates({"packet_filter": "TCP"})
    assert updated.packet_filter == "TCP"
    assert config.packet_filter == "ALL"


def test_coerce_rejects_invalid_boolean() -> None:
    with pytest.raises(ValueError):
        coerce_config_value("monitoring_enabled", "banana")
    with pytest.raises(ValueError):
        coerce_config_value("notify", "maybe")
    assert coerce_config_value("monitoring_enabled", True) is True
    assert coerce_config_value("monitoring_enabled", "false") is False


def test_coerce_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        coerce_config_value("risk_half_life_seconds", float("nan"))
    with pytest.raises(ValueError):
        coerce_config_value("correlation_window_seconds", float("inf"))


def test_invalid_boolean_apply_does_not_mutate() -> None:
    config = CANAConfig(monitoring_enabled=True)
    with pytest.raises(ValueError):
        config.with_updates({"monitoring_enabled": "banana"})
    assert config.monitoring_enabled is True


def test_load_config_rejects_invalid_boolean(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_text('{"monitoring_enabled": "banana"}\n')
    with pytest.raises(ValueError):
        load_config(path)


def test_load_config_coerces_boolean_strings(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_text('{"monitoring_enabled": "false", "automatic_startup": "on"}\n')
    loaded = load_config(path)
    assert loaded.monitoring_enabled is False
    assert loaded.automatic_startup is True


def test_coerce_rejects_non_positive_numeric_ranges() -> None:
    with pytest.raises(ValueError):
        coerce_config_value("risk_half_life_seconds", 0)
    with pytest.raises(ValueError):
        coerce_config_value("correlation_window_seconds", -1)
    with pytest.raises(ValueError):
        coerce_config_value("risk_half_life_seconds", "NaN")


def test_load_config_rejects_invalid_numeric_range(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_text('{"risk_half_life_seconds": 0}\n')
    with pytest.raises(ValueError):
        load_config(path)


def test_load_config_tolerates_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"packet_filter": "TCP"}\n')
    loaded = load_config(path)
    assert loaded.packet_filter == "TCP"


def test_save_then_load_round_trip_has_no_bom(tmp_path: Path) -> None:
    path = tmp_path / "cana.json"
    save_config(CANAConfig(packet_filter="HTTPS"), path)
    assert not path.read_bytes().startswith(b"\xef\xbb\xbf")
    assert load_config(path).packet_filter == "HTTPS"


def test_invalid_numeric_apply_does_not_mutate() -> None:
    config = CANAConfig(risk_half_life_seconds=300.0)
    with pytest.raises(ValueError):
        CANAConfig(risk_half_life_seconds=-5).validate()
    assert config.risk_half_life_seconds == 300.0
