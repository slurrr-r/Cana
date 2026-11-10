"""
config.py
=========

Shared configuration for the CANA engine, Windows service, and UI.

Installed Windows services use ``%ProgramData%\\CANA`` as the
authoritative layout. ``CANA_CONFIG`` may only redirect developer/test
runs, never an installed service.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path
from typing import Any, Dict, Optional

from anomaly_detection.config import BASELINE_DB_PATH
from packet_capture.config import LOGS_DIR, SESSIONS_DIR, SUPPORTED_FILTERS
from risk_scoring.config import CORRELATION_WINDOW_SECONDS, RISK_HALF_LIFE_SECONDS

CONFIG_FILE_NAME = "config.json"
INSTALLER_USER_SID_FILE = "installer-user.sid"
PRIVILEGED_SERVICE_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
ACCOUNT_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")
ALLOWED_CONFIG_KEYS = {
    "capture_interface",
    "packet_filter",
    "logging_level",
    "monitoring_enabled",
    "automatic_startup",
    "persist",
    "notify",
}
BOOL_CONFIG_KEYS = {
    "monitoring_enabled",
    "automatic_startup",
    "persist",
    "notify",
    "print_summaries",
    "reset_baseline",
}
WATCHDOG_INTERVAL_SECONDS = 5.0
WATCHDOG_RESTART_DELAY_SECONDS = 8.0
WATCHDOG_MAX_RAPID_RESTARTS = 3
WATCHDOG_RAPID_WINDOW_SECONDS = 120.0


def application_root() -> Path:
    """
    Directory that holds CANA's source/install files.

    Frozen (PyInstaller) builds use the executable directory. Runtime
    data on Windows lives under ``program_data_dir()``, not here.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def uses_program_data() -> bool:
    """True for Windows and frozen installs; developer trees stay local."""
    return os.name == "nt" or bool(getattr(sys, "frozen", False))


def program_data_dir() -> Path:
    """Preferred per-machine data root on Windows; project data/ otherwise."""
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA")
        if base:
            return Path(base) / "CANA"
    if getattr(sys, "frozen", False):
        return application_root() / "data"
    return application_root() / "data"


def is_installed_runtime() -> bool:
    """
    True when this process is the installed Windows product.

    Frozen Windows binaries and the SCM service must ignore ``CANA_CONFIG``.
    Explicit ``CANA_DEV=1`` or ``CANA_TEST=1`` keeps developer overrides.
    """
    if os.environ.get("CANA_DEV") == "1" or os.environ.get("CANA_TEST") == "1":
        return False
    if os.name == "nt" and bool(getattr(sys, "frozen", False)):
        return True
    if os.environ.get("CANA_SERVICE") == "1" and os.name == "nt":
        return True
    return False


def default_config_path() -> Path:
    if not is_installed_runtime():
        override = os.environ.get("CANA_CONFIG")
        if override:
            return Path(override)
    if uses_program_data():
        return program_data_dir() / CONFIG_FILE_NAME
    return application_root() / "data" / CONFIG_FILE_NAME


_TRUE_BOOL_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_BOOL_VALUES = frozenset({"0", "false", "no", "off"})


def installer_user_sid_path() -> Path:
    return program_data_dir() / INSTALLER_USER_SID_FILE


def validate_installer_user_sid(sid: str) -> str:
    """Accept only an unelevated interactive user SID. Fail closed."""
    resolved = (sid or "").strip()
    if not ACCOUNT_SID_RE.fullmatch(resolved):
        raise ValueError(
            "Could not determine the installing user's unelevated SID. "
            "Installation aborted."
        )
    if resolved in PRIVILEGED_SERVICE_SIDS:
        raise ValueError(
            "Installer SID resolved to a privileged service account. "
            "Installation aborted."
        )
    return resolved


def load_installer_user_sid() -> str:
    path = installer_user_sid_path()
    if not path.exists():
        return ""
    # utf-8-sig so a BOM written by packaging tools does not silently
    # invalidate the SID (which would deny the UI at the pipe).
    raw = path.read_text(encoding="utf-8-sig").strip()
    try:
        return validate_installer_user_sid(raw)
    except ValueError:
        return ""


def save_installer_user_sid(sid: str) -> Path:
    resolved = validate_installer_user_sid(sid)
    path = installer_user_sid_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(resolved + "\n", encoding="utf-8")
    return path


def coerce_config_value(key: str, value: Any) -> Any:
    """Normalize a config update value without touching live state."""
    if key in BOOL_CONFIG_KEYS:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            text = value.strip().lower()
            if text in _TRUE_BOOL_VALUES:
                return True
            if text in _FALSE_BOOL_VALUES:
                return False
        raise ValueError(f"Invalid boolean for '{key}'")
    if key in {"risk_half_life_seconds", "correlation_window_seconds"}:
        try:
            number = float(value)
        except (TypeError, ValueError) as extra:
            raise ValueError(f"Invalid number for '{key}'") from extra
        if not math.isfinite(number) or number <= 0:
            raise ValueError(f"Invalid number for '{key}'")
        return number
    return value


@dataclass
class CANAConfig:
    """Service-relevant settings shared by the engine, service, and UI."""

    capture_interface: str = ""
    packet_filter: str = "ALL"
    logging_level: str = "INFO"
    database_path: str = ""
    sessions_dir: str = ""
    logs_dir: str = ""
    automatic_startup: bool = True
    monitoring_enabled: bool = True
    risk_half_life_seconds: float = RISK_HALF_LIFE_SECONDS
    correlation_window_seconds: float = CORRELATION_WINDOW_SECONDS
    notify: bool = False
    persist: bool = True
    print_summaries: bool = False
    reset_baseline: bool = False

    def resolved_database_path(self) -> Path:
        if self.database_path:
            return Path(self.database_path)
        if uses_program_data():
            return program_data_dir() / "cana.db"
        return BASELINE_DB_PATH

    def resolved_sessions_dir(self) -> Path:
        if self.sessions_dir:
            return Path(self.sessions_dir)
        if uses_program_data():
            return program_data_dir() / "sessions"
        return SESSIONS_DIR

    def resolved_logs_dir(self) -> Path:
        if self.logs_dir:
            return Path(self.logs_dir)
        if uses_program_data():
            return program_data_dir() / "logs"
        return LOGS_DIR

    def validate(self) -> None:
        if self.packet_filter.upper() not in SUPPORTED_FILTERS:
            raise ValueError(
                f"Unsupported packet filter '{self.packet_filter}'. "
                f"Must be one of {SUPPORTED_FILTERS}."
            )
        level = self.logging_level.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"Unsupported logging_level '{self.logging_level}'.")
        if (
            not math.isfinite(self.risk_half_life_seconds)
            or self.risk_half_life_seconds <= 0
        ):
            raise ValueError("Invalid risk_half_life_seconds.")
        if (
            not math.isfinite(self.correlation_window_seconds)
            or self.correlation_window_seconds <= 0
        ):
            raise ValueError("Invalid correlation_window_seconds.")
        self.logging_level = level
        self.packet_filter = self.packet_filter.upper()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def with_updates(self, updates: Dict[str, Any]) -> "CANAConfig":
        """Return a validated copy. Never mutates this instance."""
        unknown = set(updates) - ALLOWED_CONFIG_KEYS
        if unknown:
            raise ValueError(f"Unsupported configuration keys: {sorted(unknown)}")
        known = {
            key: coerce_config_value(key, value)
            for key, value in updates.items()
            if key in _FIELD_NAMES
        }
        candidate = replace(self, **known)
        candidate.validate()
        return candidate


_FIELD_NAMES = {item.name for item in fields(CANAConfig)}


def _from_mapping(raw: Dict[str, Any]) -> CANAConfig:
    known = {
        key: coerce_config_value(key, value)
        for key, value in raw.items()
        if key in _FIELD_NAMES
    }
    config = CANAConfig(**known)
    config.validate()
    return config


def load_config(path: Optional[Path] = None) -> CANAConfig:
    """
    Load configuration from JSON.

    Missing files yield defaults. Unknown keys are ignored so older
    installers remain compatible after new fields are added.
    """
    config_path = Path(path) if path is not None else default_config_path()
    if not config_path.exists():
        config = CANAConfig()
        config.validate()
        return config
    # utf-8-sig tolerates a UTF-8 BOM, which Windows PowerShell's
    # ``Set-Content -Encoding UTF8`` writes into installed config.json.
    with config_path.open("r", encoding="utf-8-sig") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("CANA configuration must be a JSON object.")
    return _from_mapping(raw)


def save_config(config: CANAConfig, path: Optional[Path] = None) -> Path:
    """Write configuration atomically-enough for a single local writer."""
    config.validate()
    config_path = Path(path) if path is not None else default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(config.to_dict(), indent=2, sort_keys=True) + "\n"
    tmp_path = config_path.with_suffix(config_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    tmp_path.replace(config_path)
    return config_path


def prepare_runtime_config(config: Optional[CANAConfig] = None) -> CANAConfig:
    """Fill Windows/frozen install paths if missing."""
    config = config if config is not None else load_config()
    changed = False
    if uses_program_data():
        root = program_data_dir()
        if not config.database_path:
            config.database_path = str(root / "cana.db")
            changed = True
        if not config.sessions_dir:
            config.sessions_dir = str(root / "sessions")
            changed = True
        if not config.logs_dir:
            config.logs_dir = str(root / "logs")
            changed = True
    config.validate()
    if changed:
        try:
            save_config(config)
        except OSError:
            pass
    return config


def public_config_dict(config: CANAConfig) -> Dict[str, Any]:
    """Serialize config for APIs without exposing secrets."""
    return config.to_dict()


def config_from_cli_args(args: Any) -> CANAConfig:
    """Map ``main.py`` argparse results onto the shared config object."""
    config = load_config()
    if getattr(args, "db", None) is not None:
        config.database_path = str(args.db)
    if getattr(args, "no_persist", False):
        config.persist = False
    if getattr(args, "reset_baseline", False):
        config.reset_baseline = True
    if getattr(args, "notify", False):
        config.notify = True
    if getattr(args, "risk_half_life", None) is not None:
        config.risk_half_life_seconds = float(args.risk_half_life)
    if getattr(args, "correlation_window", None) is not None:
        config.correlation_window_seconds = float(args.correlation_window)
    if getattr(args, "debug", False):
        config.logging_level = "DEBUG"
    config.print_summaries = True
    config.validate()
    return config


__all__ = [
    "ALLOWED_CONFIG_KEYS",
    "BOOL_CONFIG_KEYS",
    "CANAConfig",
    "CONFIG_FILE_NAME",
    "INSTALLER_USER_SID_FILE",
    "WATCHDOG_INTERVAL_SECONDS",
    "WATCHDOG_MAX_RAPID_RESTARTS",
    "WATCHDOG_RAPID_WINDOW_SECONDS",
    "WATCHDOG_RESTART_DELAY_SECONDS",
    "application_root",
    "coerce_config_value",
    "config_from_cli_args",
    "default_config_path",
    "installer_user_sid_path",
    "is_installed_runtime",
    "load_config",
    "load_installer_user_sid",
    "validate_installer_user_sid",
    "prepare_runtime_config",
    "program_data_dir",
    "public_config_dict",
    "save_config",
    "save_installer_user_sid",
    "uses_program_data",
]
