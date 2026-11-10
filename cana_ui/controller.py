"""
controller.py
=============

Native UI controller. Talks only to the Windows service via ControlClient.
Never starts packet capture or owns the engine.
"""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from cana_engine.client import ControlClient, ControlClientError, SERVICE_UNAVAILABLE
from cana_engine.ipc import PIPE_RECONNECT, PipeClient, PipeProtocolError
from cana_service.constants import SERVICE_NAME

UNAVAILABLE = {
    "ok": False,
    "state": "service_not_running",
    "display_state": "Service Not Running",
    "running": False,
    "capture_active": False,
    "last_error": SERVICE_UNAVAILABLE,
    "health": {
        "service_alive": False,
        "engine_alive": False,
        "capture_alive": False,
        "database_available": False,
        "packets_processed": 0,
        "packets_dropped": 0,
        "applications_observed": 0,
        "selected_interface": "",
        "packet_filter": "",
        "last_packet_at": None,
        "last_checkpoint_at": None,
        "last_error": SERVICE_UNAVAILABLE,
        "capture_error": "",
        "monitoring_enabled": False,
    },
    "service_health": {
        "service_alive": False,
        "engine_alive": False,
        "capture_alive": False,
        "database_available": False,
    },
    "overview": {},
    "alerts": [],
    "risk": [],
    "config": {},
    "service_unavailable": True,
}

DISPLAY_MAP = {
    "protected": "Protected",
    "monitoring": "Monitoring",
    "starting": "Starting",
    "stopped": "Stopped",
    "stopping": "Stopped",
    "capture_unavailable": "Capture Unavailable",
    "service_error": "Unavailable",
    "service_not_running": "Service Not Running",
    "degraded": "Degraded",
}

SERVICE_LABELS = {
    "not_installed": "Not installed",
    "stopped": "Stopped",
    "starting": "Starting",
    "stopping": "Stopping",
    "running": "Running",
    "start_failed": "Start failed",
    "stop_failed": "Stop failed",
    "error": "Error",
    "unknown": "Unknown",
}

CONNECTION_LABELS = {
    "connected": "Connected",
    "connecting": "Connecting",
    "disconnected": "Disconnected",
    "reconnecting": "Reconnecting",
}

_SCM_STATE_TOKENS = frozenset(
    {"RUNNING", "START_PENDING", "STOP_PENDING", "STOPPED", "PAUSED"}
)
MONITORING_LABELS = {
    "stopped": "Stopped",
    "starting": "Starting",
    "running": "Running",
    "stopping": "Stopping",
    "start_failed": "Start failed",
    "stop_failed": "Stop failed",
    "unknown": "Checking...",
}
CAPTURE_LABELS = {
    "unavailable": "Unavailable",
    "initializing": "Initializing",
    "running": "Running",
    "failed": "Failed",
    "stopped": "Stopped",
}

_TECHNICAL_MARKERS = (
    "traceback",
    "pywintypes",
    "permissionerror",
    "attributeerror",
    "brokenpipeerror",
    "winerror",
    "oserror",
    "filenotfounderror",
)


def user_facing_error(raw: Any, fallback: str = "") -> str:
    """Map control/pipe/Windows errors to a short user-facing sentence.

    Raw exceptions stay in ``technical_details`` / logs. Never show
    PermissionError, pywintypes, traceback, or WinError codes in the UI.
    """
    text = str(raw or "").strip()
    lowered = text.lower()
    if not text:
        return fallback or "CANA couldn't connect to the background service."
    if "forbidden" in lowered or "permission" in lowered or "access is denied" in lowered:
        return "CANA doesn't have permission to perform this action."
    if "could not identify caller" in lowered or "reconnect" in lowered:
        return PIPE_RECONNECT
    if "temporarily unavailable" in lowered:
        return PIPE_RECONNECT
    if "start monitoring" in lowered and "couldn't" in lowered:
        return "CANA couldn't start monitoring."
    if "couldn't start monitoring" in lowered:
        return "CANA couldn't start monitoring."
    if "monitoring start failed" in lowered:
        return "CANA couldn't start monitoring."
    if "service is starting" in lowered or "start_pending" in lowered:
        return "CANA service is starting. Please wait..."
    if "not installed" in lowered:
        return "CANA Windows service is not installed."
    if "not running" in lowered or "service is not running" in lowered:
        return SERVICE_UNAVAILABLE
    if any(marker in lowered for marker in _TECHNICAL_MARKERS):
        if "1056" in lowered or "already been started" in lowered:
            return "CANA service is already running."
        if "5" in lowered and ("denied" in lowered or "access" in lowered):
            return "CANA doesn't have permission to perform this action."
        if "2" in lowered and ("cannot find" in lowered or "not found" in lowered):
            return "CANA couldn't connect to the background service."
        return fallback or "CANA couldn't connect to the background service."
    if text.startswith("CANA"):
        return text
    return fallback or "CANA couldn't connect to the background service."


def technical_details(raw: Any) -> str:
    """Keep the original error for logs / View technical details."""
    return str(raw or "").strip()


def _is_control_error(exc: BaseException) -> bool:
    """True for pipe/control failures, including reloaded exception classes."""
    if isinstance(exc, (ControlClientError, PipeProtocolError)):
        return True
    return type(exc).__name__ in {"ControlClientError", "PipeProtocolError"}


def classify_scm_state(raw: str) -> str:
    """Map an ``sc.exe query`` token onto the independent service state.

    Empty or malformed SCM output is ``unknown``, never ``stopped``.
    """
    text = str(raw or "").strip().upper()
    if not text or text == "UNKNOWN":
        return "unknown"
    if text == "1060" or "1060" in text or "DOES NOT EXIST" in text:
        return "not_installed"
    if text in {"RUNNING"}:
        return "running"
    if text in {"START_PENDING"}:
        return "starting"
    if text in {"STOP_PENDING"}:
        return "stopping"
    if text in {"STOPPED", "PAUSED"}:
        return "stopped"
    return "unknown"


def runtime_states(payload: Dict[str, Any]) -> Dict[str, str]:
    """Independent service / monitoring / capture / data-source states.

    SERVICE RUNNING never implies MONITORING RUNNING. Historical Apps
    data never implies live capture.
    """
    health = payload.get("health") or payload.get("service_health") or {}
    scm = classify_scm_state(str(payload.get("scm_state") or ""))
    pipe_alive = bool(health.get("service_alive"))
    if payload.get("service_not_installed") or scm == "not_installed":
        service = "not_installed"
    elif payload.get("service_start_failed"):
        service = "start_failed"
    elif payload.get("service_stop_failed"):
        service = "stop_failed"
    elif str(payload.get("state") or "").lower() == "service_error":
        service = "error"
    elif payload.get("service_starting") or scm == "starting":
        service = "starting"
    elif scm == "running":
        service = "running"
    elif scm == "stopping":
        service = "stopping"
    elif scm == "stopped":
        service = "stopped"
    elif pipe_alive:
        service = "running"
    elif payload.get("service_unavailable"):
        service = "stopped"
    elif scm == "unknown":
        service = "unknown"
    else:
        service = "stopped"

    engine_alive = bool(health.get("engine_alive", payload.get("running")))
    monitoring_enabled = bool(health.get("monitoring_enabled", False))
    ui_state = str(payload.get("state") or "").lower()
    if payload.get("monitoring_start_failed"):
        monitoring = "start_failed"
    elif payload.get("monitoring_stop_failed"):
        monitoring = "stop_failed"
    elif payload.get("monitoring_starting") or ui_state == "starting":
        monitoring = "starting"
    elif ui_state == "stopping":
        monitoring = "stopping"
    elif engine_alive and monitoring_enabled:
        monitoring = "running"
    elif service == "unknown" and "engine_alive" not in health and not payload.get("state"):
        monitoring = "unknown"
    else:
        monitoring = "stopped"

    capture_alive = bool(health.get("capture_alive", payload.get("capture_active")))
    capture_error = str(health.get("capture_error") or payload.get("last_error") or "")
    if capture_alive:
        capture = "running"
    elif monitoring == "starting":
        capture = "initializing"
    elif capture_error and monitoring_enabled:
        capture = "failed"
    elif monitoring == "stopped":
        capture = "stopped" if service == "running" else "unavailable"
    else:
        capture = "unavailable"

    if monitoring == "running" and capture == "running":
        data_source = "live"
    elif payload.get("has_session_data"):
        data_source = "historical"
    else:
        data_source = "none"

    last_error = str(payload.get("last_error") or "").lower()
    if "reconnect" in last_error or "temporarily unavailable" in last_error:
        connection = "reconnecting"
    elif payload.get("connection_lost"):
        connection = "disconnected"
    elif payload.get("service_unavailable") and service in {"running", "unknown", "error"}:
        connection = "disconnected"
    elif service == "unknown" and not pipe_alive:
        connection = "connecting"
    else:
        connection = "connected"

    return {
        "service": service,
        "monitoring": monitoring,
        "capture": capture,
        "data_source": data_source,
        "connection": connection,
        "service_label": SERVICE_LABELS.get(service, service),
        "monitoring_label": MONITORING_LABELS.get(monitoring, monitoring),
        "capture_label": CAPTURE_LABELS.get(capture, capture),
        "connection_label": CONNECTION_LABELS.get(connection, connection),
    }


def display_state_for(payload: Dict[str, Any]) -> str:
    runtime = runtime_states(payload)
    if runtime["service"] == "not_installed":
        return "Service Not Installed"
    if runtime["service"] == "starting":
        return "Service Starting"
    if runtime["service"] == "start_failed":
        return "Service Start Failed"
    if runtime["service"] == "stop_failed":
        return "Service Stop Failed"
    if runtime["service"] == "error":
        return "Service Error"
    if runtime["service"] == "stopping":
        return "Service Stopping"
    if runtime.get("connection") == "disconnected":
        return "Connection Lost"
    if runtime.get("connection") == "reconnecting":
        return "Reconnecting"
    if runtime.get("connection") == "connecting":
        return "Connecting..."
    if runtime["monitoring"] == "unknown":
        return "Checking monitoring status..."
    if runtime["service"] == "unknown" and payload.get("service_unavailable"):
        return "Service Not Running"
    if runtime["service"] != "running" and payload.get("service_unavailable"):
        return "Service Not Running"
    if runtime["monitoring"] == "starting":
        return "Starting"
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Protected"
    if runtime["monitoring"] == "running" and runtime["capture"] in {"failed", "unavailable"}:
        return "Capture Unavailable"
    if runtime["monitoring"] == "running":
        return "Monitoring"
    if runtime["capture"] == "failed":
        return "Capture Unavailable"
    state = str(payload.get("state") or "").lower()
    mapped = DISPLAY_MAP.get(state)
    if mapped:
        return mapped
    raw = payload.get("display_state")
    if raw:
        return str(raw)
    if runtime["service"] == "running":
        return "Stopped"
    return "Unavailable"


def header_status(payload: Dict[str, Any]) -> Dict[str, str]:
    runtime = runtime_states(payload)
    service_label = runtime["service_label"]
    if runtime["service"] == "stopped":
        service_label = "Not running"
    monitoring_label = runtime["monitoring_label"]
    if runtime["monitoring"] == "running":
        monitoring_label = "Active"
    capture_label = runtime["capture_label"]
    if runtime["capture"] == "running":
        capture_label = "Active"
    elif runtime["capture"] == "failed":
        capture_label = "Failed"
    elif runtime["capture"] == "stopped":
        capture_label = "Stopped"
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        detection = "Active"
    else:
        detection = "Inactive"
    return {
        "badge": display_state_for(payload),
        "service": service_label,
        "capture": capture_label,
        "monitoring": monitoring_label,
        "detection": detection,
        "service_state": runtime["service"],
        "monitoring_state": runtime["monitoring"],
        "capture_state": runtime["capture"],
        "connection_state": runtime["connection"],
        "data_source": runtime["data_source"],
    }


def _uses_injected_transport(client: Any) -> bool:
    """True when the UI talks through an explicit in-process pipe transport.

    Production uses the default named-pipe client (no injected transport)
    and must still query Windows SCM. Tests and developer in-process
    control inject a transport and must not be overridden by a live
    SCM result for a different process.
    """
    pipe = getattr(client, "_pipe", None)
    return callable(getattr(pipe, "_transport", None))


class UIController:
    """Thin service client used by the native window and tests."""

    def __init__(self, client: Optional[ControlClient] = None) -> None:
        self.client = client or ControlClient.from_config()
        self.last_payload: Dict[str, Any] = dict(UNAVAILABLE)
        self.last_error = ""

    @classmethod
    def from_pipe(cls, pipe: PipeClient) -> "UIController":
        return cls(ControlClient.from_config(pipe_client=pipe))

    def snapshot(self) -> Dict[str, Any]:
        scm_state = query_windows_service_state()
        scm_kind = classify_scm_state(scm_state)
        trust_client = _uses_injected_transport(self.client)
        if trust_client:
            scm_state = "UNKNOWN"
            scm_kind = "unknown"
        try:
            payload = self.client.snapshot()
            payload.setdefault("ok", True)
            payload["service_unavailable"] = False
            payload.setdefault("alerts", [])
            payload.setdefault("risk", [])
            payload.setdefault("overview", {})
            payload.setdefault("config", {})
            if scm_kind and scm_kind != "unknown":
                payload["scm_state"] = scm_state
            else:
                payload.setdefault("scm_state", scm_state or "UNKNOWN")
            payload["service_not_installed"] = scm_kind == "not_installed"
            payload["display_state"] = display_state_for(payload)
            self.last_payload = payload
            self.last_error = str(payload.get("last_error") or "")
            return payload
        except Exception as extra:  # noqa: BLE001
            if not _is_control_error(extra):
                raise
            detail = technical_details(extra)
            message = user_facing_error(extra)
            previous = self.last_payload if isinstance(self.last_payload, dict) else {}
            previous_health = previous.get("health") or previous.get("service_health") or {}
            had_live = bool(previous_health.get("service_alive")) and not previous.get(
                "service_unavailable"
            )
            reconnecting = message == PIPE_RECONNECT or "reconnect" in message.lower()
            if (
                scm_kind in {"running", "starting"}
                and had_live
                and reconnecting
            ):
                payload = copy.deepcopy(previous)
                payload["ok"] = False
                payload["service_unavailable"] = False
                payload["last_error"] = message
                payload["technical_details"] = detail
                payload["scm_state"] = scm_state or payload.get("scm_state") or "RUNNING"
                payload["display_state"] = display_state_for(payload)
                health = payload.setdefault("health", {})
                health["service_alive"] = True
                health["last_error"] = message
                payload.setdefault("service_health", {})["service_alive"] = True
                self.last_payload = payload
                self.last_error = message
                return payload
            if scm_kind == "not_installed":
                message = user_facing_error(
                    "CANA Windows service is not installed."
                )
            payload = copy.deepcopy(UNAVAILABLE)
            payload["last_error"] = message
            payload["technical_details"] = detail
            payload["scm_state"] = scm_state or "UNKNOWN"
            payload["service_not_installed"] = scm_kind == "not_installed"
            if scm_kind == "not_installed":
                payload["service_unavailable"] = True
                payload["state"] = "service_not_running"
                payload["display_state"] = "Service Not Installed"
            elif scm_kind in {"running", "starting"}:
                payload["service_unavailable"] = False
                payload["state"] = "stopped"
                payload["display_state"] = "Stopped"
                payload["health"]["service_alive"] = True
                payload["service_health"]["service_alive"] = True
                payload["health"]["last_error"] = message
            elif scm_kind == "unknown":
                payload["service_not_installed"] = False
                payload["display_state"] = display_state_for(payload)
            self.last_payload = payload
            self.last_error = message
            return payload

    def start_monitoring(self) -> Dict[str, Any]:
        current = self.snapshot()
        runtime = runtime_states(current)
        if runtime["service"] != "running":
            if runtime["service"] == "not_installed":
                message = "CANA Windows service is not installed."
            elif runtime["service"] == "unknown":
                message = (
                    "CANA service state is unknown. Start the CANA Windows "
                    "service, then retry Start Monitoring."
                )
            else:
                message = (
                    "CANA service is not running. Start the CANA Windows "
                    "service, then retry Start Monitoring."
                )
            current["ok"] = False
            current["last_error"] = user_facing_error(message)
            current["technical_details"] = message
            current["monitoring_start_failed"] = True
            self.last_error = current["last_error"]
            self.last_payload = current
            return current
        try:
            result = self.client.start_monitoring()
            payload = self.snapshot() if "health" not in result else result
            payload.setdefault("ok", True)
            deadline = time.time() + 3
            while time.time() < deadline:
                health = payload.get("health") or {}
                if (
                    health.get("engine_alive")
                    or health.get("capture_error")
                    or health.get("last_error")
                ):
                    break
                time.sleep(0.1)
                payload = self.snapshot()
            return payload
        except Exception as extra:  # noqa: BLE001
            if not _is_control_error(extra):
                raise
            payload = self.snapshot()
            payload["ok"] = False
            payload["last_error"] = user_facing_error(
                extra, "CANA couldn't start monitoring."
            )
            payload["technical_details"] = technical_details(extra)
            payload["monitoring_start_failed"] = True
            payload["service_unavailable"] = False
            self.last_error = payload["last_error"]
            self.last_payload = payload
            return payload

    def stop_monitoring(self) -> Dict[str, Any]:
        try:
            result = self.client.stop_monitoring()
            payload = self.snapshot() if "health" not in result else result
            payload.setdefault("ok", True)
            return payload
        except Exception as extra:  # noqa: BLE001
            if not _is_control_error(extra):
                raise
            payload = self.snapshot()
            payload["ok"] = False
            payload["last_error"] = user_facing_error(
                extra, "CANA couldn't stop monitoring."
            )
            payload["technical_details"] = technical_details(extra)
            payload["monitoring_stop_failed"] = True
            payload["service_unavailable"] = False
            self.last_error = payload["last_error"]
            self.last_payload = payload
            return payload

    def apply_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self.client.apply_config(updates)
        except Exception as exc:  # noqa: BLE001
            if not _is_control_error(exc):
                raise
            self.last_error = str(exc)
            raise ControlClientError(str(exc)) from exc

    def get_config(self) -> Dict[str, Any]:
        try:
            return self.client.get_config()
        except Exception as extra:  # noqa: BLE001
            if not _is_control_error(extra):
                raise
            return dict(self.last_payload.get("config") or {})


def _run_sc(*args: str) -> Any:
    """Run ``sc.exe`` safely from both console and windowed (frozen) builds.

    A PyInstaller ``console=False`` process has no valid stdin handle;
    letting the child inherit it raises ``OSError [WinError 6]`` and makes
    every service check fail. ``CREATE_NO_WINDOW`` also stops ``sc.exe``
    from flashing a console window.
    """
    import os
    import subprocess

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return subprocess.run(
        ["sc.exe", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
    )


def query_windows_service() -> tuple:
    """Return ``(scm_token, kind)`` for the registered CANA service."""
    try:
        import os

        if os.name != "nt":
            return "UNKNOWN", "unknown"
        result = _run_sc("query", SERVICE_NAME)
        text = f"{result.stdout or ''}{result.stderr or ''}"
        if _scm_code(result) == 1060 or "1060" in text:
            return "1060", "not_installed"
        token = _parse_scm_state_token(text)
        if not token:
            return "UNKNOWN", "unknown"
        kind = classify_scm_state(token)
        return token, kind
    except Exception:  # noqa: BLE001
        return "UNKNOWN", "unknown"


def query_windows_service_state() -> str:
    """Return the SCM state token, or ``UNKNOWN`` when SCM is unavailable."""
    token, kind = query_windows_service()
    if kind == "not_installed":
        return "1060"
    if not token:
        return "UNKNOWN"
    return token


def _scm_text(result: Any) -> str:
    return f"{getattr(result, 'stdout', '') or ''}{getattr(result, 'stderr', '') or ''}"


def _scm_code(result: Any) -> int:
    return int(getattr(result, "returncode", 1) or 0)


def _parse_scm_state_token(text: str) -> str:
    """Extract a recognized SCM STATE token, or empty if output is unusable."""
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("STATE"):
            continue
        parts = stripped.split()
        if not parts:
            continue
        token = parts[-1].upper()
        if token in _SCM_STATE_TOKENS:
            return token
    return ""


def _scm_query_token() -> tuple:
    """Run ``sc.exe query`` and return ``(token, text, code)``."""
    queried = _run_sc("query", SERVICE_NAME)
    text = _scm_text(queried)
    code = _scm_code(queried)
    token = _parse_scm_state_token(text)
    return token, text, code


def try_start_windows_service(runner: Optional[Callable[[], Any]] = None) -> str:
    """Ask Windows to start the CANA service. Never starts capture itself.

    Returns ``already_running`` when SCM is already RUNNING, an empty
    string when start reached RUNNING, or an error message.
    """
    if runner is not None:
        try:
            runner()
            return ""
        except Exception as extra:  # noqa: BLE001
            return str(extra)
    try:
        token, query_text, query_code = _scm_query_token()
        if query_code == 1060 or "1060" in query_text:
            return "CANA Windows service is not installed."
        if not token:
            return "CANA service state is unknown."
        if token == "RUNNING":
            return "already_running"
        if token != "START_PENDING":
            result = _run_sc("start", SERVICE_NAME)
            text = _scm_text(result)
            code = _scm_code(result)
            if code == 5:
                sc = str(Path(os.environ["SystemRoot"]) / "System32/sc.exe")
                code = _run_elevated(sc, "start " + SERVICE_NAME)
            if code == 1060 or "1060" in text:
                return "CANA Windows service is not installed."
            if code == 1056 or "1056" in text:
                return "already_running"
            if code != 0:
                return (result.stderr or result.stdout or "sc start failed").strip()
            started_token = _parse_scm_state_token(text)
            if started_token == "RUNNING":
                return ""
        token, query_text, query_code = _scm_query_token()
        if query_code == 1060 or "1060" in query_text:
            return "CANA Windows service is not installed."
        if not token:
            return "CANA service state is unknown."
        if token == "RUNNING":
            return ""
        if token == "START_PENDING":
            deadline = time.time() + 8
            while time.time() < deadline:
                token, query_text, query_code = _scm_query_token()
                if token == "RUNNING":
                    return ""
                if query_code == 1060 or "1060" in query_text:
                    return "CANA Windows service is not installed."
                if not token:
                    return "CANA service state is unknown."
                time.sleep(0.4)
            if token != "RUNNING":
                return "CANA service start failed."
        if token not in _SCM_STATE_TOKENS:
            return "CANA service state is unknown."
        return "CANA service start failed."
    except Exception as extra:  # noqa: BLE001
        return str(extra)


def request_windows_service_install(
    launcher: Optional[Callable[[str, str], int]] = None,
    is_windows: Optional[bool] = None,
) -> str:
    """Wait for elevated setup and return an empty string only on success."""
    if not (os.name == "nt" if is_windows is None else is_windows):
        return "CANA service installation is only available on Windows."

    if not getattr(sys, "frozen", False):
        return "CANA service setup requires the built CANA-Setup.exe. Run setup first."

    if launcher is None:
        launcher = _run_elevated

    try:
        result = int(launcher(sys.executable, "--install-service"))
    except Exception as extra:  # noqa: BLE001
        return str(extra)
    if result == 0:
        return ""
    return "CANA service installation failed. See C:\\ProgramData\\CANA\\logs\\install.log."


def _run_elevated(executable: str, parameters: str) -> int:
    from win32com.shell import shell, shellcon
    import win32event
    import win32process

    try:
        process = shell.ShellExecuteEx(
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS, lpVerb="runas",
            lpFile=executable, lpParameters=parameters, nShow=0,
        )["hProcess"]
    except Exception as exc:
        if getattr(exc, "winerror", None) == 1223 or (exc.args and exc.args[0] == 1223):
            raise RuntimeError("CANA service setup was cancelled. Approve the Windows prompt to continue.") from exc
        raise
    try:
        if win32event.WaitForSingleObject(process, 120000) != win32event.WAIT_OBJECT_0:
            raise RuntimeError("CANA service setup is taking longer than expected. Check the installation log before retrying.")
        return win32process.GetExitCodeProcess(process)
    finally:
        process.Close()


__all__ = [
    "CAPTURE_LABELS",
    "CONNECTION_LABELS",
    "DISPLAY_MAP",
    "MONITORING_LABELS",
    "SERVICE_LABELS",
    "UNAVAILABLE",
    "UIController",
    "classify_scm_state",
    "display_state_for",
    "header_status",
    "query_windows_service",
    "query_windows_service_state",
    "runtime_states",
    "technical_details",
    "request_windows_service_install",
    "try_start_windows_service",
    "user_facing_error",
]
