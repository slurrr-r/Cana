"""
install.py
==========

Register, configure, start, and unregister the CANA Windows service.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from cana_engine.config import (
    CANAConfig,
    load_config,
    prepare_runtime_config,
    save_config,
    save_installer_user_sid,
    validate_installer_user_sid,
)
from cana_engine.logging_setup import configure_service_logging, log_lifecycle
from cana_service.constants import (
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
    SERVICE_RECOVERY_DELAY_MS,
    SERVICE_RESTART_RESET_SECONDS,
)


def _python_executable() -> str:
    return sys.executable


def install_packaged_service() -> int:
    """Use the same installer and ACLs as Windows Setup."""
    if not getattr(sys, "frozen", False):
        raise RuntimeError("Build CANA-Setup.exe and run setup to install the Windows service.")
    script = Path(sys._MEIPASS) / "packaging" / "install.ps1"
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    return subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(script), "-InstallDir", str(Path(sys.executable).parent)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW, check=False,
    ).returncode


def _is_windows() -> bool:
    return os.name == "nt"


def _service_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    module = Path(__file__).resolve().parent / "service.py"
    return f'"{_python_executable()}" "{module}"'


def _sc(*args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["sc.exe", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as extra:
        return subprocess.CompletedProcess(
            extra.cmd,
            1,
            stdout=extra.stdout or "",
            stderr=extra.stderr or f"{args[0] if args else 'sc'} timed out",
        )


def _scm_error_detail(result: subprocess.CompletedProcess, action: str) -> str:
    return (result.stderr or result.stdout or f"{action} failed").strip()


def _fail_scm(action: str, result: subprocess.CompletedProcess, event: str) -> int:
    detail = _scm_error_detail(result, action)
    print(detail)
    log_lifecycle(event, f"{action}: {detail}")
    return result.returncode or 1


def _ensure_directories(config: CANAConfig) -> None:
    config.resolved_database_path().parent.mkdir(parents=True, exist_ok=True)
    config.resolved_sessions_dir().mkdir(parents=True, exist_ok=True)
    config.resolved_logs_dir().mkdir(parents=True, exist_ok=True)


def _sid_from_token(token) -> str:
    import win32security

    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


def _current_windows_sid() -> str:
    try:
        import win32api
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY
        )
        return _sid_from_token(token)
    except Exception:
        return ""


def _explorer_owner_sid() -> str:
    """Logged-on interactive user via explorer.exe in this session."""
    try:
        import psutil
        import win32api
        import win32ts
        import win32con
        import win32security

        session = win32ts.ProcessIdToSessionId(win32api.GetCurrentProcessId())
        for proc in psutil.process_iter(["name", "pid"]):
            if (proc.info.get("name") or "").lower() != "explorer.exe":
                continue
            try:
                if win32ts.ProcessIdToSessionId(proc.pid) != session:
                    continue
                handle = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, proc.pid
                )
                try:
                    token = win32security.OpenProcessToken(
                        handle, win32security.TOKEN_QUERY
                    )
                    try:
                        sid = _sid_from_token(token)
                    finally:
                        token.Close()
                finally:
                    handle.Close()
                if sid.startswith("S-1-"):
                    return sid
            except Exception:
                continue
    except Exception:
        pass
    return ""


def _unelevated_windows_sid() -> str:
    """
    SID of the logged-on interactive user, not a different elevated admin.

    Prefers explorer.exe in the current session so a UAC "run as other
    admin" install still DACLs the pipe to the user at the console.
    Never falls back to the elevated token.
    """
    return _explorer_owner_sid()


def record_installer_user_sid(sid: str = "") -> str:
    """Persist the installing-user SID used for named-pipe DACL."""
    try:
        resolved = validate_installer_user_sid(sid or _unelevated_windows_sid())
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    save_installer_user_sid(resolved)
    return resolved


def configure_recovery() -> subprocess.CompletedProcess:
    """Restart on failure with a delay; do not spin forever."""
    delay = str(SERVICE_RECOVERY_DELAY_MS)
    result = _sc(
        "failure",
        SERVICE_NAME,
        "reset=",
        str(SERVICE_RESTART_RESET_SECONDS),
        "actions=",
        f"restart/{delay}/restart/{delay}/restart/{delay}",
    )
    if result.returncode != 0:
        return result
    return _sc("failureflag", SERVICE_NAME, "1")


def install_service(config: Optional[CANAConfig] = None) -> int:
    """Register CANA as an Automatic Windows service and start it."""
    if not _is_windows():
        print("Windows service installation is only available on Windows.")
        return 1
    config = prepare_runtime_config(
        config if config is not None else load_config()
    )
    _ensure_directories(config)
    try:
        record_installer_user_sid()
    except RuntimeError as exc:
        print(str(exc))
        log_lifecycle("SERVICE_INSTALL_FAILURE", str(exc))
        return 1
    save_config(config)
    configure_service_logging(config.resolved_logs_dir(), config.logging_level)
    bin_path = _service_command()
    start_type = "auto" if config.automatic_startup else "demand"
    result = _sc(
        "create",
        SERVICE_NAME,
        "binPath=",
        bin_path,
        "start=",
        start_type,
        "DisplayName=",
        SERVICE_DISPLAY_NAME,
        "obj=",
        "LocalSystem",
    )
    if result.returncode not in (0, 1073):
        return _fail_scm("sc create", result, "SERVICE_INSTALL_FAILURE")
    described = _sc("description", SERVICE_NAME, SERVICE_DESCRIPTION)
    if described.returncode != 0:
        return _fail_scm("sc description", described, "SERVICE_INSTALL_FAILURE")
    configured = _sc("config", SERVICE_NAME, "binPath=", bin_path, "start=", start_type)
    if configured.returncode != 0:
        return _fail_scm("sc config", configured, "SERVICE_INSTALL_FAILURE")
    recovery = configure_recovery()
    if recovery.returncode != 0:
        cmd = [str(part) for part in (getattr(recovery, "args", None) or ())]
        action = "sc failureflag" if "failureflag" in cmd else "sc failure"
        return _fail_scm(action, recovery, "SERVICE_INSTALL_FAILURE")
    start = _sc("start", SERVICE_NAME)
    start_text = f"{start.stdout or ''}{start.stderr or ''}"
    if start.returncode not in (0, 1056) and "1056" not in start_text:
        return _fail_scm("sc start", start, "SERVICE_INSTALL_FAILURE")
    log_lifecycle(
        "SERVICE_INSTALLED",
        f"start={start.returncode} type={start_type}",
    )
    print(f"Installed Windows service '{SERVICE_DISPLAY_NAME}' ({SERVICE_NAME}).")
    return 0


def uninstall_service(keep_data: bool = True) -> int:
    """Stop and unregister the CANA service. Data is kept by default."""
    if not _is_windows():
        print("Windows service uninstallation is only available on Windows.")
        return 1
    stopped = _sc("stop", SERVICE_NAME)
    if stopped.returncode not in (0, 1060, 1062):
        return _fail_scm("sc stop", stopped, "SERVICE_UNINSTALL_FAILURE")
    result = _sc("delete", SERVICE_NAME)
    if result.returncode not in (0, 1060):
        return _fail_scm("sc delete", result, "SERVICE_UNINSTALL_FAILURE")
    log_lifecycle("SERVICE_UNINSTALLED", result.stdout or result.stderr)
    print(f"Removed Windows service '{SERVICE_NAME}'.")
    if keep_data:
        print("User data (database, sessions, logs) was preserved.")
    return 0


def service_exists() -> bool:
    result = _sc("query", SERVICE_NAME)
    return result.returncode == 0
