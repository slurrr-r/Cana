"""
service.py
==========

Windows Service entry point for CANA.

Uses pywin32 when available. On non-Windows platforms the same module
still exposes ``run_foreground()`` so tests and Linux development can
exercise start/stop without pywin32.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import TYPE_CHECKING, Optional

from cana_service.constants import (
    SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
    SERVICE_NAME,
)

if TYPE_CHECKING:
    from cana_engine.config import CANAConfig


def _try_import_win32():
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
    except ImportError:
        return None
    return {
        "servicemanager": servicemanager,
        "win32event": win32event,
        "win32service": win32service,
        "win32serviceutil": win32serviceutil,
    }


_win32 = _try_import_win32()
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063


class NotStartedBySCM(Exception):
    """Raised when StartServiceCtrlDispatcher is used outside SCM."""


class CANAServiceRuntime:
    """
    Platform-neutral service runtime used by both the Windows service
    class and tests.
    """

    def __init__(self, config: Optional["CANAConfig"] = None) -> None:
        from cana_engine.config import load_config, prepare_runtime_config

        self.config = prepare_runtime_config(
            config if config is not None else load_config()
        )
        # Engine is constructed in start() so SCM can be told RUNNING
        # before scapy/Npcap imports run.
        self.engine = None
        self.pipe_server = None
        self.pipe_handler = None
        self._stopped = threading.Event()
        self._stop_lock = threading.Lock()
        self._stop_started = False

    def start(self) -> None:
        from cana_engine.logging_setup import configure_service_logging, log_lifecycle

        configure_service_logging(
            self.config.resolved_logs_dir(), self.config.logging_level
        )
        log_lifecycle("SERVICE_STARTED")
        if self.engine is None:
            from cana_engine.engine import CANAEngine

            self.engine = CANAEngine(self.config, print_alerts=False, track_user_activity=False)
        self._start_pipe()
        self._start_engine()

    def _start_pipe(self) -> None:
        from cana_engine.config import default_config_path, load_installer_user_sid, uses_program_data
        from cana_engine.logging_setup import log_lifecycle
        from cana_engine.pipe import (
            PipeCommandHandler,
            SID_ADMINS,
            SID_SYSTEM,
            run_pipe_server,
        )

        try:
            allowed = {SID_SYSTEM, SID_ADMINS}
            installer_sid = load_installer_user_sid()
            if installer_sid:
                allowed.add(installer_sid)
            persist = uses_program_data()
            self.pipe_handler = PipeCommandHandler(
                self.engine,
                allowed,
                persist=persist,
                config_path=default_config_path() if persist else None,
            )
            self.pipe_server = run_pipe_server(
                self.pipe_handler, allowed_sids=allowed
            )
        except Exception as exc:  # noqa: BLE001
            from cana_engine.logging_setup import log_lifecycle

            log_lifecycle("PIPE_SERVER_START_FAILURE", str(exc))
            self.pipe_server = None
            self.pipe_handler = None

    def _start_engine(self) -> None:
        from cana_engine.logging_setup import log_lifecycle

        try:
            if self.config.monitoring_enabled:
                self.engine.start()
            else:
                log_lifecycle("SERVICE_MONITORING_DISABLED")
        except Exception as extra:  # noqa: BLE001
            log_lifecycle("ENGINE_START_FAILURE", str(extra))

    def stop(self) -> None:
        from cana_engine.logging_setup import log_lifecycle

        with self._stop_lock:
            if self._stop_started:
                return
            self._stop_started = True
        log_lifecycle("SERVICE_STOPPING")
        if self.engine is not None:
            self.engine.stop()
        if self.pipe_server is not None:
            try:
                self.pipe_server.stop()
                self.pipe_server.join(timeout=5)
            except Exception as exc:  # noqa: BLE001
                log_lifecycle("PIPE_SERVER_STOP_ERROR", str(exc))
            self.pipe_server = None
        self.pipe_handler = None
        self._stopped.set()
        log_lifecycle("SERVICE_STOPPED")

    def wait(self) -> None:
        while not self._stopped.is_set():
            time.sleep(0.5)
            if self.engine is None:
                continue
            if not self.engine.status().running and self.config.monitoring_enabled:
                # Engine died while the service process is still alive.
                # Watchdog inside the engine handles recovery; we only log.
                health = self.engine.health()
                if health.last_error:
                    from cana_engine.logging_setup import log_lifecycle

                    log_lifecycle("ENGINE_NOT_RUNNING", health.last_error)


def run_foreground(config: Optional["CANAConfig"] = None) -> int:
    """Run the service runtime until interrupted. Used by CLI --service."""
    runtime = CANAServiceRuntime(config)
    runtime.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


def os_is_windows() -> bool:
    return sys.platform == "win32"


def launched_by_service_control_manager(argv: Optional[list] = None) -> bool:
    """
    True when this process looks like an SCM/service launch.

    Installed binPath is the frozen exe with no extra args, or
    ``python cana_service/service.py``. ``--service`` is developer
    foreground debug only and must not enter SCM dispatch.
    """
    if not os_is_windows():
        return False
    args = list(sys.argv[1:] if argv is None else argv)
    return args == []


def run_as_windows_service() -> int:
    """Enter the pywin32 Service Control Manager dispatch loop."""
    if _win32 is None:
        print("pywin32 is required to run CANA as a Windows service.")
        return 1
    servicemanager = _win32["servicemanager"]
    try:
        servicemanager.Initialize(SERVICE_NAME, None)
        servicemanager.PrepareToHostSingle(CANAWindowsService)
        servicemanager.StartServiceCtrlDispatcher()
    except NotStartedBySCM:
        raise
    except Exception as exc:  # noqa: BLE001
        winerror = getattr(exc, "winerror", None)
        if winerror is None:
            args = getattr(exc, "args", ())
            if args and isinstance(args[0], int):
                winerror = args[0]
        if winerror == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            raise NotStartedBySCM() from exc
        raise
    return 0


def run_service_entry(config: Optional["CANAConfig"] = None) -> int:
    """
    Developer/debug foreground runtime used by ``python main.py --service``.

    Installed SCM launches ``CANA.exe`` with no extra args so
    ``handle_service_cli`` reaches ``StartServiceCtrlDispatcher``.
    """
    return run_foreground(config)


if _win32 is not None:
    win32serviceutil = _win32["win32serviceutil"]
    win32service = _win32["win32service"]
    win32event = _win32["win32event"]
    servicemanager = _win32["servicemanager"]

    class CANAWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.runtime: Optional[CANAServiceRuntime] = None

        def SvcStop(self):  # noqa: N802
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            from cana_engine.logging_setup import log_lifecycle

            log_lifecycle("SERVICE_STOP_EVENT")
            win32event.SetEvent(self.stop_event)

        def SvcShutdown(self):  # noqa: N802
            self.SvcStop()

        def SvcDoRun(self):  # noqa: N802
            # Handshake first. SCM error 1053 is a timeout waiting for
            # SERVICE_RUNNING; engine/Npcap/scapy init must not block it.
            self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            self.runtime = CANAServiceRuntime()
            try:
                self.runtime.start()
            except Exception as extra:  # noqa: BLE001
                from cana_engine.logging_setup import log_lifecycle

                log_lifecycle("SERVICE_START_FAILURE", str(extra))
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.runtime is not None:
                self.runtime.stop()
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, ""),
            )
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)

else:
    class CANAWindowsService:  # type: ignore[no-redef]
        """Placeholder when pywin32 is not installed."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME


def handle_service_cli(argv: Optional[list] = None) -> int:
    """Dispatch ``cana-service`` commands (install/start/stop/remove)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if launched_by_service_control_manager(args):
        return run_as_windows_service()
    if not args or args[0] in {"run", "foreground", "--service"}:
        return run_foreground()
    if args[0] == "install":
        from cana_service.install import install_service

        return install_service()
    if args[0] == "uninstall":
        from cana_service.install import uninstall_service

        return uninstall_service()
    if _win32 is None:
        print("pywin32 is required for Windows service management.")
        return 1
    win32serviceutil.HandleCommandLine(CANAWindowsService, argv=["cana-service", *args])
    return 0


if __name__ == "__main__":
    sys.exit(handle_service_cli())
