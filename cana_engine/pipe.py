"""
pipe.py
=======

Privileged local IPC for start/stop/apply_config/status.

The Windows service hosts a named pipe whose DACL allows SYSTEM,
Administrators, and the installing-user SID. Authorization uses the
impersonated TokenUser SID plus Administrators group membership.
The protocol is JSON commands. Linux tests exercise the same handler
through an in-process fake transport.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from cana_engine.config import ALLOWED_CONFIG_KEYS, public_config_dict, save_config
from cana_engine.control import snapshot_payload, status_payload
from cana_engine.engine import CANAEngine
from cana_engine.ipc import (
    PIPE_MAX_MESSAGE_BYTES,
    PIPE_NAME,
    PipeClient,
    PipeProtocolError,
    SID_ADMINS,
    SID_SYSTEM,
    _decode_pipe_body,
    _pipe_client_security_flags,
    _read_pipe_message,
    _overlapped_pipe_io,
    _safe_close_handle,
    _windows_pipe_request,
    encode_pipe_response,
)
from cana_engine.logging_setup import log_lifecycle

PIPE_BUFFER_SIZE = 65536
PIPE_IO_TIMEOUT_MS = 3000
ALLOWED_COMMANDS = {
    "start",
    "stop",
    "apply_config",
    "status",
    "get_config",
    "snapshot",
}
EMPTY_COMMANDS = frozenset({"start", "stop", "status", "get_config", "snapshot"})


def _ok(engine: CANAEngine, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {"ok": True, **status_payload(engine)}
    if extra:
        payload.update(extra)
    return payload


class PipeCommandHandler:
    """Transport-agnostic privileged command handler."""

    def __init__(
        self,
        engine: CANAEngine,
        allowed_sids: Iterable[str],
        *,
        persist: bool = True,
        config_path: Optional[Any] = None,
    ) -> None:
        self.engine = engine
        self.allowed_sids: Set[str] = {sid for sid in allowed_sids if sid}
        self.persist = persist
        self.config_path = config_path

    def authorize(self, caller_sid: str, is_admin: bool = False) -> bool:
        """Allow SYSTEM, the installing user SID, or Administrators members.

        TokenUser is never compared as equal to the Administrators group
        SID. Group membership is checked separately via ``is_admin``.
        """
        if not caller_sid:
            return False
        if caller_sid == SID_ADMINS:
            return False
        if caller_sid == SID_SYSTEM and SID_SYSTEM in self.allowed_sids:
            return True
        if caller_sid in self.allowed_sids and caller_sid != SID_ADMINS:
            return True
        return bool(is_admin and SID_ADMINS in self.allowed_sids)

    def handle(
        self,
        caller_sid: str,
        command: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        is_admin: bool = False,
    ) -> Dict[str, Any]:
        allowed = self.authorize(caller_sid, is_admin=is_admin)
        log_lifecycle(
            "PIPE_AUTH",
            f"sid={caller_sid} admin={is_admin} allowed={allowed} command={command}",
        )
        if not allowed:
            raise PipeProtocolError("forbidden", 403)
        if command not in ALLOWED_COMMANDS:
            raise PipeProtocolError("unknown command", 400)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise PipeProtocolError("JSON object required", 400)
        if command in EMPTY_COMMANDS:
            if payload:
                raise PipeProtocolError("unexpected fields", 400)
            if command == "status":
                return _ok(self.engine)
            if command == "snapshot":
                return _ok(self.engine, extra=snapshot_payload(self.engine))
            if command == "get_config":
                return _ok(
                    self.engine,
                    extra={"config": public_config_dict(self.engine.config)},
                )
            enabled = command == "start"
            return self._set_monitoring(enabled)
        return self._apply_config(payload)

    def _set_monitoring(self, enabled: bool) -> Dict[str, Any]:
        """Persist the flag, then always start/stop the live engine.

        ``replace_config`` skips runtime work when ``monitoring_enabled``
        is unchanged (installer default is already True). Start/Stop
        Monitoring must still drive ``CANAEngine.start()`` / ``stop()``.
        """
        result = self._persist_then_apply({"monitoring_enabled": enabled})
        try:
            if enabled:
                log_lifecycle("PIPE_START_MONITORING")
                self.engine.start()
                deadline = time.time() + 5
                while time.time() < deadline:
                    status = self.engine.status()
                    if (
                        status.running
                        or status.last_error
                        or status.health.capture_error
                    ):
                        break
                    time.sleep(0.05)
            else:
                log_lifecycle("PIPE_STOP_MONITORING")
                self.engine.stop()
        except Exception as extra:  # noqa: BLE001
            raise PipeProtocolError(f"config apply failed: {extra}", 500) from extra
        result.update(_ok(self.engine, extra={"accepted": True}))
        result["config"] = public_config_dict(self.engine.config)
        return result

    def _persist_then_apply(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        try:
            candidate = self.engine.config.with_updates(updates)
        except ValueError as exc:
            raise PipeProtocolError(str(exc), 400) from exc
        persisted = False
        previous = None
        if self.persist:
            try:
                previous = self.engine.config
                save_config(candidate, self.config_path)
                persisted = True
            except Exception as exc:  # noqa: BLE001
                raise PipeProtocolError(
                    f"config persist failed: {exc}", 500
                ) from exc
        try:
            self.engine.replace_config(candidate, wait=True)
        except Exception as exc:
            if persisted and previous is not None:
                try:
                    save_config(previous, self.config_path)
                except Exception as rollback_exc:  # noqa: BLE001
                    log_lifecycle("CONFIG_ROLLBACK_FAILED", str(rollback_exc))
            raise PipeProtocolError(f"config apply failed: {exc}", 500) from exc
        return _ok(
            self.engine,
            extra={
                "accepted": True,
                "config": public_config_dict(self.engine.config),
            },
        )

    def _apply_config(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        extra = set(payload) - {"config"}
        if extra:
            raise PipeProtocolError("unexpected fields", 400)
        if "config" not in payload:
            raise PipeProtocolError("config object required", 400)
        updates = payload["config"]
        if not isinstance(updates, dict):
            raise PipeProtocolError("config object required", 400)
        unknown = set(updates) - ALLOWED_CONFIG_KEYS
        if unknown:
            raise PipeProtocolError(
                f"unsupported keys: {sorted(unknown)}", 400
            )
        result = self._persist_then_apply(updates)
        result["accepted"] = True
        if "automatic_startup" in updates:
            _apply_windows_startup_type(bool(self.engine.config.automatic_startup))
        return result


class InProcessPipeServer:
    """Fake pipe transport for Linux tests and non-Windows runtimes."""

    def __init__(self, handler: PipeCommandHandler) -> None:
        self.handler = handler
        self._lock = threading.Lock()
        self._started = False

    def start(self) -> None:
        self._started = True

    def stop(self) -> None:
        self._started = False

    def join(self, timeout: Optional[float] = None) -> None:
        return

    def request(
        self,
        caller_sid: str,
        command: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        is_admin: bool = False,
    ) -> Dict[str, Any]:
        with self._lock:
            try:
                return self.handler.handle(
                    caller_sid, command, payload, is_admin=is_admin
                )
            except PipeProtocolError as ext:
                return {"ok": False, "error": str(ext), "status": ext.status}


class NamedPipeServer:
    """Windows named-pipe listener with an explicit start/stop/join lifecycle."""

    def __init__(
        self,
        handler: PipeCommandHandler,
        allowed_sids: Iterable[str],
    ) -> None:
        self.handler = handler
        self.allowed_sids = [sid for sid in allowed_sids if sid]
        if SID_SYSTEM not in self.allowed_sids:
            self.allowed_sids.append(SID_SYSTEM)
        if SID_ADMINS not in self.allowed_sids:
            self.allowed_sids.append(SID_ADMINS)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current_handle = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve, name="CANAPipeServer", daemon=True
        )
        self._thread.start()
        log_lifecycle("PIPE_SERVER_STARTED", PIPE_NAME)

    def stop(self) -> None:
        self._stop.set()
        self._wakeup()
        handle = self._current_handle
        if handle is not None:
            try:
                import win32file

                win32file.CloseHandle(handle)
            except Exception:
                pass
            self._current_handle = None
        log_lifecycle("PIPE_SERVER_STOPPING", PIPE_NAME)

    def join(self, timeout: Optional[float] = None) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None
        log_lifecycle("PIPE_SERVER_STOPPED", PIPE_NAME)

    def _wakeup(self) -> None:
        try:
            import win32file

            handle = win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                _pipe_client_security_flags(win32file),
                None,
            )
            win32file.CloseHandle(handle)
        except Exception:
            pass

    def _serve(self) -> None:
        try:
            import pywintypes
            import win32api
            import win32file
            import win32pipe
            import win32security
            import ntsecuritycon as con
        except ImportError:
            log_lifecycle("PIPE_SERVER_SKIPPED", "pywin32 unavailable")
            return

        while not self._stop.is_set():
            handle = None
            try:
                sd = win32security.SECURITY_DESCRIPTOR()
                dacl = win32security.ACL()
                for sid_str in self.allowed_sids:
                    sid = win32security.ConvertStringSidToSid(sid_str)
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                        sid,
                    )
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                sa = win32security.SECURITY_ATTRIBUTES()
                sa.SECURITY_DESCRIPTOR = sd
                handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
                    win32pipe.PIPE_TYPE_MESSAGE
                    | win32pipe.PIPE_READMODE_MESSAGE
                    | win32pipe.PIPE_WAIT
                    | getattr(win32pipe, "PIPE_REJECT_REMOTE_CLIENTS", 0),
                    win32pipe.PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER_SIZE,
                    PIPE_BUFFER_SIZE,
                    PIPE_IO_TIMEOUT_MS,
                    sa,
                )
                self._current_handle = handle
                _overlapped_pipe_io(win32file, pywintypes, handle, 'connect', timeout_ms=PIPE_IO_TIMEOUT_MS)
                if self._stop.is_set():
                    _safe_close_handle(win32file, handle)
                    self._current_handle = None
                    break
                try:
                    raw = _read_pipe_message(win32file, pywintypes, handle, timeout_ms=PIPE_IO_TIMEOUT_MS)
                    body = _decode_pipe_body(raw)
                    if "command" not in body:
                        raise PipeProtocolError("command required", 400)
                    command = str(body.get("command", ""))
                    payload = {k: v for k, v in body.items() if k != "command"}
                    try:
                        caller_sid, is_admin = _windows_connected_client_identity(
                            handle, win32pipe, win32security, win32api, con
                        )
                    except Exception as extra:  # noqa: BLE001
                        winerr = extra.args[0] if getattr(extra, "args", None) else extra
                        log_lifecycle(
                            "PIPE_IMPERSONATION_FAILED",
                            f"command={command} winerr={winerr}",
                        )
                        result = {
                            "ok": False,
                            "error": "could not identify caller",
                            "status": 401,
                        }
                    else:
                        log_lifecycle(
                            "PIPE_IMPERSONATION_OK",
                            f"sid={caller_sid} admin={is_admin} command={command}",
                        )
                        try:
                            result = self.handler.handle(
                                caller_sid, command, payload, is_admin=is_admin
                            )
                        except PipeProtocolError as extra:
                            result = {
                                "ok": False,
                                "error": str(extra),
                                "status": extra.status,
                            }
                except PipeProtocolError as extra:
                    result = {"ok": False, "error": str(extra), "status": extra.status}
                except Exception as extra:  # noqa: BLE001
                    result = {"ok": False, "error": "internal error"}
                    log_lifecycle("PIPE_REQUEST_ERROR", str(extra))
                _safe_write_pipe(win32file, handle, encode_pipe_response(result))
                # A bounded acknowledgement replaces FlushFileBuffers, which can wait forever.
                try:
                    _read_pipe_message(win32file, pywintypes, handle, timeout_ms=PIPE_IO_TIMEOUT_MS)
                except Exception:
                    pass
                _release_pipe_client(win32file, win32pipe, handle)
                self._current_handle = None
            except TimeoutError:
                _release_pipe_client(win32file, win32pipe, handle)
                self._current_handle = None
            except pywintypes.error as extra:
                if handle is not None:
                    _release_pipe_client(win32file, win32pipe, handle)
                    self._current_handle = None
                if self._stop.is_set():
                    break
                log_lifecycle("PIPE_SERVER_ERROR", str(extra))
            except Exception as extra:  # noqa: BLE001
                if handle is not None:
                    _release_pipe_client(win32file, win32pipe, handle)
                    self._current_handle = None
                if self._stop.is_set():
                    break
                log_lifecycle("PIPE_SERVER_ERROR", str(extra))


def _safe_write_pipe(win32file, handle, payload: bytes) -> None:
    try:
        import pywintypes
        _overlapped_pipe_io(win32file, pywintypes, handle, 'write', payload, PIPE_IO_TIMEOUT_MS)
    except Exception:
        pass


def _impersonate_named_pipe_client(handle, win32security, win32pipe) -> None:
    """Impersonate the connected pipe client using the correct pywin32 module.

    Current pywin32 exposes ``ImpersonateNamedPipeClient`` on
    ``win32security``. Older builds kept a copy on ``win32pipe``. Prefer
    security, then fall back, so SID extraction keeps working.
    """
    impersonate = getattr(win32security, "ImpersonateNamedPipeClient", None)
    if callable(impersonate):
        impersonate(handle)
        return
    impersonate = getattr(win32pipe, "ImpersonateNamedPipeClient", None)
    if callable(impersonate):
        impersonate(handle)
        return
    raise AttributeError("ImpersonateNamedPipeClient is unavailable")


def _release_pipe_client(win32file, win32pipe, handle) -> None:
    """Disconnect without an unbounded wait for a client to drain its buffers."""
    if handle is None:
        return
    try:
        win32pipe.DisconnectNamedPipe(handle)
    except Exception:
        pass
    _safe_close_handle(win32file, handle)


SE_GROUP_ENABLED = 0x00000004


def _group_entry_enabled(entry: Any, win32security) -> bool:
    attributes = 0
    if isinstance(entry, (tuple, list)) and len(entry) > 1:
        try:
            attributes = int(entry[1])
        except (TypeError, ValueError):
            attributes = 0
    else:
        attributes = int(getattr(entry, "Attributes", 0) or 0)
    enabled_flag = int(getattr(win32security, "SE_GROUP_ENABLED", SE_GROUP_ENABLED))
    return bool(attributes & enabled_flag)


def _token_is_admin(win32security, token) -> bool:
    """True when the impersonated token is an enabled Administrators member."""
    try:
        admin_sid = win32security.ConvertStringSidToSid(SID_ADMINS)
        if bool(win32security.CheckTokenMembership(token, admin_sid)):
            return True
    except Exception:
        pass
    try:
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
    except Exception:
        return False
    for entry in groups or ():
        try:
            sid = entry[0] if isinstance(entry, (tuple, list)) else getattr(entry, "Sid", entry)
            if win32security.ConvertSidToStringSid(sid) != SID_ADMINS:
                continue
            if _group_entry_enabled(entry, win32security):
                return True
        except Exception:
            continue
    return False


def _windows_connected_client_identity(
    handle, win32pipe, win32security, win32api, con
) -> Tuple[str, bool]:
    """
    Return the connected caller's user SID and Administrators membership.

    Must not use the service process token. The caller message is
    read first; then impersonate the client, read TokenUser plus
    group membership, then RevertToSelf before handling the command.
    TokenUser is never S-1-5-32-544.
    """
    try:
        _impersonate_named_pipe_client(handle, win32security, win32pipe)
        log_lifecycle("PIPE_IMPERSONATE")
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(),
            con.TOKEN_QUERY,
            False,
        )
        log_lifecycle("PIPE_OPEN_THREAD_TOKEN_OK")
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        caller_sid = win32security.ConvertSidToStringSid(sid)
        is_admin = _token_is_admin(win32security, token)
        log_lifecycle("PIPE_TOKEN_USER", f"sid={caller_sid} admin={is_admin}")
        return caller_sid, is_admin
    except Exception as extra:
        winerr = extra.args[0] if getattr(extra, "args", None) else extra
        log_lifecycle("PIPE_OPEN_THREAD_TOKEN_FAILED", f"winerr={winerr}")
        raise
    finally:
        win32security.RevertToSelf()


def _windows_connected_client_sid(handle, win32pipe, win32security, win32api, con) -> str:
    """Compatibility wrapper used by existing impersonation tests."""
    sid, _is_admin = _windows_connected_client_identity(
        handle, win32pipe, win32security, win32api, con
    )
    return sid


def _apply_windows_startup_type(automatic: bool) -> None:
    """Best-effort SCM start-type update for Settings automatic startup."""
    if os.name != "nt":
        return
    start_type = "auto" if automatic else "demand"
    try:
        import subprocess

        from cana_service.constants import SERVICE_NAME

        subprocess.run(
            ["sc.exe", "config", SERVICE_NAME, "start=", start_type],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        log_lifecycle("SERVICE_START_TYPE_UPDATED", start_type)
    except Exception as extra:  # noqa: BLE001
        log_lifecycle("SERVICE_START_TYPE_UPDATE_FAILED", str(extra))


def run_pipe_server(
    handler: PipeCommandHandler,
    *,
    allowed_sids: Iterable[str],
):
    """Start the privileged IPC listener.

    Windows always uses the real named pipe. Non-Windows tests use the
    in-process fake transport.
    """
    if os.name == "nt":
        server = NamedPipeServer(handler, allowed_sids)
        server.start()
        return server
    server = InProcessPipeServer(handler)
    server.start()
    log_lifecycle("PIPE_SERVER_SKIPPED", "non-Windows in-process transport")
    return server


__all__ = [
    "ALLOWED_COMMANDS",
    "InProcessPipeServer",
    "NamedPipeServer",
    "PIPE_NAME",
    "PIPE_MAX_MESSAGE_BYTES",
    "PipeClient",
    "PipeCommandHandler",
    "PipeProtocolError",
    "SID_ADMINS",
    "SID_SYSTEM",
    "encode_pipe_response",
    "run_pipe_server",
]
