"""
ipc.py
======

UI-safe named-pipe client for ``\\\\.\\pipe\\CANAControl``.

This module must not import the engine, capture, risk scoring, or
anomaly loggers. The Windows service hosts the pipe; the UI only
connects as a client.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, Optional

PIPE_NAME = r"\\.\pipe\CANAControl"
SID_SYSTEM = "S-1-5-18"
SID_ADMINS = "S-1-5-32-544"
PIPE_MAX_MESSAGE_BYTES = 65536
PIPE_BUSY = 231
PIPE_NO_DATA = 232
PIPE_NOT_CONNECTED = 233
BROKEN_PIPE = 109
SEM_TIMEOUT = 121
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
SERVICE_UNAVAILABLE = (
    "CANA service is not running. Start the CANA Windows "
    "service, then open the UI again."
)
PIPE_RECONNECT = (
    "CANA service connection was temporarily unavailable. Reconnecting..."
)
PIPE_PERMISSION = "CANA doesn't have permission to perform this action."


class PipeProtocolError(Exception):
    """Rejected pipe command. Never mutates engine or config."""

    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


class PipeClient:
    """UI client for privileged commands. Named pipe on Windows, injected transport in tests."""

    def __init__(
        self,
        transport: Optional[Callable[[str, Optional[Dict[str, Any]]], Dict[str, Any]]] = None,
        caller_sid: str = "",
    ) -> None:
        self._transport = transport
        self.caller_sid = caller_sid
        self.timeout = 3.0

    def request(
        self, command: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if self._transport is not None:
            return self._transport(command, payload)
        return _windows_pipe_request(command, payload, timeout=self.timeout)

    def start_monitoring(self) -> Dict[str, Any]:
        return self.request("start")

    def stop_monitoring(self) -> Dict[str, Any]:
        return self.request("stop")

    def apply_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("apply_config", {"config": updates})

    def status(self) -> Dict[str, Any]:
        return self.request("status")

    def get_config(self) -> Dict[str, Any]:
        return self.request("get_config")

    def snapshot(self) -> Dict[str, Any]:
        return self.request("snapshot")


def _pipe_client_security_flags(win32file) -> int:
    """``CreateFile`` flags that let the service impersonate the caller.

    Win32 defaults a named-pipe client's impersonation level to
    ``SecurityAnonymous`` when no SQOS flags are supplied. The service
    then cannot read the caller's token and ``ImpersonateNamedPipeClient``
    fails. Request impersonation explicitly so SID checks can run.
    """
    present = int(getattr(win32file, "SECURITY_SQOS_PRESENT", 0x00100000))
    impersonation = int(getattr(win32file, "SECURITY_IMPERSONATION", 0x00020000))
    return present | impersonation


def _safe_close_handle(win32file, handle) -> None:
    if handle is None:
        return
    try:
        win32file.CloseHandle(handle)
    except Exception:
        pass


def _overlapped_pipe_io(win32file, pywintypes, handle, operation, payload=None, timeout_ms=3000):
    """Keep buffers alive until completion or cancellation of a bounded pipe operation."""
    import win32event
    import win32pipe

    overlapped = pywintypes.OVERLAPPED()
    overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
    buffer = win32file.AllocateReadBuffer(PIPE_MAX_MESSAGE_BYTES) if operation == 'read' else payload
    pending = False
    try:
        try:
            if operation == 'read':
                code, _ = win32file.ReadFile(handle, buffer, overlapped)
            elif operation == 'write':
                code, _ = win32file.WriteFile(handle, buffer, overlapped)
            else:
                code = win32pipe.ConnectNamedPipe(handle, overlapped)
                if code == 535:
                    return None
            pending = code == 997
        except pywintypes.error as exc:
            code = windows_error_code(exc)
            if operation == 'connect' and code == 535:
                return None
            if code != 997:
                raise
            pending = True
        if pending and win32event.WaitForSingleObject(overlapped.hEvent, timeout_ms) != 0:
            raise TimeoutError(f'Named pipe {operation} timed out')
        count = win32file.GetOverlappedResult(handle, overlapped, False)
        pending = False
        return bytes(buffer[:count]) if operation == 'read' else None
    finally:
        if pending:
            try:
                # This thread issued the operation; CancelIo is available across pywin32 builds.
                win32file.CancelIo(handle)
            except pywintypes.error:
                pass
            finally:
                try:
                    win32file.GetOverlappedResult(handle, overlapped, True)
                except pywintypes.error:
                    pass
        win32file.CloseHandle(overlapped.hEvent)


def _read_pipe_message(win32file, pywintypes, handle, *, timeout_ms=None) -> bytes:
    """Read one message-mode pipe payload. Reject oversized/incomplete data."""
    more_data = getattr(win32file, "ERROR_MORE_DATA", 234)
    try:
        if timeout_ms is None:
            _code, raw = win32file.ReadFile(handle, PIPE_MAX_MESSAGE_BYTES)
        else:
            raw = _overlapped_pipe_io(win32file, pywintypes, handle, 'read', timeout_ms=timeout_ms)
    except pywintypes.error as extra:
        winerr = extra.args[0] if extra.args else None
        if winerr == more_data:
            raise PipeProtocolError("message too large", 413) from extra
        raise
    if not isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw)
    if len(raw) > PIPE_MAX_MESSAGE_BYTES:
        raise PipeProtocolError("message too large", 413)
    return bytes(raw)


def _decode_pipe_body(raw: bytes) -> Dict[str, Any]:
    """Parse one JSON pipe request. Reject oversized or non-object bodies."""
    if len(raw) > PIPE_MAX_MESSAGE_BYTES:
        raise PipeProtocolError("message too large", 413)
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as extra:
        raise PipeProtocolError("invalid JSON", 400) from extra
    if not isinstance(body, dict):
        raise PipeProtocolError("JSON object required", 400)
    return body


def windows_error_code(extra: Exception) -> Optional[int]:
    """Extract a Win32 error code from pywintypes.error / OSError."""
    args = getattr(extra, "args", ())
    if args and isinstance(args[0], int):
        return int(args[0])
    winerror = getattr(extra, "winerror", None)
    if isinstance(winerror, int):
        return winerror
    errno = getattr(extra, "errno", None)
    if isinstance(errno, int):
        return errno
    return None


def classify_pipe_io_error(extra: Exception) -> PipeProtocolError:
    """Map client pipe I/O failures without calling them authorization errors."""
    code = windows_error_code(extra)
    if code == ERROR_ACCESS_DENIED:
        return PipeProtocolError(PIPE_PERMISSION, 403)
    if code in {PIPE_BUSY, PIPE_NO_DATA, PIPE_NOT_CONNECTED, BROKEN_PIPE, SEM_TIMEOUT}:
        return PipeProtocolError(PIPE_RECONNECT, 503)
    if code == ERROR_FILE_NOT_FOUND:
        return PipeProtocolError(SERVICE_UNAVAILABLE, 503)
    if isinstance(extra, (BrokenPipeError, TimeoutError, ConnectionError, ConnectionResetError)):
        return PipeProtocolError(PIPE_RECONNECT, 503)
    name = type(extra).__name__.lower()
    if "brokenpipe" in name or "timeout" in name or "busy" in name:
        return PipeProtocolError(PIPE_RECONNECT, 503)
    return PipeProtocolError(SERVICE_UNAVAILABLE, 503)


def encode_pipe_response(payload: Dict[str, Any]) -> bytes:
    """Serialize a pipe response and cap it to PIPE_MAX_MESSAGE_BYTES."""
    raw = json.dumps(payload, default=str).encode("utf-8")
    if len(raw) <= PIPE_MAX_MESSAGE_BYTES:
        return raw
    # Keep live health available as the snapshot's recent-history lists grow.
    if 'health' in payload:
        bounded = dict(payload)
        bounded['history_truncated'] = True
        while len(raw) > PIPE_MAX_MESSAGE_BYTES:
            lists = [key for key in ('alerts', 'correlated', 'risk') if bounded.get(key)]
            if not lists:
                break
            key = max(lists, key=lambda key: len(json.dumps(bounded[key], default=str)))
            bounded[key] = bounded[key][:len(bounded[key]) // 2]
            raw = json.dumps(bounded, default=str).encode('utf-8')
        if len(raw) <= PIPE_MAX_MESSAGE_BYTES:
            return raw
    fallback = json.dumps(
        {"ok": False, "error": "response too large", "status": 413}
    ).encode("utf-8")
    return fallback


def _windows_pipe_request(
    command: str,
    payload: Optional[Dict[str, Any]],
    timeout: float = 3.0,
) -> Dict[str, Any]:
    if os.name != "nt":
        raise PipeProtocolError(
            "CANA service is not running. Start the CANA Windows "
            "service, then retry from the UI."
        )
    try:
        import pywintypes
        import win32file
        import win32pipe
    except ImportError as exc:
        raise PipeProtocolError(
            "CANA service named pipe is unavailable. Start the CANA "
            "Windows service, then retry Start/Stop from the tray."
        ) from exc
    handle = None
    try:
        deadline = time.time() + max(float(timeout), 0.1)
        last_error: Optional[Exception] = None
        while True:
            try:
                win32pipe.WaitNamedPipe(
                    PIPE_NAME, int(max(deadline - time.time(), 0.05) * 1000)
                )
            except Exception:
                pass
            try:
                handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    _pipe_client_security_flags(win32file),
                    None,
                )
                last_error = None
                break
            except Exception as extra:
                last_error = extra
                code = windows_error_code(extra)
                # The server recreates its pipe between requests.
                if code in {PIPE_BUSY, ERROR_FILE_NOT_FOUND} and time.time() < deadline:
                    time.sleep(0.05)
                    continue
                raise classify_pipe_io_error(extra) from extra
        if handle is None and last_error is not None:
            raise classify_pipe_io_error(last_error) from last_error
        try:
            win32pipe.SetNamedPipeHandleState(
                handle, win32pipe.PIPE_READMODE_MESSAGE, None, None
            )
        except Exception:
            pass
        message = json.dumps({"command": command, **(payload or {})}).encode("utf-8")
        if len(message) > PIPE_MAX_MESSAGE_BYTES:
            raise PipeProtocolError("message too large", 413)
        win32file.WriteFile(handle, message)
        raw = _read_pipe_message(win32file, pywintypes, handle)
        # The server can disconnect safely once the complete response was consumed.
        win32file.WriteFile(handle, b'\x06')
        return _decode_pipe_body(raw)
    except PipeProtocolError:
        raise
    except Exception as extra:
        raise classify_pipe_io_error(extra) from extra
    finally:
        _safe_close_handle(win32file, handle)


__all__ = [
    "PIPE_NAME",
    "PIPE_MAX_MESSAGE_BYTES",
    "PIPE_PERMISSION",
    "PIPE_RECONNECT",
    "PipeClient",
    "PipeProtocolError",
    "SERVICE_UNAVAILABLE",
    "SID_ADMINS",
    "SID_SYSTEM",
    "classify_pipe_io_error",
    "encode_pipe_response",
    "windows_error_code",
]
