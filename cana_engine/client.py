"""
client.py
=========

UI client for the CANA Windows service.

The native UI talks only to the named pipe hosted by the service.
"""

from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from cana_engine.ipc import (
    PIPE_RECONNECT,
    PipeClient,
    PipeProtocolError,
    SERVICE_UNAVAILABLE,
)


class ControlClientError(Exception):
    """Raised when the UI cannot reach or use the local control pipe."""


class ControlClient:
    def __init__(
        self,
        timeout: float = 3.0,
        pipe_client: Optional[PipeClient] = None,
    ) -> None:
        self.timeout = float(timeout)
        self._pipe = pipe_client or PipeClient()
        if hasattr(self._pipe, "timeout"):
            self._pipe.timeout = self.timeout

    @classmethod
    def from_config(cls, pipe_client: Optional[PipeClient] = None) -> "ControlClient":
        return cls(pipe_client=pipe_client)

    def _pipe_request(
        self,
        command: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        box: Dict[str, Any] = {}
        done = threading.Event()
        wait_for = self.timeout if timeout is None else float(timeout)
        if hasattr(self._pipe, "timeout"):
            self._pipe.timeout = wait_for

        def worker() -> None:
            try:
                box["result"] = self._pipe.request(command, payload)
            except Exception as extra:  # noqa: BLE001
                box["error"] = extra
            finally:
                done.set()

        threading.Thread(target=worker, name="CANAPipeClient", daemon=True).start()
        if not done.wait(timeout=wait_for):
            raise ControlClientError(PIPE_RECONNECT)
        extra = box.get("error")
        if extra is not None:
            if isinstance(extra, ControlClientError):
                raise extra
            if isinstance(extra, PipeProtocolError):
                raise ControlClientError(str(extra)) from extra
            raise ControlClientError(PIPE_RECONNECT) from extra
        result = box.get("result")
        if not isinstance(result, dict):
            raise ControlClientError(PIPE_RECONNECT)
        if not result.get("ok", True):
            raise ControlClientError(result.get("error", f"{command} failed"))
        return result

    def status(self) -> Dict[str, Any]:
        return self._pipe_request("status")

    def snapshot(self) -> Dict[str, Any]:
        try:
            return self._pipe_request("snapshot")
        except ControlClientError as exc:
            if str(exc) != 'response too large':
                raise
            payload = self.status()
            payload['history_truncated'] = True
            return payload

    def get_config(self) -> Dict[str, Any]:
        result = self._pipe_request("get_config")
        return result.get("config", result)

    def start_monitoring(self) -> Dict[str, Any]:
        return self._pipe_request("start", timeout=20.0)

    def stop_monitoring(self) -> Dict[str, Any]:
        return self._pipe_request("stop", timeout=20.0)

    def apply_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self._pipe_request("apply_config", {"config": updates})


__all__ = [
    "ControlClient",
    "ControlClientError",
    "PIPE_RECONNECT",
    "SERVICE_UNAVAILABLE",
]
