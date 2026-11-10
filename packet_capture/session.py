"""
session.py
==========

Capture session metadata management.

Tracks metadata about a single capture run - session ID, timing,
selected interface/filter, packet totals, the full captured packet
data, and a chronological log of the actions performed during the
session - and persists all of it as a single JSON file under
``sessions/`` when the session ends.

Note: this supersedes an earlier, narrower version of this module that
intentionally excluded packet data from the session file. Per updated
requirements, the session file is now the single source of truth for
"what happened in this run," including the packets themselves.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from packet_capture.config import (
    SESSION_FILE_PREFIX,
    SESSION_MAX_STORED_PACKETS,
    SESSIONS_DIR,
    ensure_runtime_directories,
)
from packet_capture.logger import get_logger, log_module_event

logger = get_logger(__name__)


class SessionError(Exception):
    """Raised when session metadata cannot be created or saved."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class SessionInfo:
    """
    Full record of a single capture session.

    Attributes:
        session_id: Unique identifier for this session.
        start_time: ISO-8601 UTC timestamp when the session started.
        end_time: ISO-8601 UTC timestamp when the session ended, or
            ``None`` while still running.
        interface_display_name: Human-friendly interface name used.
        applied_filter: The packet filter selected for this session.
        total_packets: Total packets captured during this session.
        actions: Chronological, human-readable log of significant
            actions performed during this session (e.g. "Interface
            selected: Ethernet 3", "Capture started", "Application
            mapping performed: 42 mapped, 3 unknown"). Each entry is
            prefixed with its own UTC timestamp.
        packets: The full list of captured/classified (and, once
            Module 2 has run, application-mapped) packet dictionaries
            for this session.
    """

    session_id: str
    start_time: str
    end_time: Optional[str] = None
    interface_display_name: str = ""
    applied_filter: str = "ALL"
    total_packets: int = 0
    actions: List[str] = field(default_factory=list)
    packets: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation, suitable for JSON export."""
        return asdict(self)


class SessionManager:
    """
    Creates, updates, and persists a :class:`SessionInfo` for a single
    capture run, including the full packet data and an action log.
    """

    def __init__(self) -> None:
        self._session: Optional[SessionInfo] = None

    def start_session(
        self, interface_display_name: str, applied_filter: str
    ) -> SessionInfo:
        """
        Begin a new capture session.

        Args:
            interface_display_name: Friendly name of the selected
                interface.
            applied_filter: The packet filter chosen for this session.

        Returns:
            The newly created :class:`SessionInfo`.
        """
        session = SessionInfo(
            session_id=str(uuid.uuid4()),
            start_time=_utc_now_iso(),
            interface_display_name=interface_display_name,
            applied_filter=applied_filter,
        )
        self._session = session
        log_module_event(
            logger, "SESSION_STARTED", detail=f"session_id={session.session_id}"
        )
        self.add_action(
            f"Session started - interface '{interface_display_name}', "
            f"filter '{applied_filter}'"
        )
        return session

    def add_action(self, action: str) -> None:
        """
        Append a timestamped entry to this session's action log.

        Args:
            action: Human-readable description of what happened (e.g.
                "Capture started", "Packets captured: 214",
                "Application mapping performed: 200 mapped, 14 unknown").

        Raises:
            SessionError: If no session has been started.
        """
        if self._session is None:
            raise SessionError("Cannot log an action before starting a session.")
        self._session.actions.append(f"[{_utc_now_iso()}] {action}")

    def attach_packets(self, packets: List[Dict[str, Any]]) -> None:
        """
        Attach the full list of packet dictionaries to this session.

        Can be called more than once (e.g. once after Module 1's
        capture completes, and again after Module 2's application
        mapping enriches the same packets) - each call replaces the
        previously attached packet list with the latest version.

        If ``packets`` exceeds ``SESSION_MAX_STORED_PACKETS``, only
        the first that many are actually written into the stored
        ``packets`` list (keeping the on-disk JSON file a reasonable
        size for a high-volume capture), but ``total_packets`` always
        reflects the true, untruncated count - the truncation is
        logged as an explicit action, never silent.

        Args:
            packets: The packet dictionaries to store with this
                session.

        Raises:
            SessionError: If no session has been started.
        """
        if self._session is None:
            raise SessionError("Cannot attach packets before starting a session.")

        true_total = len(packets)
        if true_total > SESSION_MAX_STORED_PACKETS:
            self._session.packets = packets[:SESSION_MAX_STORED_PACKETS]
            self.add_action(
                f"Session packet list truncated for storage: "
                f"{true_total} captured, only the first "
                f"{SESSION_MAX_STORED_PACKETS} were written to the JSON "
                f"file (total_packets below reflects the true count)."
            )
        else:
            self._session.packets = packets

        self._session.total_packets = true_total

    def end_session(self, total_packets: Optional[int] = None) -> SessionInfo:
        """
        Finalize the current session with an end time.

        Args:
            total_packets: Optional explicit packet total. If omitted,
                the total is derived from whatever packets have been
                attached via :meth:`attach_packets` so far.

        Returns:
            The finalized :class:`SessionInfo`.

        Raises:
            SessionError: If no session has been started.
        """
        if self._session is None:
            raise SessionError("Cannot end a session that was never started.")

        self._session.end_time = _utc_now_iso()
        if total_packets is not None:
            self._session.total_packets = total_packets
        self.add_action(
            f"Session ended - total_packets={self._session.total_packets}"
        )
        log_module_event(
            logger,
            "SESSION_ENDED",
            detail=f"session_id={self._session.session_id} "
            f"total_packets={self._session.total_packets}",
        )
        return self._session

    def save(self, directory: Optional[Path] = None) -> Path:
        """
        Persist the current session (metadata + action log + full
        packet data) as a single JSON file.

        Safe to call more than once for the same session (e.g. once
        right after capture, again after application mapping enriches
        the packets) - each call overwrites the same file with the
        latest data, since the filename is derived from the stable
        session ID.

        Args:
            directory: Directory to save into. Defaults to the
                module's configured ``sessions/`` directory.

        Returns:
            Path to the written JSON file.

        Raises:
            SessionError: If there is no session to save, or if
                writing to disk fails.
        """
        if self._session is None:
            raise SessionError("No active session to save.")

        target_dir = directory if directory is not None else SESSIONS_DIR
        if directory is None:
            ensure_runtime_directories()
        target_dir.mkdir(parents=True, exist_ok=True)

        file_name = f"{SESSION_FILE_PREFIX}{self._session.session_id}.json"
        file_path = target_dir / file_name

        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                json.dump(self._session.to_dict(), handle, indent=2, default=str)
        except OSError as exc:
            raise SessionError(f"Failed to save session file: {exc}") from exc

        log_module_event(
            logger, "SESSION_SAVED", detail=f"path={file_path}"
        )
        return file_path

    @property
    def current_session(self) -> Optional[SessionInfo]:
        """Return the active session, if any."""
        return self._session
