"""Live Windows acceptance: SCM, named pipe, Npcap parking.

Skipped on non-Windows. On Windows, set CANA_ACCEPTANCE=1 to exercise
an installed service (sc.exe, \\\\.\\pipe\\CANAControl, Npcap).
"""

from __future__ import annotations

import os
import subprocess

import pytest

from cana_engine.pipe import PIPE_NAME
from cana_service.constants import SERVICE_NAME

pytestmark = pytest.mark.windows

_LIVE = os.name == "nt" and os.environ.get("CANA_ACCEPTANCE") == "1"


def _skip_unless_live() -> None:
    if os.name != "nt":
        pytest.skip("Windows acceptance requires Windows")
    if os.environ.get("CANA_ACCEPTANCE") != "1":
        pytest.skip("set CANA_ACCEPTANCE=1 to run live SCM/Npcap/pipe checks")


def test_acceptance_is_gated_off_linux() -> None:
    if os.name != "nt":
        assert _LIVE is False


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_service_query_succeeds() -> None:
    _skip_unless_live()
    result = subprocess.run(
        ["sc.exe", "query", SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    combined = (result.stdout + result.stderr).upper()
    assert "RUNNING" in combined or "STOPPED" in combined or "START_PENDING" in combined


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_service_binpath_has_no_service_flag() -> None:
    _skip_unless_live()
    result = subprocess.run(
        ["sc.exe", "qc", SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--service" not in result.stdout.lower()


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_installer_sid_file_is_sid() -> None:
    _skip_unless_live()
    from cana_engine.config import load_installer_user_sid

    sid = load_installer_user_sid()
    assert sid.startswith("S-1-")


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_named_pipe_start_stop_roundtrip() -> None:
    _skip_unless_live()
    from cana_engine.pipe import PipeClient

    client = PipeClient()
    started = client.start_monitoring()
    assert started.get("ok") is True
    stopped = client.stop_monitoring()
    assert stopped.get("ok") is True
    restarted = client.start_monitoring()
    assert restarted.get("ok") is True


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_named_pipe_rejects_unknown_command() -> None:
    _skip_unless_live()
    from cana_engine.pipe import PipeClient

    client = PipeClient()
    result = client.request("shell")
    assert result.get("ok") is False


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_named_pipe_start_rejects_extra_fields() -> None:
    _skip_unless_live()
    from cana_engine.pipe import PipeClient

    client = PipeClient()
    result = client.request("start", {"something": "unexpected"})
    assert result.get("ok") is False


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_invalid_apply_config_leaves_runtime() -> None:
    _skip_unless_live()
    from cana_engine.pipe import PipeClient

    client = PipeClient()
    before = client.get_config()
    packet_filter = (before.get("config") or before).get("packet_filter", "ALL")
    rejected = client.apply_config({"packet_filter": "FTP"})
    assert rejected.get("ok") is False
    after = client.get_config()
    assert (after.get("config") or after).get("packet_filter") == packet_filter


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_service_stays_queryable_after_pipe_roundtrip() -> None:
    _skip_unless_live()
    result = subprocess.run(
        ["sc.exe", "query", SERVICE_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "RUNNING" in (result.stdout + result.stderr).upper()


@pytest.mark.skipif(not _LIVE, reason="live Windows acceptance disabled")
def test_named_pipe_path_is_local() -> None:
    _skip_unless_live()
    assert PIPE_NAME.startswith("\\\\.\\pipe\\")
    import win32file

    handle = win32file.CreateFile(
        PIPE_NAME,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0,
        None,
        win32file.OPEN_EXISTING,
        0,
        None,
    )
    win32file.CloseHandle(handle)
