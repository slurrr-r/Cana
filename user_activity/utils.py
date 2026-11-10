"""
utils.py
========

Console formatting helpers for Module 3.
"""

from __future__ import annotations

from user_activity.tracker import ActivityStatus


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds as ``HH:MM:SS``.

    Args:
        seconds: Elapsed time in seconds.

    Returns:
        A zero-padded ``HH:MM:SS`` string.
    """
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_status_line(status: ActivityStatus) -> str:
    """
    Build a clean, human-readable status line.

    Example output::

        User status: ACTIVE (idle for 00:00:12)

    Args:
        status: An :class:`user_activity.tracker.ActivityStatus`.

    Returns:
        A formatted status line.
    """
    return (
        f"User status: {status.status} "
        f"(idle for {format_duration(status.idle_seconds)})"
    )
