"""
logger.py
=========

Centralized logging configuration for Module 4, mirroring the
file-only rotating-log pattern used by packet_capture and
user_activity (no console handler - console output is entirely the
caller's responsibility).

Critical design point (fixed after a real crash caught via actual
usage): every module in this package calls ``get_logger(__name__)``
with a DIFFERENT logger name (e.g. "anomaly_detection.rules",
"anomaly_detection.orchestrator"), but they must all write to the SAME
underlying log file. An earlier version created a brand new
``RotatingFileHandler`` per logger name - meaning several independent
handler objects, each holding their own open file handle, all pointed
at one physical file. The moment the file grew past its rotation size,
one handler tried to rename it while the others still held it open -
on Windows this raised ``PermissionError: [WinError 32]`` and silently
dropped log lines (Python's logging module swallows handler errors
internally rather than crashing the caller, so this didn't crash
capture, but it broke logging and spammed noisy "--- Logging error
---" output).

The fix: exactly ONE ``RotatingFileHandler`` is created per process
(module-level singleton, built lazily on first use) and shared/
attached to every logger this module hands out, regardless of name.
One handler, one open file handle, no self-inflicted lock contention
during rotation.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

from anomaly_detection.config import (
    LOG_BACKUP_COUNT,
    LOG_DATE_FORMAT,
    LOG_FILE_NAME,
    LOG_FORMAT,
    LOG_MAX_BYTES,
    LOGS_DIR,
    ensure_runtime_directories,
)

_CONFIGURED_LOGGERS: dict[str, logging.Logger] = {}
_shared_file_handler: Optional[RotatingFileHandler] = None


def _get_shared_file_handler() -> RotatingFileHandler:
    """
    Return the single, process-wide ``RotatingFileHandler`` for this
    module's log file, creating it on first use.

    The handler's own level is deliberately left at ``NOTSET`` (0) -
    filtering is done entirely by each individual logger's own
    ``setLevel()`` before a record ever reaches this shared handler,
    so one logger's level can never inadvertently affect another's via
    a shared handler-level filter.
    """
    global _shared_file_handler
    if _shared_file_handler is None:
        ensure_runtime_directories()
        formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        handler = RotatingFileHandler(
            filename=str(LOGS_DIR / LOG_FILE_NAME),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        _shared_file_handler = handler
    return _shared_file_handler


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Return a configured logger instance, creating and caching it on
    first use. All loggers returned by this function share a single
    underlying file handler (see module docstring).
    """
    if name in _CONFIGURED_LOGGERS:
        return _CONFIGURED_LOGGERS[name]

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        logger.addHandler(_get_shared_file_handler())

    _CONFIGURED_LOGGERS[name] = logger
    return logger


def log_module_event(
    logger: logging.Logger,
    event: str,
    detail: Optional[str] = None,
) -> None:
    """Emit a standardized, structured lifecycle event log line."""
    message = f"EVENT={event}"
    if detail:
        message += f" | DETAIL={detail}"
    logger.info(message)
