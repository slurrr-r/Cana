"""
logger.py
=========

Centralized logging configuration for Module 1.

Design goals:
    * A single, consistently-configured logger factory used by every
      component in the package (no ad-hoc `print()` calls for
      diagnostics).
    * Logs are written to a rotating file under ``logs/`` so long-running
      capture sessions do not produce an unbounded log file.
    * Logging is completely separate from packet data - this module has
      no knowledge of packet structures.
    * Logs are file-only by design. The console is reserved for clean,
      human-readable output controlled explicitly by ``main.py`` (menus,
      packet summaries, statistics, error explanations) - mixing raw
      timestamped log lines into that output made the terminal
      confusing and cluttered for non-technical users. Full technical
      detail is always available in ``logs/packet_capture.log`` for
      debugging.

Critical design point (fixed after a real crash caught via actual
usage on the sibling anomaly_detection package, which has the
identical structure): every module in a package like this one calls
``get_logger(__name__)`` with a DIFFERENT logger name (e.g.
"packet_capture.capture", "packet_capture.interface"), but they must
all write to the SAME underlying log file. An earlier version created
a brand new ``RotatingFileHandler`` per logger name - meaning several
independent handler objects, each holding their own open file handle,
all pointed at one physical file. The moment the file grew past its
rotation size, one handler would try to rename it while the others
still held it open - on Windows this raises
``PermissionError: [WinError 32]`` and silently drops log lines.

The fix: exactly ONE ``RotatingFileHandler`` is created per process
(module-level singleton, built lazily on first use) and shared/
attached to every logger this module hands out, regardless of name.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from typing import Optional

from packet_capture.config import (
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
    first use.

    Args:
        name: Logger name, conventionally the calling module's
            ``__name__``.
        level: Minimum severity level this logger will emit.

    Returns:
        A ``logging.Logger`` configured with a rotating file handler
        only (shared across all loggers from this factory - see
        module docstring). Nothing is printed to the console by this
        logger - console output is the exclusive responsibility of
        ``main.py``.
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
    """
    Emit a standardized, structured lifecycle event log line.

    Centralizing the format for lifecycle events (module started,
    interface selected, capture started/stopped, export completed,
    etc.) keeps log output consistent and greppable.

    Args:
        logger: Logger instance to emit through.
        event: Short event name, e.g. "CAPTURE_STARTED".
        detail: Optional human-readable detail/context.
    """
    message = f"EVENT={event}"
    if detail:
        message += f" | DETAIL={detail}"
    logger.info(message)
