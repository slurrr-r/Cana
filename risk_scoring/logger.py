"""
logger.py
=========

Centralized logging configuration for Module 5, mirroring the
file-only rotating-log pattern used by every other package: one shared
``RotatingFileHandler`` per process, attached to any logger handed out
here, writing to ``logs/risk_scoring.log``.

The single-shared-handler design is critical on Windows (the same
reason documented in ``anomaly_detection/logger.py``): multiple
handlers pointed at one physical file fight over rotation renames and
drop log lines. One handler, one file handle, no contention.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from anomaly_detection.config import (
    LOG_BACKUP_COUNT,
    LOG_DATE_FORMAT,
    LOG_FORMAT,
    LOG_MAX_BYTES,
    LOGS_DIR,
)

LOG_FILE_NAME = "risk_scoring.log"

_CONFIGURED_LOGGERS: dict[str, logging.Logger] = {}
_shared_file_handler: Optional[RotatingFileHandler] = None


def _get_shared_file_handler() -> RotatingFileHandler:
    """Return the single, process-wide file handler, creating it on first use."""
    global _shared_file_handler
    if _shared_file_handler is None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        handler = RotatingFileHandler(
            filename=str(Path(LOGS_DIR) / LOG_FILE_NAME),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        _shared_file_handler = handler
    return _shared_file_handler


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger instance, cached on first use."""
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


__all__ = ["get_logger", "log_module_event"]
