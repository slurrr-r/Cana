"""
logging_setup.py
================

Service-oriented logging on top of the existing rotating-file loggers.

Adds a dedicated ``logs/cana_service.log`` for lifecycle events without
logging every packet. Existing module loggers continue to write to their
own files.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from packet_capture.config import LOG_BACKUP_COUNT, LOG_DATE_FORMAT, LOG_FORMAT, LOG_MAX_BYTES

SERVICE_LOG_FILE_NAME = "cana_service.log"

_handler: Optional[RotatingFileHandler] = None
_configured_level: Optional[int] = None


def configure_service_logging(logs_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure the process-wide CANA service logger."""
    global _handler, _configured_level
    logs_dir.mkdir(parents=True, exist_ok=True)
    numeric = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("cana.service")
    logger.setLevel(numeric)
    logger.propagate = False
    if _handler is None:
        handler = RotatingFileHandler(
            filename=str(logs_dir / SERVICE_LOG_FILE_NAME),
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
        logger.addHandler(handler)
        _handler = handler
    _configured_level = numeric
    for existing in logging.getLogger("packet_capture").handlers:
        existing.setLevel(numeric)
    return logger


def service_logger() -> logging.Logger:
    return logging.getLogger("cana.service")


def log_lifecycle(event: str, detail: str = "") -> None:
    logger = service_logger()
    message = f"EVENT={event}"
    if detail:
        message += f" | DETAIL={detail}"
    logger.info(message)


__all__ = [
    "SERVICE_LOG_FILE_NAME",
    "configure_service_logging",
    "log_lifecycle",
    "service_logger",
]
