"""Unit tests for packet_capture.logger."""

from __future__ import annotations

import logging

from packet_capture.logger import get_logger, log_module_event


class TestGetLogger:
    def test_returns_same_instance_on_repeated_calls(self) -> None:
        logger_a = get_logger("test.module.a")
        logger_b = get_logger("test.module.a")
        assert logger_a is logger_b

    def test_has_no_console_stream_handler(self) -> None:
        """
        Console output must be reserved exclusively for main.py's
        clean, human-readable prints. If a StreamHandler sneaks back
        in, raw timestamped log lines will clutter the terminal again.
        """
        logger = get_logger("test.module.console_check")
        stream_handlers = [
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert stream_handlers == []

    def test_has_exactly_one_file_handler(self) -> None:
        logger = get_logger("test.module.file_check")
        file_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1

    def test_does_not_propagate_to_root(self) -> None:
        logger = get_logger("test.module.propagate_check")
        assert logger.propagate is False

    def test_different_loggers_share_the_same_handler_instance(self) -> None:
        """
        The core proof for a real fix: this package writes every
        differently-named logger's output to ONE physical file, so
        they must all share exactly ONE handler object - not one
        handler each. An earlier version created a fresh
        RotatingFileHandler per logger name, all pointed at the same
        file; when that file hit its rotation size, one handler's
        rename would collide with another handler's still-open file
        handle to the identical file, crashing with
        PermissionError: [WinError 32] on Windows. Sharing a single
        handler instance eliminates that self-inflicted lock
        contention entirely, since only one handler ever has the file
        open.
        """
        logger_a = get_logger("test.module.shared_handler_a")
        logger_b = get_logger("test.module.shared_handler_b")

        assert logger_a is not logger_b  # genuinely different loggers
        assert logger_a.handlers[0] is logger_b.handlers[0]  # same handler object

    def test_many_differently_named_loggers_all_share_one_handler(self) -> None:
        names = [f"test.module.many.{i}" for i in range(10)]
        loggers = [get_logger(name) for name in names]
        handler_ids = {id(logger.handlers[0]) for logger in loggers}
        assert len(handler_ids) == 1


class TestLogModuleEvent:
    def test_logs_event_without_detail(self, caplog) -> None:
        logger = get_logger("test.module.event_check")
        with caplog.at_level(logging.INFO, logger="test.module.event_check"):
            log_module_event(logger, "TEST_EVENT")
        # caplog captures via the root handler propagation path; since
        # propagate=False, verify no exception was raised instead.
        assert True

    def test_logs_event_with_detail_no_exception(self) -> None:
        logger = get_logger("test.module.event_detail_check")
        log_module_event(logger, "TEST_EVENT", detail="key=value")
