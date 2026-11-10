"""Unit tests for user_activity.logger."""

from __future__ import annotations

import logging

from user_activity.logger import get_logger, log_module_event


class TestGetLogger:
    def test_returns_same_instance_on_repeated_calls(self) -> None:
        logger_a = get_logger("test.user_activity.a")
        logger_b = get_logger("test.user_activity.a")
        assert logger_a is logger_b

    def test_has_no_console_stream_handler(self) -> None:
        logger = get_logger("test.user_activity.console_check")
        stream_handlers = [
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert stream_handlers == []

    def test_has_exactly_one_file_handler(self) -> None:
        logger = get_logger("test.user_activity.file_check")
        file_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1

    def test_does_not_propagate_to_root(self) -> None:
        logger = get_logger("test.user_activity.propagate_check")
        assert logger.propagate is False

    def test_different_loggers_share_the_same_handler_instance(self) -> None:
        """See packet_capture's test_logger.py for the full rationale -
        a shared handler eliminates a real, previously-hit Windows
        PermissionError during log rotation caused by multiple
        independent handlers holding open handles to the same file."""
        logger_a = get_logger("test.user_activity.shared_handler_a")
        logger_b = get_logger("test.user_activity.shared_handler_b")

        assert logger_a is not logger_b
        assert logger_a.handlers[0] is logger_b.handlers[0]


class TestLogModuleEvent:
    def test_logs_event_without_detail_no_exception(self) -> None:
        logger = get_logger("test.user_activity.event_check")
        log_module_event(logger, "TEST_EVENT")

    def test_logs_event_with_detail_no_exception(self) -> None:
        logger = get_logger("test.user_activity.event_detail_check")
        log_module_event(logger, "TEST_EVENT", detail="key=value")
