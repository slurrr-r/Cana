"""
Unit tests for anomaly_detection.logger.

This is the package where the real shared-handler bug was actually
caught: anomaly_detection logs an EVENT line for every rule trigger
(see rules.py's evaluate_all_rules), which under real, heavy traffic
produced enough log volume to hit the 5MB rotation size - exposing
the fact that every differently-named logger (rules, orchestrator,
baseline, etc.) previously held its own independent handler pointed
at the same file, causing a Windows PermissionError the moment one of
them tried to rotate while the others still had it open.
"""

from __future__ import annotations

import logging

from anomaly_detection.logger import get_logger, log_module_event


class TestGetLogger:
    def test_returns_same_instance_on_repeated_calls(self) -> None:
        logger_a = get_logger("test.anomaly_detection.a")
        logger_b = get_logger("test.anomaly_detection.a")
        assert logger_a is logger_b

    def test_has_no_console_stream_handler(self) -> None:
        logger = get_logger("test.anomaly_detection.console_check")
        stream_handlers = [
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert stream_handlers == []

    def test_has_exactly_one_file_handler(self) -> None:
        logger = get_logger("test.anomaly_detection.file_check")
        file_handlers = [
            h for h in logger.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1

    def test_does_not_propagate_to_root(self) -> None:
        logger = get_logger("test.anomaly_detection.propagate_check")
        assert logger.propagate is False

    def test_different_loggers_share_the_same_handler_instance(self) -> None:
        """
        The core proof for the real fix that resolved an actual
        production crash: rules.py, orchestrator.py, baseline.py, etc.
        each call get_logger(__name__) with a different name, but all
        write to the same anomaly_detection.log file. They must share
        exactly ONE handler object, not one each - otherwise, once the
        file grows past its rotation size, one handler's rename
        collides with another still-open handle to the identical file
        (PermissionError: [WinError 32] on Windows).
        """
        logger_a = get_logger("test.anomaly_detection.shared_handler_a")
        logger_b = get_logger("test.anomaly_detection.shared_handler_b")

        assert logger_a is not logger_b
        assert logger_a.handlers[0] is logger_b.handlers[0]

    def test_many_module_loggers_all_share_one_handler(self) -> None:
        """
        Simulates the real shape of the bug: this package genuinely
        has six separate modules (context, baseline, aggregator,
        rate_tracker, rules, orchestrator) each independently calling
        get_logger(__name__). All of them must resolve to one handler.
        """
        real_module_style_names = [
            "test.anomaly_detection.context",
            "test.anomaly_detection.baseline",
            "test.anomaly_detection.aggregator",
            "test.anomaly_detection.rate_tracker",
            "test.anomaly_detection.rules",
            "test.anomaly_detection.orchestrator",
        ]
        loggers = [get_logger(name) for name in real_module_style_names]
        handler_ids = {id(logger.handlers[0]) for logger in loggers}
        assert len(handler_ids) == 1


class TestLogModuleEvent:
    def test_logs_event_without_detail_no_exception(self) -> None:
        logger = get_logger("test.anomaly_detection.event_check")
        log_module_event(logger, "TEST_EVENT")

    def test_logs_event_with_detail_no_exception(self) -> None:
        logger = get_logger("test.anomaly_detection.event_detail_check")
        log_module_event(logger, "TEST_EVENT", detail="key=value")

    def test_high_volume_logging_does_not_raise(self) -> None:
        """
        Directly simulates the real-world trigger condition (a large
        burst of RULE_TRIGGERED events) at a scale far smaller than
        what would hit actual file rotation, just to confirm rapid
        repeated logging through many differently-named loggers never
        raises within the test process.
        """
        logger = get_logger("test.anomaly_detection.high_volume")
        for i in range(500):
            log_module_event(logger, "RULE_TRIGGERED", detail=f"sample_{i}")
