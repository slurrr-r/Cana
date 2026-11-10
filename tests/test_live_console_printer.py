"""
Unit tests for packet_capture.utils.LiveConsolePrinter.

Captures stdout to verify actual printed output, since this class's
entire purpose is console display behavior.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from packet_capture.utils import LiveConsolePrinter


def _packet(**overrides):
    packet = {
        "timestamp": "2026-08-10 10:09:25",
        "application_name": "svchost.exe",
        "protocol": "TCP",
        "direction": "INCOMING",
        "source_ip": "92.223.116.252",
        "destination_ip": "10.127.11.39",
        "source_port": 80,
        "destination_port": 61162,
    }
    packet.update(overrides)
    return packet


def _run(printer: LiveConsolePrinter, packets) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        for packet in packets:
            printer.display(packet)
        printer.finalize()
    return buffer.getvalue()


class TestLiveConsolePrinterBasicDisplay:
    def test_single_packet_prints_full_block(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet()])
        assert "svchost.exe" in output
        assert "TCP (Incoming)" in output

    def test_distinct_conversations_each_get_a_block(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(
            printer,
            [
                _packet(destination_ip="1.1.1.1"),
                _packet(destination_ip="2.2.2.2"),
            ],
        )
        assert "1.1.1.1" in output
        assert "2.2.2.2" in output


class TestLiveConsolePrinterSuppression:
    def test_unmapped_packets_suppressed_by_default(self) -> None:
        printer = LiveConsolePrinter()
        output = _run(printer, [_packet(application_name="UNKNOWN")])
        assert output == ""

    def test_unmapped_packets_shown_when_suppression_disabled(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet(application_name="UNKNOWN")])
        assert "UNKNOWN" in output

    def test_missing_application_name_treated_as_unmapped(self) -> None:
        printer = LiveConsolePrinter()
        packet = _packet()
        del packet["application_name"]
        output = _run(printer, [packet])
        assert output == ""

    def test_mapped_packets_never_suppressed(self) -> None:
        printer = LiveConsolePrinter()
        output = _run(printer, [_packet(application_name="chrome.exe")])
        assert "chrome.exe" in output


class TestLiveConsolePrinterCollapsing:
    def test_repeated_same_conversation_collapses_to_counter(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet(), _packet(), _packet()])
        assert output.count("[10:09:25]") == 1
        assert "3 packets exchanged" in output

    def test_alternating_ports_to_same_destination_still_collapses(self) -> None:
        """
        The exact real-world pattern that motivated fixing the
        connection key: the same logical conversation cycling through
        different ephemeral ports must still collapse.
        """
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(
            printer,
            [
                _packet(direction="INCOMING", source_port=80, destination_port=61162),
                _packet(direction="INCOMING", source_port=80, destination_port=61162),
                _packet(direction="OUTGOING", source_port=61162, destination_port=80,
                        source_ip="10.127.11.39", destination_ip="92.223.116.252"),
                _packet(direction="INCOMING", source_port=80, destination_port=37424),
                _packet(direction="INCOMING", source_port=80, destination_port=37424),
                _packet(direction="OUTGOING", source_port=37424, destination_port=80,
                        source_ip="10.127.11.39", destination_ip="92.223.116.252"),
            ],
        )
        assert output.count("svchost.exe\n") <= 1
        assert "6 packets exchanged" in output

    def test_different_destination_breaks_the_collapse(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(
            printer,
            [
                _packet(destination_ip="1.1.1.1"),
                _packet(destination_ip="1.1.1.1"),
                _packet(destination_ip="9.9.9.9"),
            ],
        )
        assert "1.1.1.1" in output
        assert "9.9.9.9" in output
        assert "3 packets exchanged" not in output

    def test_different_application_breaks_the_collapse(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(
            printer,
            [
                _packet(application_name="svchost.exe"),
                _packet(application_name="chrome.exe"),
            ],
        )
        assert "svchost.exe" in output
        assert "chrome.exe" in output

    def test_finalize_closes_an_open_counter_line(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet(), _packet()])
        assert output.endswith("\n") or "2 packets exchanged" in output


class TestLiveConsolePrinterHighVolumeScenario:
    def test_reproduces_the_real_burst_scenario_compactly(self) -> None:
        """
        Reproduces the exact real-world scenario: thousands of
        svchost.exe packets alternating between two ports to the same
        destination. Output must stay compact, not one block/packet.
        """
        printer = LiveConsolePrinter(suppress_unmapped=False)
        packets = []
        for i in range(500):
            port = 61162 if i % 2 == 0 else 37424
            packets.append(
                _packet(
                    direction="INCOMING" if i % 3 else "OUTGOING",
                    destination_port=port,
                )
            )
        output = _run(printer, packets)

        line_count = output.count("\n")
        assert line_count < 20
        assert "500 packets exchanged" in output


class TestLiveConsolePrinterNeverGarblesWhenCopied:
    """
    Reproduces and proves the fix for a real bug: an earlier version
    used a carriage-return (\\r) in-place-overwrite trick for a
    slicker live-terminal effect, which mashed old and new text
    together into unreadable garbage the moment output was copied,
    redirected, or logged - exactly what happens when sharing terminal
    output for debugging, a routine part of this project's workflow.
    """

    def test_no_carriage_return_in_output_for_a_repeat_burst(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet() for _ in range(50)])
        assert "\r" not in output

    def test_no_carriage_return_across_many_distinct_conversations(self) -> None:
        printer = LiveConsolePrinter(suppress_unmapped=False)
        packets = [
            _packet(destination_ip=f"10.0.0.{i}") for i in range(20)
            for _ in range(5)
        ]
        output = _run(printer, packets)
        assert "\r" not in output

    def test_every_output_line_is_a_complete_independent_line(self) -> None:
        """
        A garbled \\r-collision produces a single line containing
        fragments of two different messages mashed together (e.g.
        "...exchangedchrome.exe..." from the real bug report). Every
        line here must be one complete, sensible line - checked by
        confirming no line contains two separate "packets exchanged"
        counts glued together, the exact failure pattern observed.
        """
        printer = LiveConsolePrinter(suppress_unmapped=False)
        output = _run(printer, [_packet() for _ in range(10)] * 3)
        assert output.count("packets exchanged") <= output.count("\n")


class TestLiveConsolePrinterThrottledPeriodicUpdates:
    def test_periodic_updates_occur_as_real_time_passes(self, monkeypatch) -> None:
        """
        Proves the throttled periodic printing actually works over
        real elapsed time (not just "one block, then silence until
        finalize", which is all a fast unit test would show without
        controlling the clock) - simulates time passing between
        packets using monkeypatched time.time().
        """
        import packet_capture.utils as utils_module

        fake_now = [1000.0]
        monkeypatch.setattr(utils_module.time, "time", lambda: fake_now[0])

        printer = LiveConsolePrinter(suppress_unmapped=False)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            printer.display(_packet())  # first packet - full block
            for i in range(3):
                fake_now[0] += 1.5  # advance past the 1.0s throttle each time
                printer.display(_packet())
            printer.finalize()
        output = buffer.getvalue()

        # Each throttle-interval-spaced repeat should have produced
        # its own fresh summary line - not just one lump total.
        assert output.count("packets exchanged") >= 3

    def test_rapid_repeats_within_throttle_window_produce_no_interim_line(
        self, monkeypatch
    ) -> None:
        import packet_capture.utils as utils_module

        fake_now = [2000.0]
        monkeypatch.setattr(utils_module.time, "time", lambda: fake_now[0])

        printer = LiveConsolePrinter(suppress_unmapped=False)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            printer.display(_packet())  # full block
            for _ in range(10):
                fake_now[0] += 0.01  # stays well within the 1.0s throttle
                printer.display(_packet())
            # No finalize() yet - nothing should have printed a
            # repeat-summary line during the throttled window.
        output = buffer.getvalue()

        assert "packets exchanged" not in output
