"""Unit tests for anomaly_detection.aggregator."""

from __future__ import annotations

from anomaly_detection.aggregator import IdleTransferAggregator
from anomaly_detection.context import ContextRecord


def _context(user_status: str, packet_size: int = 1000, hour: int = 20) -> ContextRecord:
    return ContextRecord(
        timestamp=0.0,
        hour_of_day=hour,
        protocol="TCP",
        source_ip="10.0.0.1",
        destination_ip="93.184.216.34",
        direction="OUTGOING",
        communication_type="INTERNET",
        packet_size=packet_size,
        application_name="chrome.exe",
        process_id=1234,
        user_status=user_status,
        idle_seconds=310.0,
    )


class TestIdleTransferAggregatorUpdate:
    def test_active_user_returns_zero(self) -> None:
        aggregator = IdleTransferAggregator()
        result = aggregator.update(_context("ACTIVE"))
        assert result == 0.0

    def test_idle_accumulates_across_packets(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=1000))
        aggregator.update(_context("IDLE", packet_size=1500))
        total = aggregator.update(_context("IDLE", packet_size=500))
        assert total == 3000.0

    def test_transition_to_active_resets_running_total(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=5000))
        result = aggregator.update(_context("ACTIVE"))
        assert result == 0.0

    def test_new_idle_window_starts_fresh_after_active(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=5000))
        aggregator.update(_context("ACTIVE"))
        total = aggregator.update(_context("IDLE", packet_size=100))
        assert total == 100.0

    def test_current_accumulated_bytes_property(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=2000))
        assert aggregator.current_accumulated_bytes == 2000.0

    def test_current_accumulated_bytes_zero_when_active(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("ACTIVE"))
        assert aggregator.current_accumulated_bytes == 0.0


class TestIdleTransferAggregatorCompletedSession:
    def test_no_completed_session_while_still_idle(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=1000))
        assert aggregator.pop_completed_session() is None

    def test_completed_session_emitted_on_transition_to_active(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=1000, hour=20))
        aggregator.update(_context("IDLE", packet_size=2000, hour=20))
        aggregator.update(_context("ACTIVE"))

        completed = aggregator.pop_completed_session()
        assert completed is not None
        hour, total = completed
        assert hour == 20
        assert total == 3000.0

    def test_pop_completed_session_clears_after_reading(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=1000))
        aggregator.update(_context("ACTIVE"))

        first_pop = aggregator.pop_completed_session()
        second_pop = aggregator.pop_completed_session()
        assert first_pop is not None
        assert second_pop is None

    def test_never_going_idle_never_completes_a_session(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("ACTIVE"))
        aggregator.update(_context("ACTIVE"))
        assert aggregator.pop_completed_session() is None

    def test_intermediate_running_totals_are_not_treated_as_completed_sessions(
        self,
    ) -> None:
        """
        Critical statistical correctness check: while still IDLE, the
        running total must NOT appear as a "completed session" - only
        the transition back to ACTIVE should produce one.
        """
        aggregator = IdleTransferAggregator()
        for _ in range(10):
            aggregator.update(_context("IDLE", packet_size=1000))
            assert aggregator.pop_completed_session() is None

    def test_reset_clears_pending_completed_session(self) -> None:
        aggregator = IdleTransferAggregator()
        aggregator.update(_context("IDLE", packet_size=1000))
        aggregator.update(_context("ACTIVE"))
        aggregator.reset()
        assert aggregator.pop_completed_session() is None
