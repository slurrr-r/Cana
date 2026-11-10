"""Unit tests for anomaly_detection.orchestrator."""

from __future__ import annotations

from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.rules import METRIC_IDLE_TRANSFER_BYTES, METRIC_PACKET_SIZE


def _packet(**overrides):
    packet = {
        "protocol": "TCP",
        "source_ip": "10.0.0.1",
        "destination_ip": "93.184.216.34",
        "direction": "OUTGOING",
        "communication_type": "INTERNET",
        "packet_size": 1000,
        "application_name": "chrome.exe",
        "process_id": 1234,
    }
    packet.update(overrides)
    return packet


def _activity(status: str = "ACTIVE", idle_seconds: float = 0.0):
    return {"status": status, "idle_seconds": idle_seconds}


def _total_observations(orchestrator: AnomalyDetectionOrchestrator, metric_name: str) -> int:
    """Sum observation counts across all 24 hour-buckets for a metric."""
    total = 0
    for hour in range(24):
        bucket = orchestrator.baseline.get_bucket(metric_name, hour)
        if bucket is not None:
            total += bucket.count
    return total


class TestOrchestratorBasics:
    def test_process_packet_returns_thirteen_results(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        results = orchestrator.process_packet(_packet(), _activity())
        assert len(results) == 13

    def test_packets_processed_counter_increments(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        orchestrator.process_packet(_packet(), _activity())
        orchestrator.process_packet(_packet(), _activity())
        assert orchestrator.packets_processed == 2

    def test_total_triggers_counts_across_calls(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        # Missing attribution is diagnostic; it must not increase security counts.
        orchestrator.process_packet(
            _packet(application_name="UNKNOWN"), _activity()
        )
        assert orchestrator.total_triggers == 0
        orchestrator.process_packet(_packet(tcp_flags='SF'), _activity())
        assert orchestrator.total_triggers == 1

    def test_works_without_activity_status(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        results = orchestrator.process_packet(_packet(), activity_status=None)
        assert len(results) == 13


class TestOrchestratorBaselineFeeding:
    def test_packet_size_baseline_updated_every_packet(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        for _ in range(5):
            orchestrator.process_packet(_packet(), _activity())

        assert _total_observations(orchestrator, METRIC_PACKET_SIZE) == 5

    def test_idle_transfer_baseline_not_fed_until_session_completes(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        for _ in range(5):
            orchestrator.process_packet(
                _packet(), _activity(status="IDLE", idle_seconds=310.0)
            )

        # Still mid-idle-session - no completed session yet, so the
        # idle-transfer baseline must not have been fed anything.
        assert _total_observations(orchestrator, METRIC_IDLE_TRANSFER_BYTES) == 0

    def test_idle_transfer_baseline_fed_once_session_completes(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        for _ in range(5):
            orchestrator.process_packet(
                _packet(), _activity(status="IDLE", idle_seconds=310.0)
            )
        # Transition back to active - completes the idle session.
        orchestrator.process_packet(_packet(), _activity(status="ACTIVE"))

        assert _total_observations(orchestrator, METRIC_IDLE_TRANSFER_BYTES) == 1


class TestOrchestratorEndToEndMovieNightScenario:
    def test_full_orchestrator_movie_night_scenario(self) -> None:
        """
        The complete, real end-to-end proof: run several simulated
        'evening streaming' idle sessions through the actual
        orchestrator (not just the baseline/rule functions directly),
        then confirm a similar session doesn't get flagged, while an
        unprecedented one still does.
        """
        orchestrator = AnomalyDetectionOrchestrator()

        def simulate_idle_session(total_bytes: float, hour: int) -> None:
            orchestrator.process_packet(
                _packet(packet_size=int(total_bytes)),
                _activity(status="IDLE", idle_seconds=310.0),
            )
            # End the session.
            orchestrator.process_packet(_packet(), _activity(status="ACTIVE"))

        # Several "normal" evening sessions.
        for volume in [140_000_000, 155_000_000, 148_000_000, 160_000_000, 152_000_000]:
            simulate_idle_session(volume, hour=20)

        # Tonight's movie: similar volume - should not trigger idle_large_transfer.
        results = orchestrator.process_packet(
            _packet(packet_size=150_000_000),
            _activity(status="IDLE", idle_seconds=310.0),
        )
        idle_result = next(r for r in results if r.rule_name == "idle_large_transfer")
        assert idle_result.triggered is False


class TestOrchestratorBaselineLeakage:
    """Regression tests for P2 Bug #1 (baseline leakage)."""

    def test_packet_size_diagnostic_learns_new_sizes(
        self,
    ) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        # Establish a tight normal baseline of small packets.
        for _ in range(10):
            orchestrator.process_packet(_packet(packet_size=500), _activity())

        count_before = _total_observations(orchestrator, METRIC_PACKET_SIZE)

        # Diagnostic size statistics can adapt; they are excluded from security scoring.
        results = orchestrator.process_packet(
            _packet(packet_size=5_000_000), _activity()
        )
        size_result = next(
            r for r in results if r.rule_name == "packet_size_anomaly"
        )
        assert size_result.triggered is True
        assert _total_observations(orchestrator, METRIC_PACKET_SIZE) == count_before + 1

    def test_normal_packet_is_still_learned(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        for _ in range(10):
            orchestrator.process_packet(_packet(packet_size=500), _activity())
        count_before = _total_observations(orchestrator, METRIC_PACKET_SIZE)

        results = orchestrator.process_packet(
            _packet(packet_size=505), _activity()
        )
        size_result = next(
            r for r in results if r.rule_name == "packet_size_anomaly"
        )
        assert size_result.triggered is False
        assert _total_observations(orchestrator, METRIC_PACKET_SIZE) == count_before + 1

    def test_an_idle_session_that_triggered_an_alert_is_not_learned_as_normal(
        self,
    ) -> None:
        """
        Regression test for P2 Bugs #1 and #5 together: an idle
        session whose completed transfer was flagged as anomalous
        (fallback threshold, since the baseline is still cold here)
        must not be learned into the idle-transfer baseline - doing
        so would let one loud, already-flagged session quietly start
        legitimizing future transfers of the same size.
        """
        from anomaly_detection.config import FALLBACK_LARGE_TRANSFER_BYTES

        orchestrator = AnomalyDetectionOrchestrator()
        huge = FALLBACK_LARGE_TRANSFER_BYTES + 1
        results = orchestrator.process_packet(
            _packet(packet_size=huge), _activity(status="IDLE", idle_seconds=310.0)
        )
        idle_result = next(
            r for r in results if r.rule_name == "idle_large_transfer"
        )
        assert idle_result.triggered is True

        # Complete the session.
        orchestrator.process_packet(_packet(), _activity(status="ACTIVE"))

        assert _total_observations(orchestrator, METRIC_IDLE_TRANSFER_BYTES) == 0


class TestOrchestratorIdleTransferDoubleCounting:
    """Regression tests for P2 Bug #5 (idle-transfer double counting)."""

    def test_a_single_packets_bytes_are_counted_once_not_twice(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        orchestrator.process_packet(
            _packet(packet_size=1000),
            _activity(status="IDLE", idle_seconds=310.0),
        )
        assert orchestrator.idle_aggregator.current_accumulated_bytes == 1000.0

    def test_completed_session_total_matches_sum_of_packet_sizes(self) -> None:
        orchestrator = AnomalyDetectionOrchestrator()
        sizes = [1000, 2000, 3000]
        for size in sizes:
            orchestrator.process_packet(
                _packet(packet_size=size),
                _activity(status="IDLE", idle_seconds=310.0),
            )
        orchestrator.process_packet(_packet(), _activity(status="ACTIVE"))

        bucket = None
        for hour in range(24):
            candidate = orchestrator.baseline.get_bucket(
                METRIC_IDLE_TRANSFER_BYTES, hour
            )
            if candidate is not None and candidate.count:
                bucket = candidate
                break
        assert bucket is not None
        # If double-counted, this would be 2 * sum(sizes) instead.
        assert bucket.mean == float(sum(sizes))
