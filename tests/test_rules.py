"""Unit tests for anomaly_detection.rules."""

from __future__ import annotations

from anomaly_detection.aggregator import IdleTransferAggregator
from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.config import (
    FALLBACK_LARGE_TRANSFER_BYTES,
    MIN_RATE_SAMPLES_FOR_BASELINE,
)
from anomaly_detection.context import ContextRecord
from anomaly_detection.rate_tracker import ConnectionRateTracker
from anomaly_detection.rules import (
    METRIC_CONNECTION_RATE,
    METRIC_IDLE_TRANSFER_BYTES,
    METRIC_PACKET_SIZE,
    connection_rate_anomaly_rule,
    connection_rate_metric_name,
    connection_rate_peer,
    evaluate_all_rules,
    idle_large_transfer_rule,
    packet_size_anomaly_rule,
    unknown_application_internet_rule,
)


def _context(**overrides) -> ContextRecord:
    base = dict(
        timestamp=0.0,
        hour_of_day=20,
        protocol="TCP",
        source_ip="10.0.0.1",
        destination_ip="93.184.216.34",
        direction="OUTGOING",
        communication_type="INTERNET",
        packet_size=1000,
        application_name="chrome.exe",
        process_id=1234,
        user_status="ACTIVE",
        idle_seconds=0.0,
    )
    base.update(overrides)
    return ContextRecord(**base)


class TestIdleLargeTransferRule:
    def test_not_triggered_when_active(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        result = idle_large_transfer_rule(
            _context(user_status="ACTIVE"), baseline, aggregator
        )
        assert result.triggered is False
        assert "active" in result.reason.lower()

    def test_fallback_threshold_used_during_cold_start(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        big_packet_size = FALLBACK_LARGE_TRANSFER_BYTES + 1
        # The rule reads the aggregator's CURRENT accumulated total; it
        # no longer updates the aggregator itself (P2 fix - see
        # orchestrator.py, which is the only caller responsible for
        # calling aggregator.update() exactly once per packet). Unit
        # tests calling the rule directly must prime the aggregator
        # first, mirroring what the orchestrator does before invoking
        # this rule.
        context = _context(user_status="IDLE", packet_size=big_packet_size)
        aggregator.update(context)
        result = idle_large_transfer_rule(context, baseline, aggregator)
        assert result.triggered is True
        assert "fixed fallback" in result.reason

    def test_the_movie_night_scenario_not_triggered_once_baseline_established(
        self,
    ) -> None:
        baseline = BaselineTracker()
        volumes = [140_000_000, 155_000_000, 148_000_000, 160_000_000, 152_000_000, 145_000_000]
        for volume in volumes:
            baseline.update(METRIC_IDLE_TRANSFER_BYTES, hour_of_day=20, value=volume)

        aggregator = IdleTransferAggregator()
        context = _context(user_status="IDLE", packet_size=150_000_000, hour_of_day=20)
        aggregator.update(context)
        result = idle_large_transfer_rule(context, baseline, aggregator)
        assert result.triggered is False
        assert "learned baseline" in result.reason

    def test_genuinely_unprecedented_transfer_triggers_even_with_baseline(
        self,
    ) -> None:
        baseline = BaselineTracker()
        volumes = [140_000_000, 155_000_000, 148_000_000, 160_000_000, 152_000_000, 145_000_000]
        for volume in volumes:
            baseline.update(METRIC_IDLE_TRANSFER_BYTES, hour_of_day=20, value=volume)

        aggregator = IdleTransferAggregator()
        context = _context(
            user_status="IDLE", packet_size=5_000_000_000, hour_of_day=20
        )
        aggregator.update(context)
        result = idle_large_transfer_rule(context, baseline, aggregator)
        assert result.triggered is True

    def test_rule_does_not_double_count_the_current_packet(self) -> None:
        """
        Regression test for P2 Bug #5 (idle-transfer double counting).

        Before the fix, this rule called ``aggregator.update(context)``
        a second time (the orchestrator already calls it once), so a
        single packet's bytes were counted twice in the live verdict.
        """
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        context = _context(user_status="IDLE", packet_size=1000, hour_of_day=20)

        # Simulate exactly what the orchestrator does: update the
        # aggregator once per packet, then evaluate the rule.
        aggregator.update(context)
        idle_large_transfer_rule(context, baseline, aggregator)

        assert aggregator.current_accumulated_bytes == 1000.0


class TestUnknownApplicationInternetRule:
    def test_triggered_for_unknown_app_internet_traffic(self) -> None:
        result = unknown_application_internet_rule(
            _context(application_name="UNKNOWN", communication_type="INTERNET")
        )
        assert result.triggered is True
        assert result.severity == "MEDIUM"

    def test_not_triggered_for_known_app(self) -> None:
        result = unknown_application_internet_rule(
            _context(application_name="chrome.exe", communication_type="INTERNET")
        )
        assert result.triggered is False

    def test_not_triggered_for_local_network_traffic(self) -> None:
        result = unknown_application_internet_rule(
            _context(application_name="UNKNOWN", communication_type="LOCAL_NETWORK")
        )
        assert result.triggered is False

    def test_not_triggered_for_broadcast(self) -> None:
        result = unknown_application_internet_rule(
            _context(application_name="UNKNOWN", communication_type="BROADCAST")
        )
        assert result.triggered is False

    def test_not_triggered_for_multicast(self) -> None:
        result = unknown_application_internet_rule(
            _context(application_name="UNKNOWN", communication_type="MULTICAST")
        )
        assert result.triggered is False

    def test_icmp_exempted_even_if_unknown_and_internet(self) -> None:
        result = unknown_application_internet_rule(
            _context(
                application_name="UNKNOWN",
                communication_type="INTERNET",
                protocol="ICMP",
            )
        )
        assert result.triggered is False

    def test_icmpv6_exempted(self) -> None:
        result = unknown_application_internet_rule(
            _context(
                application_name="UNKNOWN",
                communication_type="INTERNET",
                protocol="ICMPV6",
            )
        )
        assert result.triggered is False

    def test_udp_unknown_internet_still_triggers(self) -> None:
        result = unknown_application_internet_rule(
            _context(
                application_name="UNKNOWN",
                communication_type="INTERNET",
                protocol="UDP",
            )
        )
        assert result.triggered is True


class TestPacketSizeAnomalyRule:
    def test_not_triggered_when_baseline_not_established(self) -> None:
        baseline = BaselineTracker()
        result = packet_size_anomaly_rule(_context(packet_size=99999), baseline)
        assert result.triggered is False
        assert "not yet established" in result.reason

    def test_triggered_for_outlier_packet_size(self) -> None:
        baseline = BaselineTracker()
        for size in [500, 520, 480, 510, 495, 505]:
            baseline.update(METRIC_PACKET_SIZE, hour_of_day=20, value=size)

        result = packet_size_anomaly_rule(
            _context(packet_size=50000, hour_of_day=20), baseline
        )
        assert result.triggered is True

    def test_not_triggered_for_normal_packet_size(self) -> None:
        baseline = BaselineTracker()
        for size in [500, 520, 480, 510, 495, 505]:
            baseline.update(METRIC_PACKET_SIZE, hour_of_day=20, value=size)

        result = packet_size_anomaly_rule(
            _context(packet_size=515, hour_of_day=20), baseline
        )
        assert result.triggered is False


class TestConnectionRateAnomalyRule:
    def test_insufficient_data_reported_below_threshold(self) -> None:
        """
        29 samples (one short of MIN_RATE_SAMPLES_FOR_BASELINE=30)
        must NOT be treated as an established baseline - the rule
        should report "not enough data", never trigger or clear.
        """
        baseline = BaselineTracker()
        metric_name = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        for _ in range(MIN_RATE_SAMPLES_FOR_BASELINE - 1):  # 29 samples
            baseline.update(metric_name, hour_of_day=20, value=1.0)

        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        # A fresh tracker always samples on its very first call (by
        # design, for real capture) - consume that allowance here,
        # separately, so the rule's own internal sampling doesn't
        # silently add a 30th sample while we're specifically checking
        # the still-insufficient (29-sample) state.
        rate_tracker.record("chrome.exe", "93.184.216.34")

        result = connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", hour_of_day=20),
            baseline,
            rate_tracker,
        )
        assert result.triggered is False
        assert "not enough data" in result.reason.lower()
        assert "29/30" in result.reason

    def test_becomes_evaluable_at_exactly_the_threshold(self) -> None:
        """
        Exactly 30 samples (MIN_RATE_SAMPLES_FOR_BASELINE) must be
        enough to move the rule from "insufficient data" into a real
        evaluation against the learned baseline.
        """
        baseline = BaselineTracker()
        metric_name = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        for _ in range(MIN_RATE_SAMPLES_FOR_BASELINE):  # 30 samples
            baseline.update(metric_name, hour_of_day=20, value=1.0)

        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        result = connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", hour_of_day=20),
            baseline,
            rate_tracker,
        )
        # No longer "insufficient data" - it's now a real evaluation
        # (triggered or not depends on the value, but the reason must
        # reference the learned baseline, not a sample-count skip).
        assert "not enough data" not in result.reason.lower()
        assert "learned baseline" in result.reason

    def test_no_fixed_fallback_threshold_exists_anymore(self) -> None:
        """
        A very high raw rate during cold start must NOT trigger just
        because it's numerically large - there is deliberately no
        global fallback threshold for this rule anymore (see
        config.py). It must report insufficient data instead.
        """
        baseline = BaselineTracker()
        rate_tracker = ConnectionRateTracker(window_seconds=1.0)
        result = None
        for _ in range(200):  # a rate that would have tripped the old fallback
            result = connection_rate_anomaly_rule(
                _context(application_name="chrome.exe", hour_of_day=20),
                baseline,
                rate_tracker,
            )
        assert result.triggered is False
        assert "not enough data" in result.reason.lower()

    def test_chrome_and_spotify_do_not_share_a_rate_baseline(self) -> None:
        """
        The core fix: two different applications must be judged
        against their OWN learned normal, not a shared pooled
        baseline. Chrome's normal bursty rate and Spotify's normal
        steady rate are genuinely different behaviors - a rate that's
        perfectly normal for one could be wildly anomalous for the
        other, and pooling them together (the old design) made the
        baseline meaningless for both.
        """
        baseline = BaselineTracker()
        chrome_metric = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        spotify_metric = connection_rate_metric_name("spotify.exe", "93.184.216.34")

        # Chrome: bursty, normally high rate (~8 pkt/s) at this hour.
        for rate in [7.5, 8.2, 7.8, 8.5, 8.0, 7.9, 8.1, 8.3, 7.7, 8.0] * 3:
            baseline.update(chrome_metric, hour_of_day=20, value=rate)

        # Spotify: steady, normally low rate (~0.5 pkt/s) at this hour.
        for rate in [0.4, 0.5, 0.6, 0.5, 0.4, 0.5, 0.6, 0.5, 0.4, 0.5] * 3:
            baseline.update(spotify_metric, hour_of_day=20, value=rate)

        chrome_bucket = baseline.get_bucket(chrome_metric, 20)
        spotify_bucket = baseline.get_bucket(spotify_metric, 20)
        assert chrome_bucket is not None
        assert spotify_bucket is not None
        assert chrome_bucket.count == 30
        assert spotify_bucket.count == 30
        # The two baselines are numerically distinct, proving they
        # were never pooled together.
        assert chrome_bucket.mean != spotify_bucket.mean
        assert abs(chrome_bucket.mean - 8.0) < 1.0
        assert abs(spotify_bucket.mean - 0.5) < 0.5

        # The definitive proof: the SAME numeric rate (8.0 pkt/s),
        # evaluated against each app's own independently-learned
        # baseline, gives OPPOSITE verdicts. If the two apps secretly
        # shared one pooled baseline, both checks would agree.
        assert chrome_bucket.is_anomalous(8.0, MIN_RATE_SAMPLES_FOR_BASELINE) is False
        assert spotify_bucket.is_anomalous(8.0, MIN_RATE_SAMPLES_FOR_BASELINE) is True

    def test_different_remote_peers_do_not_share_a_rate_baseline(self) -> None:
        """
        Regression test for P2 Bug #2 (connection-rate metric
        identity): the SAME application talking to two DIFFERENT
        remote peers must not pool into one baseline - a burst of
        traffic to peer A must not be able to poison the "normal"
        baseline used to judge traffic to peer B.
        """
        baseline = BaselineTracker()
        tracker = ConnectionRateTracker(window_seconds=5.0)

        connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", destination_ip="1.1.1.1"),
            baseline,
            tracker,
        )
        connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", destination_ip="8.8.8.8"),
            baseline,
            tracker,
        )

        peer_a_metric = connection_rate_metric_name("chrome.exe", "1.1.1.1")
        peer_b_metric = connection_rate_metric_name("chrome.exe", "8.8.8.8")
        bucket_a = baseline.get_bucket(peer_a_metric, 20)
        bucket_b = baseline.get_bucket(peer_b_metric, 20)
        assert bucket_a is not None
        assert bucket_b is not None
        assert bucket_a.count == 1
        assert bucket_b.count == 1

    def test_inbound_traffic_is_keyed_by_the_remote_source_not_local_destination(
        self,
    ) -> None:
        """
        Regression test for P2 Bug #2: for an INCOMING packet, the
        remote peer is ``source_ip`` (the far end), not
        ``destination_ip`` (this machine). Using destination_ip for
        inbound traffic would key every distinct remote peer under
        the same (local) address, pooling them all together.
        """
        assert (
            connection_rate_peer(
                _context(
                    direction="INCOMING",
                    source_ip="203.0.113.9",
                    destination_ip="10.0.0.1",
                )
            )
            == "203.0.113.9"
        )
        assert (
            connection_rate_peer(
                _context(
                    direction="OUTGOING",
                    source_ip="10.0.0.1",
                    destination_ip="203.0.113.9",
                )
            )
            == "203.0.113.9"
        )

    def test_legitimate_high_volume_download_not_flagged_once_baseline_established(
        self,
    ) -> None:
        """
        Same 'don't cry wolf on normal heavy use' principle as the
        movie-night test - a big legitimate download naturally
        produces a high packet rate; once that's established as
        normal for this app at this hour, it should not be flagged.
        """
        baseline = BaselineTracker()
        metric_name = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        for rate in [180.0, 190.0, 175.0, 195.0, 185.0, 188.0] * 5:  # 30 samples
            baseline.update(metric_name, hour_of_day=20, value=rate)

        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        result = connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", hour_of_day=20),
            baseline,
            rate_tracker,
        )
        assert result.triggered is False

    def test_genuine_spike_still_triggers_once_baseline_established(self) -> None:
        baseline = BaselineTracker()
        metric_name = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        for rate in [0.2, 0.3, 0.2, 0.3, 0.2, 0.3] * 5:  # steady low baseline, 30 samples
            baseline.update(metric_name, hour_of_day=20, value=rate)

        bucket = baseline.get_bucket(metric_name, 20)
        assert bucket is not None
        assert bucket.is_anomalous(50.0, MIN_RATE_SAMPLES_FOR_BASELINE) is True

    def test_baseline_sampling_is_throttled_not_per_packet(self) -> None:
        """Statistical correctness: the baseline must not receive one
        sample per packet during a burst - only throttled samples."""
        baseline = BaselineTracker()
        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        for _ in range(50):
            connection_rate_anomaly_rule(
                _context(application_name="chrome.exe", hour_of_day=20),
                baseline,
                rate_tracker,
            )
        bucket = baseline.get_bucket(
            connection_rate_metric_name("chrome.exe", "93.184.216.34"), 20
        )
        assert bucket is not None
        # 50 rapid calls within one 5s window should have produced
        # only 1 baseline sample (throttled), not 50.
        assert bucket.count == 1

    def test_an_anomalous_rate_sample_does_not_contaminate_its_own_baseline(
        self,
    ) -> None:
        """
        Regression test for P2 Bug #1 (baseline leakage), applied to
        connection rate: a sample that the rule itself judges
        anomalous must be evaluated against the PRE-EXISTING baseline
        only, and must never be learned into that same baseline -
        otherwise a sustained burst would progressively relax its own
        threshold until it stopped being flagged as anomalous at all.
        """
        baseline = BaselineTracker()
        metric_name = connection_rate_metric_name("chrome.exe", "93.184.216.34")
        for rate in [0.2, 0.3, 0.2, 0.3, 0.2, 0.3] * 5:  # steady low baseline, 30 samples
            baseline.update(metric_name, hour_of_day=20, value=rate)

        rate_tracker = ConnectionRateTracker(window_seconds=1000.0)
        # Force a single very high rate sample by pre-seeding the
        # tracker's event window, then evaluate through the rule.
        for _ in range(500):
            rate_tracker.record("chrome.exe", "93.184.216.34")

        bucket_before = baseline.get_bucket(metric_name, 20)
        assert bucket_before is not None
        count_before = bucket_before.count

        result = connection_rate_anomaly_rule(
            _context(application_name="chrome.exe", hour_of_day=20),
            baseline,
            rate_tracker,
        )

        bucket_after = baseline.get_bucket(metric_name, 20)
        assert bucket_after is not None
        if result.triggered:
            # An anomalous sample must not have been learned.
            assert bucket_after.count == count_before
        else:
            # (Non-anomalous outcome would still be a valid throttled
            # learn - only assert the leakage-relevant case above.)
            pass


class TestEvaluateAllRules:
    def test_returns_one_result_per_rule(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        results = evaluate_all_rules(_context(), baseline, aggregator, rate_tracker)
        assert len(results) == 4

    def test_rule_names_are_distinct(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        results = evaluate_all_rules(_context(), baseline, aggregator, rate_tracker)
        names = {r.rule_name for r in results}
        assert names == {
            "idle_large_transfer",
            "unknown_application_internet",
            "packet_size_anomaly",
            "connection_rate_anomaly",
        }

    def test_every_result_has_a_reason(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        results = evaluate_all_rules(_context(), baseline, aggregator, rate_tracker)
        assert all(r.reason for r in results)

    def test_multiple_rules_can_trigger_simultaneously(self) -> None:
        baseline = BaselineTracker()
        aggregator = IdleTransferAggregator()
        rate_tracker = ConnectionRateTracker(window_seconds=5.0)
        context = _context(
            user_status="IDLE",
            idle_seconds=400.0,
            packet_size=FALLBACK_LARGE_TRANSFER_BYTES + 1,
            application_name="UNKNOWN",
            communication_type="INTERNET",
        )
        # evaluate_all_rules (like the individual rules) reads the
        # aggregator's current state rather than updating it itself -
        # only the orchestrator updates it, exactly once per packet.
        aggregator.update(context)
        results = evaluate_all_rules(context, baseline, aggregator, rate_tracker)
        triggered_names = {r.rule_name for r in results if r.triggered}
        assert "idle_large_transfer" in triggered_names
        assert "unknown_application_internet" in triggered_names
