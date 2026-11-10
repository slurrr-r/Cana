"""Unit tests for anomaly_detection.baseline."""

from __future__ import annotations

import pytest

from anomaly_detection.baseline import BaselineSummary, BaselineTracker, HourBucket
from anomaly_detection.config import MIN_OBSERVATIONS_FOR_BASELINE


class TestHourBucketStatistics:
    def test_empty_bucket_mean_is_zero(self) -> None:
        bucket = HourBucket()
        assert bucket.mean == 0.0
        assert bucket.count == 0

    def test_single_observation(self) -> None:
        bucket = HourBucket()
        bucket.update(100.0)
        assert bucket.count == 1
        assert bucket.mean == 100.0
        assert bucket.variance == 0.0  # need >= 2 for variance

    def test_mean_computed_correctly(self) -> None:
        bucket = HourBucket()
        for value in [10.0, 20.0, 30.0]:
            bucket.update(value)
        assert bucket.mean == pytest.approx(20.0)

    def test_std_dev_computed_correctly(self) -> None:
        bucket = HourBucket()
        # Known values with population roughly: mean=5, sample std_dev ~ 2.0
        for value in [3.0, 4.0, 5.0, 6.0, 7.0]:
            bucket.update(value)
        assert bucket.mean == pytest.approx(5.0)
        assert bucket.std_dev == pytest.approx(1.5811, rel=1e-3)

    def test_is_established_false_below_threshold(self) -> None:
        bucket = HourBucket()
        for _ in range(MIN_OBSERVATIONS_FOR_BASELINE - 1):
            bucket.update(100.0)
        assert bucket.is_established() is False

    def test_is_established_true_at_threshold(self) -> None:
        bucket = HourBucket()
        for _ in range(MIN_OBSERVATIONS_FOR_BASELINE):
            bucket.update(100.0)
        assert bucket.is_established() is True

    def test_is_anomalous_false_when_not_established(self) -> None:
        bucket = HourBucket()
        bucket.update(100.0)  # only 1 observation
        assert bucket.is_anomalous(999999.0) is False

    def test_is_anomalous_true_for_extreme_outlier(self) -> None:
        bucket = HourBucket()
        # Establish a tight baseline around 100.
        for value in [98.0, 99.0, 100.0, 101.0, 102.0, 100.0]:
            bucket.update(value)
        assert bucket.is_anomalous(100000.0) is True

    def test_is_anomalous_false_for_normal_variation(self) -> None:
        bucket = HourBucket()
        for value in [95.0, 98.0, 100.0, 102.0, 105.0, 100.0]:
            bucket.update(value)
        assert bucket.is_anomalous(103.0) is False

    def test_is_anomalous_handles_zero_variance(self) -> None:
        bucket = HourBucket()
        for _ in range(MIN_OBSERVATIONS_FOR_BASELINE):
            bucket.update(50.0)  # identical values -> zero std_dev
        assert bucket.is_anomalous(50.0) is False
        assert bucket.is_anomalous(500.0) is True


class TestBaselineTrackerUpdateAndQuery:
    def test_update_and_get_bucket(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", hour_of_day=14, value=1000.0)
        bucket = tracker.get_bucket("packet_size", 14)
        assert bucket is not None
        assert bucket.count == 1

    def test_get_bucket_returns_none_for_unknown_metric(self) -> None:
        tracker = BaselineTracker()
        assert tracker.get_bucket("nonexistent_metric", 10) is None

    def test_separate_hours_tracked_independently(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", hour_of_day=9, value=1000.0)
        tracker.update("packet_size", hour_of_day=20, value=5000.0)

        morning = tracker.get_bucket("packet_size", 9)
        evening = tracker.get_bucket("packet_size", 20)
        assert morning.mean == 1000.0
        assert evening.mean == 5000.0

    def test_separate_metrics_tracked_independently(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", hour_of_day=10, value=1000.0)
        tracker.update("idle_transfer_bytes", hour_of_day=10, value=99999.0)

        packet_bucket = tracker.get_bucket("packet_size", 10)
        idle_bucket = tracker.get_bucket("idle_transfer_bytes", 10)
        assert packet_bucket.mean == 1000.0
        assert idle_bucket.mean == 99999.0

    def test_invalid_hour_raises(self) -> None:
        tracker = BaselineTracker()
        with pytest.raises(ValueError):
            tracker.update("packet_size", hour_of_day=24, value=100.0)
        with pytest.raises(ValueError):
            tracker.update("packet_size", hour_of_day=-1, value=100.0)

    def test_reset_clears_all_data(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", hour_of_day=10, value=1000.0)
        tracker.reset()
        assert tracker.get_bucket("packet_size", 10) is None


class TestBaselineTrackerIsAnomalous:
    def test_returns_false_for_cold_start(self) -> None:
        tracker = BaselineTracker()
        tracker.update("data_volume", hour_of_day=20, value=500.0)  # only 1 obs
        assert tracker.is_anomalous("data_volume", 20, 999999.0) is False

    def test_the_movie_night_scenario(self) -> None:
        """
        The exact scenario from the project discussion: after enough
        evenings of established "normal" large evening data transfer,
        a similarly large transfer should NOT be flagged as anomalous
        just because it's large in absolute terms - it's normal FOR
        THIS TIME OF DAY on this machine.
        """
        tracker = BaselineTracker()
        # Simulate several evenings of ~150MB streaming sessions at 8pm.
        for volume_mb in [140, 155, 148, 160, 152, 145]:
            tracker.update("idle_transfer_bytes", hour_of_day=20, value=volume_mb)

        # Tonight's movie: also ~150MB at 8pm - should be normal now.
        assert tracker.is_anomalous("idle_transfer_bytes", 20, 150) is False

        # But a genuinely huge, unprecedented transfer should still stand out.
        assert tracker.is_anomalous("idle_transfer_bytes", 20, 5000) is True

    def test_same_volume_flagged_at_different_hour_with_different_baseline(
        self,
    ) -> None:
        """
        The same numeric value can be normal at one hour and anomalous
        at another, since each hour has its own independently learned
        baseline - this is the whole point of hour-bucketing.
        """
        tracker = BaselineTracker()
        # 3am: normally near-zero background traffic.
        for value in [1.0, 2.0, 1.5, 1.0, 2.0, 1.0]:
            tracker.update("idle_transfer_bytes", hour_of_day=3, value=value)
        # 8pm: normally large (streaming).
        for value in [140.0, 155.0, 148.0, 160.0, 152.0, 145.0]:
            tracker.update("idle_transfer_bytes", hour_of_day=20, value=value)

        # 150 units is normal at 8pm but wildly anomalous at 3am.
        assert tracker.is_anomalous("idle_transfer_bytes", 20, 150.0) is False
        assert tracker.is_anomalous("idle_transfer_bytes", 3, 150.0) is True


class TestHourBucketSerialization:
    def test_state_round_trip_preserves_statistics(self) -> None:
        bucket = HourBucket()
        for value in [10.0, 20.0, 30.0, 40.0]:
            bucket.update(value)

        rebuilt = HourBucket.from_state(*bucket.to_state())

        assert rebuilt.count == bucket.count
        assert rebuilt.mean == bucket.mean
        assert rebuilt.variance == bucket.variance
        assert rebuilt.std_dev == bucket.std_dev

    def test_rebuilt_bucket_resumes_welford_exactly(self) -> None:
        """
        The core persistence guarantee at the bucket level: continuing to
        update a rebuilt bucket must match an uninterrupted one. Welford's
        recurrence depends only on (count, mean, m2), so it can.
        """
        values = [3.0, 17.0, 8.5, 42.0, 1.25, 99.0, 6.0]

        uninterrupted = HourBucket()
        for value in values:
            uninterrupted.update(value)

        interrupted = HourBucket()
        for value in values[:3]:
            interrupted.update(value)
        resumed = HourBucket.from_state(*interrupted.to_state())
        for value in values[3:]:
            resumed.update(value)

        assert resumed.count == uninterrupted.count
        assert resumed.mean == pytest.approx(uninterrupted.mean, rel=1e-12)
        assert resumed.std_dev == pytest.approx(uninterrupted.std_dev, rel=1e-12)

    def test_empty_bucket_state_round_trips(self) -> None:
        rebuilt = HourBucket.from_state(*HourBucket().to_state())
        assert rebuilt.count == 0
        assert rebuilt.mean == 0.0
        assert rebuilt.is_established() is False

    def test_impossible_state_is_rejected(self) -> None:
        """
        A negative count or m2 cannot arise from a real observation
        stream, so it means the stored state is corrupt. Rejecting it
        here beats accepting it and producing a math.sqrt domain error
        later, deep inside a rule evaluation.
        """
        with pytest.raises(ValueError):
            HourBucket.from_state(-1, 10.0, 5.0)
        with pytest.raises(ValueError):
            HourBucket.from_state(5, 10.0, -0.5)


class TestBaselineTrackerSnapshot:
    def test_snapshot_of_an_empty_tracker_is_empty(self) -> None:
        assert BaselineTracker().snapshot() == {}

    def test_snapshot_omits_hours_with_no_observations(self) -> None:
        """
        A metric allocates all 24 hour buckets on first update, but a
        session typically touches one or two. Persisting 22 zero rows per
        metric would be pure noise.
        """
        tracker = BaselineTracker()
        tracker.update("packet_size", 5, 100.0)

        snapshot = tracker.snapshot()
        assert list(snapshot) == ["packet_size"]
        assert list(snapshot["packet_size"]) == [5]

    def test_snapshot_returns_plain_tuples_not_live_buckets(self) -> None:
        """
        The checkpointer thread holds whatever snapshot() returns while
        the capture thread keeps updating. Returning tuples means a saved
        snapshot can never change underneath it.
        """
        tracker = BaselineTracker()
        tracker.update("packet_size", 5, 100.0)
        snapshot = tracker.snapshot()

        tracker.update("packet_size", 5, 900.0)

        assert snapshot["packet_size"][5] == (1, 100.0, 0.0)
        assert isinstance(snapshot["packet_size"][5], tuple)


class TestBaselineTrackerRestore:
    def test_restore_replaces_existing_state(self) -> None:
        tracker = BaselineTracker()
        tracker.update("stale_metric", 1, 5.0)

        tracker.restore({"packet_size": {7: (3, 200.0, 800.0)}})

        assert tracker.get_bucket("stale_metric", 1) is None
        assert tracker.get_bucket("packet_size", 7).count == 3

    def test_restore_mirrors_update_allocation_semantics(self) -> None:
        """
        get_bucket distinguishes "this metric has never been seen"
        (None) from "seen, but not at this hour" (a zero-count bucket),
        and the rules branch differently on the two. Restoring only the
        persisted hours would silently change which reason string a user
        sees, so restore allocates all 24 buckets exactly as update does.
        """
        restored = BaselineTracker()
        restored.restore({"packet_size": {7: (3, 200.0, 800.0)}})

        live = BaselineTracker()
        live.update("packet_size", 7, 200.0)

        for tracker in (restored, live):
            # Unseen hour of a KNOWN metric: a real, empty bucket.
            unseen_hour = tracker.get_bucket("packet_size", 13)
            assert unseen_hour is not None
            assert unseen_hour.count == 0
            assert unseen_hour.is_established() is False
            # Unknown metric entirely: None.
            assert tracker.get_bucket("never_seen", 7) is None

    def test_restored_baseline_can_immediately_judge_traffic(self) -> None:
        """
        The user-visible payoff of persistence: a restored baseline is
        established straight away, so a baseline-dependent rule can judge
        the very first packet of a run instead of reporting "not enough
        data yet".
        """
        tracker = BaselineTracker()
        tracker.restore(
            {"packet_size": {9: (MIN_OBSERVATIONS_FOR_BASELINE, 500.0, 400.0)}}
        )

        assert tracker.get_bucket("packet_size", 9).is_established() is True
        assert tracker.is_anomalous("packet_size", 9, 500.0) is False
        assert tracker.is_anomalous("packet_size", 9, 50_000.0) is True

    def test_restore_rejects_out_of_range_hours(self) -> None:
        tracker = BaselineTracker()
        with pytest.raises(ValueError):
            tracker.restore({"packet_size": {24: (1, 1.0, 0.0)}})
        with pytest.raises(ValueError):
            tracker.restore({"packet_size": {-1: (1, 1.0, 0.0)}})

    def test_restore_rejects_impossible_bucket_state(self) -> None:
        tracker = BaselineTracker()
        with pytest.raises(ValueError):
            tracker.restore({"packet_size": {5: (1, 1.0, -3.0)}})

    def test_restoring_an_empty_snapshot_is_a_clean_cold_start(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", 5, 100.0)

        tracker.restore({})

        assert tracker.snapshot() == {}
        assert tracker.get_bucket("packet_size", 5) is None

    def test_snapshot_restore_snapshot_is_a_fixed_point(self) -> None:
        tracker = BaselineTracker()
        tracker.update("packet_size", 5, 100.0)
        tracker.update("packet_size", 5, 300.0)
        tracker.update("idle_transfer_bytes", 22, 9_000.0)

        original = tracker.snapshot()
        round_tripped = BaselineTracker()
        round_tripped.restore(original)

        assert round_tripped.snapshot() == original


class TestBaselineSummary:
    def test_summary_of_an_empty_tracker_reports_a_cold_start(self) -> None:
        summary = BaselineTracker().summary()
        assert summary == BaselineSummary(0, 0, 0)
        assert summary.is_empty is True

    def test_summary_counts_only_established_buckets(self) -> None:
        """
        established_bucket_count is the number that matters at startup: an
        un-established bucket cannot fire a rule, so reporting raw bucket
        counts would overstate how ready the detector actually is.
        """
        tracker = BaselineTracker()
        # Hour 8 reaches the threshold; hour 9 deliberately does not.
        for _ in range(MIN_OBSERVATIONS_FOR_BASELINE):
            tracker.update("packet_size", 8, 100.0)
        tracker.update("packet_size", 9, 100.0)
        tracker.update("idle_transfer_bytes", 20, 5.0)

        summary = tracker.summary()

        assert summary.metric_count == 2
        assert summary.established_bucket_count == 1
        assert summary.total_observations == MIN_OBSERVATIONS_FOR_BASELINE + 2
        assert summary.is_empty is False

    def test_summary_survives_a_snapshot_restore_cycle(self) -> None:
        tracker = BaselineTracker()
        for hour in (6, 18):
            for _ in range(MIN_OBSERVATIONS_FOR_BASELINE + 1):
                tracker.update("packet_size", hour, 100.0)

        restored = BaselineTracker()
        restored.restore(tracker.snapshot())

        assert restored.summary() == tracker.summary()
