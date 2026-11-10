"""
Unit tests for risk_scoring.notifier (best-effort alert channels).
"""

from __future__ import annotations

from risk_scoring.correlator import CorrelatedAlert
from risk_scoring.notifier import AlertNotifier, DesktopNotifier


def _alert() -> CorrelatedAlert:
    return CorrelatedAlert(
        alert_id="abc",
        started_at=1000.0,
        ended_at=1001.0,
        application_name="chrome.exe",
        destination_ip="93.184.216.34",
        rule_names=("connection_rate_anomaly",),
        signal_count=2,
        severity="HIGH",
        score=6.0,
        confidence=0.75,
        reason="2 suspicious signal(s) for chrome.exe -> 93.184.216.34.",
    )


class _FakePlyer:
    class _Notification:
        def __init__(self):
            self.calls = []

        def notify(self, **kwargs):
            self.calls.append(kwargs)

    def __init__(self):
        self.notification = self._Notification()


class TestDesktopNotifierUnavailable:
    def test_available_false_when_disabled(self) -> None:
        notifier = DesktopNotifier(enabled=False)
        notifier._plyer = _FakePlyer()
        assert notifier.available is False
        assert notifier.notify("t", "m") is False

    def test_available_false_when_plyer_missing(self) -> None:
        notifier = DesktopNotifier()
        notifier._plyer = None
        assert notifier.available is False
        assert notifier.notify("t", "m") is False
        assert notifier.notify_alert(_alert()) is False


class TestDesktopNotifierAvailable:
    def test_notify_dispatches_when_available(self) -> None:
        notifier = DesktopNotifier(cooldown_seconds=0.0)
        fake = _FakePlyer()
        notifier._plyer = fake
        assert notifier.notify("hello", "world") is True
        assert len(fake.notification.calls) == 1
        assert fake.notification.calls[0]["title"] == "hello"
        assert fake.notification.calls[0]["message"] == "world"

    def test_cooldown_blocks_repeats_of_same_title(self) -> None:
        notifier = DesktopNotifier(cooldown_seconds=60.0)
        fake = _FakePlyer()
        notifier._plyer = fake
        assert notifier.notify("t", "m1") is True
        assert notifier.notify("t", "m2") is False
        assert len(fake.notification.calls) == 1

    def test_cooldown_allows_different_titles(self) -> None:
        notifier = DesktopNotifier(cooldown_seconds=60.0)
        fake = _FakePlyer()
        notifier._plyer = fake
        notifier.notify("t1", "m")
        assert notifier.notify("t2", "m") is True
        assert len(fake.notification.calls) == 2

    def test_notify_alert_builds_title_and_message(self) -> None:
        notifier = DesktopNotifier(cooldown_seconds=0.0)
        fake = _FakePlyer()
        notifier._plyer = fake
        assert notifier.notify_alert(_alert()) is True
        call = fake.notification.calls[0]
        assert "HIGH" in call["title"]
        assert "chrome.exe" in call["title"]
        assert call["message"] == _alert().reason

    def test_notify_swallows_exceptions_once(self) -> None:
        class _Boom:
            class _Notification:
                def notify(self, **kwargs):
                    raise RuntimeError("no display")

        notifier = DesktopNotifier(cooldown_seconds=0.0)
        notifier._plyer = _Boom()
        assert notifier.notify("t", "m") is False
        assert notifier._failed is True
        # Subsequent calls short-circuit without raising.
        assert notifier.notify("t", "m") is False


class TestAlertNotifierHub:
    def test_no_channels_returns_false(self) -> None:
        hub = AlertNotifier()
        assert hub.notify(_alert()) is False

    def test_returns_true_when_any_channel_dispatches(self) -> None:
        class _Stub:
            def __init__(self, ok):
                self.ok = ok

            def notify_alert(self, alert):
                return self.ok

        hub = AlertNotifier(channels=[_Stub(False), _Stub(True)])
        assert hub.notify(_alert()) is True

    def test_add_channel_works(self) -> None:
        class _Stub:
            def notify_alert(self, alert):
                return True

        hub = AlertNotifier()
        assert hub.channels == []
        hub.add_channel(_Stub())
        assert len(hub.channels) == 1

    def test_raising_channel_does_not_propagate(self) -> None:
        class _Boom:
            def notify_alert(self, alert):
                raise RuntimeError("boom")

        hub = AlertNotifier(channels=[_Boom()])
        assert hub.notify(_alert()) is False
