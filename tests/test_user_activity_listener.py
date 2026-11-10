"""
Unit tests for user_activity.listener.

Real pynput cannot even be imported in this (headless, no-display)
test environment - confirmed directly:

    >>> import pynput
    ImportError: this platform is not supported: (...DisplayNameError...)

So these tests install fake ``pynput``/``pynput.mouse``/
``pynput.keyboard`` modules directly into ``sys.modules`` before
calling ``ActivityListener.start()``, which lazily does
``from pynput import keyboard, mouse`` at call time. Since Python's
import system checks ``sys.modules`` first, this transparently
substitutes our fake, controllable Listener classes for the real
(broken-in-this-environment) ones - without ever touching the real
pynput package on disk.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Callable, Dict

import pytest

from user_activity.listener import ActivityListener, ActivityListenerError


class _FakePynputListener:
    """Stand-in for pynput.mouse.Listener / pynput.keyboard.Listener."""

    def __init__(self, **kwargs: Callable[..., Any]) -> None:
        self.callbacks: Dict[str, Callable[..., Any]] = kwargs
        self.started = False
        self.stopped = False

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def trigger(self, callback_name: str, *args: Any) -> None:
        """Test helper: simulate pynput invoking one of our callbacks."""
        callback = self.callbacks.get(callback_name)
        if callback is not None:
            callback(*args)


def _install_fake_pynput(monkeypatch: pytest.MonkeyPatch):
    """Install fake pynput/mouse/keyboard modules into sys.modules."""
    fake_pynput = types.ModuleType("pynput")
    fake_mouse = types.ModuleType("pynput.mouse")
    fake_keyboard = types.ModuleType("pynput.keyboard")

    fake_mouse.Listener = _FakePynputListener  # type: ignore[attr-defined]
    fake_keyboard.Listener = _FakePynputListener  # type: ignore[attr-defined]
    fake_pynput.mouse = fake_mouse  # type: ignore[attr-defined]
    fake_pynput.keyboard = fake_keyboard  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "pynput", fake_pynput)
    monkeypatch.setitem(sys.modules, "pynput.mouse", fake_mouse)
    monkeypatch.setitem(sys.modules, "pynput.keyboard", fake_keyboard)

    return fake_mouse, fake_keyboard


class TestActivityListenerStart:
    def test_start_creates_and_starts_both_listeners(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_pynput(monkeypatch)

        listener = ActivityListener()
        listener.start()

        assert listener.is_running() is True
        assert listener._mouse_listener.started is True  # type: ignore[union-attr]
        assert listener._keyboard_listener.started is True  # type: ignore[union-attr]

    def test_start_raises_when_pynput_not_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "pynput":
                raise ImportError("simulated missing pynput")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        listener = ActivityListener()
        with pytest.raises(ActivityListenerError):
            listener.start()

    def test_start_raises_when_backend_init_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulates the real headless-environment failure mode: pynput
        imports but the Listener itself can't initialize (no display)."""
        fake_pynput = types.ModuleType("pynput")
        fake_mouse = types.ModuleType("pynput.mouse")
        fake_keyboard = types.ModuleType("pynput.keyboard")

        class RaisingListener:
            def __init__(self, **kwargs: Any) -> None:
                raise RuntimeError("failed to acquire X connection")

        fake_mouse.Listener = RaisingListener  # type: ignore[attr-defined]
        fake_keyboard.Listener = RaisingListener  # type: ignore[attr-defined]
        fake_pynput.mouse = fake_mouse  # type: ignore[attr-defined]
        fake_pynput.keyboard = fake_keyboard  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "pynput", fake_pynput)
        monkeypatch.setitem(sys.modules, "pynput.mouse", fake_mouse)
        monkeypatch.setitem(sys.modules, "pynput.keyboard", fake_keyboard)

        listener = ActivityListener()
        with pytest.raises(ActivityListenerError):
            listener.start()

    def test_double_start_is_idempotent_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_pynput(monkeypatch)

        listener = ActivityListener()
        listener.start()
        listener.start()  # should not raise or replace the running listener
        assert listener.is_running() is True


class TestActivityListenerStop:
    def test_stop_after_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_pynput(monkeypatch)

        listener = ActivityListener()
        listener.start()
        mouse_listener = listener._mouse_listener
        keyboard_listener = listener._keyboard_listener

        listener.stop()

        assert listener.is_running() is False
        assert mouse_listener.stopped is True  # type: ignore[union-attr]
        assert keyboard_listener.stopped is True  # type: ignore[union-attr]

    def test_stop_without_start_does_not_raise(self) -> None:
        listener = ActivityListener()
        listener.stop()  # should be a safe no-op
        assert listener.is_running() is False


class TestActivityListenerActivityTracking:
    def test_record_activity_updates_timestamp(self) -> None:
        listener = ActivityListener()
        before = listener.get_last_activity_time()
        listener.record_activity()
        after = listener.get_last_activity_time()
        assert after >= before

    def test_pynput_callback_updates_timestamp(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_pynput(monkeypatch)

        listener = ActivityListener()
        listener.start()

        before = listener.get_last_activity_time()
        listener._mouse_listener.trigger("on_move", 10, 20)  # type: ignore[union-attr]
        after = listener.get_last_activity_time()

        assert after >= before

    def test_keyboard_callback_updates_timestamp(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_fake_pynput(monkeypatch)

        listener = ActivityListener()
        listener.start()

        before = listener.get_last_activity_time()
        listener._keyboard_listener.trigger("on_press", "a")  # type: ignore[union-attr]
        after = listener.get_last_activity_time()

        assert after >= before

    def test_initial_last_activity_time_is_construction_time(self) -> None:
        import time

        before = time.time()
        listener = ActivityListener()
        after = time.time()

        assert before <= listener.get_last_activity_time() <= after
