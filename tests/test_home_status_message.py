from types import SimpleNamespace

import pytest

from cana_ui.window import CANAWindow


@pytest.mark.parametrize('text', [
    'Monitoring starting...', 'Monitoring stopped.', 'Checking monitoring status...',
])
def test_active_capture_clears_stale_progress(text):
    window = CANAWindow.__new__(CANAWindow)
    window._widgets = {'message': SimpleNamespace(cget=lambda _: text)}
    messages = []
    window._show_message = lambda text, *args: messages.append(text)
    window._sync_status_message(
        {'monitoring': 'running', 'capture': 'running'}, {'last_error': ''})
    assert messages == ['']


def test_starting_message_remains_until_capture_is_ready():
    window = CANAWindow.__new__(CANAWindow)
    window._widgets = {'message': SimpleNamespace(cget=lambda _: 'Monitoring starting...')}
    messages = []
    window._show_message = lambda text, *args: messages.append(text)
    window._sync_status_message({'monitoring': 'starting'}, {})
    assert messages == ['Monitoring starting...']


def test_active_capture_does_not_clear_unrelated_error():
    window = CANAWindow.__new__(CANAWindow)
    window._widgets = {'message': SimpleNamespace(cget=lambda _: 'Could not save settings.')}
    messages = []
    window._show_message = lambda text, *args: messages.append(text)
    window._sync_status_message({'monitoring': 'running', 'capture': 'running'}, {})
    assert messages == []
