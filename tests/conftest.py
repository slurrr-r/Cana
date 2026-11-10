"""Keep unit-test service configuration out of the installed app's data."""

import pytest


@pytest.fixture(autouse=True)
def isolate_windows_programdata(request, monkeypatch, tmp_path):
    if request.node.path.name == 'test_windows_acceptance.py':
        return
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'ProgramData'))
