import json

from cana_engine.ipc import PIPE_MAX_MESSAGE_BYTES, encode_pipe_response
from cana_engine.client import ControlClient, ControlClientError


def test_large_snapshot_preserves_health_without_mutating_history():
    rows = [{'reason': 'x' * 2000} for _ in range(100)]
    payload = {'ok': True, 'health': {'capture_alive': True}, 'alerts': rows,
               'correlated': rows, 'risk': []}
    raw = encode_pipe_response(payload)
    result = json.loads(raw)
    assert len(raw) <= PIPE_MAX_MESSAGE_BYTES
    assert result['ok'] and result['health']['capture_alive']
    assert result['history_truncated']
    assert len(payload['alerts']) == 100


def test_older_service_oversized_snapshot_falls_back_to_live_status(monkeypatch):
    client = ControlClient.__new__(ControlClient)
    def request(command):
        if command == 'snapshot':
            raise ControlClientError('response too large')
        return {'ok': True, 'health': {'capture_alive': True}}
    monkeypatch.setattr(client, '_pipe_request', request)
    result = client.snapshot()
    assert result['health']['capture_alive']
    assert result['history_truncated']
