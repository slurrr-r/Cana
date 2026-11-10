from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
import queue

import pytest

from anomaly_detection.context import build_context_record
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.rules import RuleResult
from cana_engine.handler import build_packet_handler
from cana_ui.incidents import build_incidents
from packet_capture.capture import PacketCaptureEngine
from risk_scoring.correlator import AlertCorrelator
from risk_scoring.scorer import RiskScorer


def result(**changes):
    packet = dict(protocol='TCP', source_ip='10.0.0.1', destination_ip='8.8.8.8',
                  direction='OUTGOING', application_name='test.exe', packet_size=60)
    packet.update(changes)
    return RuleResult('test', True, 'MEDIUM', 'test evidence', build_context_record(packet))


def test_async_sniffer_exception_reaches_error_handler(monkeypatch):
    class Failed:
        def __init__(self, **kwargs):
            self.thread = SimpleNamespace(is_alive=lambda: False)
        def start(self): pass
        def join(self, **kwargs): raise OSError('Npcap unavailable')
    monkeypatch.setattr('scapy.all.AsyncSniffer', Failed)
    errors = []
    engine = PacketCaptureEngine(SimpleNamespace(interface_name='fake', display_name='fake', packet_filter='ALL'), queue.Queue(), errors.append)
    engine._run()
    assert len(errors) == 1 and 'Npcap unavailable' in str(errors[0])


def test_service_disables_activity_without_starting_listener(monkeypatch):
    from cana_engine.engine import CANAEngine
    tracker = Mock()
    monkeypatch.setattr('cana_engine.engine.ActivityTracker', tracker)
    engine = CANAEngine(track_user_activity=False)
    assert engine._start_activity_tracker() is None
    tracker.assert_not_called()
    from cana_service.service import CANAServiceRuntime
    factory = Mock()
    monkeypatch.setattr('cana_engine.engine.CANAEngine', factory)
    runtime = CANAServiceRuntime()
    monkeypatch.setattr(runtime, '_start_pipe', lambda: None)
    monkeypatch.setattr(runtime, '_start_engine', lambda: None)
    runtime.start()
    assert factory.call_args.kwargs['track_user_activity'] is False


def test_normal_packet_sizes_adapt_without_security_alerts():
    orchestrator = AnomalyDetectionOrchestrator()
    store, risk, correlator = Mock(), RiskScorer(), AlertCorrelator()
    handler = build_packet_handler(orchestrator, None, store=store, risk_scorer=risk,
                                   correlator=correlator, print_alerts=False)
    packet = result().context.to_dict()
    for size in [60] * 5 + [1500] * 20:
        handler(dict(packet, packet_size=size))
    store.record_alert.assert_not_called()
    assert not risk.snapshot().applications
    bucket = orchestrator.baseline.get_bucket('packet_size', result().context.hour_of_day)
    assert bucket.count == 25 and bucket.mean > 1000


def test_concurrent_risk_record_and_snapshot_are_consistent():
    scorer = RiskScorer(max_entities=2048)
    def record():
        for index in range(1000):
            scorer.record(result(application_name=f'app{index}'), now=0)
    def snapshot():
        for _ in range(100):
            state = scorer.snapshot(now=0)
            assert sum(e.events for e in state.applications) == sum(e.events for e in state.destinations)
    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = [executor.submit(record), executor.submit(snapshot)]
        for job in jobs: job.result()
    assert sum(e.events for e in scorer.snapshot(now=0).applications) == 1000


def test_inbound_risk_uses_remote_peer():
    scorer = RiskScorer()
    scorer.record(result(direction='INCOMING', source_ip='8.8.8.8', destination_ip='10.0.0.1'), now=0)
    assert scorer.snapshot(now=0).destinations[0].name == '8.8.8.8'


def test_correlation_expires_other_peers_and_caps_bursts():
    correlator = AlertCorrelator(window_seconds=5)
    for index in range(100):
        correlator.observe(result(destination_ip=str(index)), now=index * 10)
    assert correlator.open_count == 1
    correlator.max_groups = 4
    for index in range(100):
        correlator.observe(result(destination_ip=str(index)), now=1000)
    assert correlator.open_count == 4
    for _ in range(300): correlator.observe(result(), now=1000)
    assert max(len(g.signals) for g in correlator._open.values()) <= 256


def test_unrelated_correlation_does_not_close_incident():
    alert = dict(rule_name='test', application_name='test.exe', direction='INCOMING',
                 source_ip='8.8.8.8', destination_ip='10.0.0.1', triggered_at_epoch=100)
    window = dict(application_name='test.exe', destination_ip='8.8.8.8', rule_names=['test'],
                  started_at_epoch=99, ended_at_epoch=101)
    assert build_incidents([alert], [window], now=200)[0].status == 'Window closed'
    for changes in ({'application_name': 'other'}, {'destination_ip': '1.1.1.1'}, {'rule_names': ['other']}):
        assert build_incidents([alert], [dict(window, **changes)], now=200)[0].status == 'Unknown'


def test_native_pipe_read_timeout_is_cancelled_and_next_read_works():
    win32file = pytest.importorskip('win32file')
    win32pipe = pytest.importorskip('win32pipe')
    pywintypes = pytest.importorskip('pywintypes')
    import uuid
    from cana_engine.ipc import _overlapped_pipe_io
    name = r'\\.\pipe\CANA-audit-test-' + uuid.uuid4().hex
    server = win32pipe.CreateNamedPipe(name, win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT, 1, 65536, 65536, 1000, None)
    client = None
    try:
        client = win32file.CreateFile(name, win32file.GENERIC_READ | win32file.GENERIC_WRITE, 0, None, win32file.OPEN_EXISTING, 0, None)
        _overlapped_pipe_io(win32file, pywintypes, server, 'connect', timeout_ms=1000)
        with pytest.raises(TimeoutError):
            _overlapped_pipe_io(win32file, pywintypes, server, 'read', timeout_ms=30)
        win32file.WriteFile(client, b'next request')
        assert _overlapped_pipe_io(win32file, pywintypes, server, 'read', timeout_ms=1000) == b'next request'
        _overlapped_pipe_io(win32file, pywintypes, server, 'write', b'response', timeout_ms=1000)
        assert win32file.ReadFile(client, 100)[1] == b'response'
        with pytest.raises(TimeoutError):
            _overlapped_pipe_io(win32file, pywintypes, server, 'write', b'x' * 262144, timeout_ms=30)
    finally:
        if client is not None: win32file.CloseHandle(client)
        win32file.CloseHandle(server)


def test_native_server_recovers_after_silent_client(monkeypatch):
    win32file = pytest.importorskip('win32file')
    win32pipe = pytest.importorskip('win32pipe')
    win32security = pytest.importorskip('win32security')
    import uuid
    from cana_engine import ipc, pipe
    token = win32security.OpenProcessToken(__import__('win32api').GetCurrentProcess(), 8)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    name = r'\\.\pipe\CANA-server-test-' + uuid.uuid4().hex
    monkeypatch.setattr(pipe, 'PIPE_NAME', name)
    monkeypatch.setattr(ipc, 'PIPE_NAME', name)
    monkeypatch.setattr(pipe, 'PIPE_IO_TIMEOUT_MS', 200)
    handler = SimpleNamespace(handle=lambda *args, **kwargs: {'ok': True, 'test': 'response'})
    server = pipe.NamedPipeServer(handler, [sid])
    silent = None
    try:
        server.start()
        import time
        deadline = time.monotonic() + 2
        while True:
            try:
                win32pipe.WaitNamedPipe(name, 100)
                break
            except Exception:
                if time.monotonic() >= deadline: raise
                time.sleep(0.01)
        silent = win32file.CreateFile(name, win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None)
        assert ipc._windows_pipe_request('status', {}, timeout=2)['test'] == 'response'
        assert ipc._windows_pipe_request('status', {}, timeout=2)['ok']
    finally:
        if silent is not None: win32file.CloseHandle(silent)
        server.stop()
        server.join(timeout=2)
