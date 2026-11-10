"""
engine.py
=========

Programmatic CANA monitoring engine.

``CANAEngine.start()`` / ``stop()`` / ``status()`` are the service
boundary. The CLI and the Windows service both drive this class. Capture
threads live here, not in the UI.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Dict, Optional, Set

from anomaly_detection.baseline import BaselineTracker
from anomaly_detection.checkpointer import BaselineCheckpointer
from anomaly_detection.orchestrator import AnomalyDetectionOrchestrator
from anomaly_detection.store import BaselineStore
from cana_engine.capture_lock import (
    CaptureLockError,
    acquire_capture_lock,
    release_capture_lock,
)
from cana_engine.config import (
    CANAConfig,
    WATCHDOG_INTERVAL_SECONDS,
    WATCHDOG_MAX_RAPID_RESTARTS,
    WATCHDOG_RAPID_WINDOW_SECONDS,
    WATCHDOG_RESTART_DELAY_SECONDS,
    load_config,
)
from cana_engine.handler import build_packet_handler
from cana_engine.health import (
    DISPLAY_STATES,
    STATE_STOPPING,
    EngineStatus,
    HealthSnapshot,
    derive_ui_state,
)
from cana_engine.logging_setup import configure_service_logging, log_lifecycle
from packet_capture.app_mapper import ApplicationMapper, UNKNOWN_APPLICATION
from packet_capture.capture import start_packet_capture
from packet_capture.config import CaptureSettings
from packet_capture.interface import (
    InterfaceDetectionError,
    InterfaceSelectionError,
    detect_interfaces,
    get_all_local_ips,
    resolve_interface,
)
from packet_capture.session import SessionManager
from packet_capture.statistics import StatisticsManager
from risk_scoring.checkpointer import RiskCheckpointer
from risk_scoring.correlator import AlertCorrelator
from risk_scoring.notifier import AlertNotifier, DesktopNotifier
from risk_scoring.scorer import RiskScorer
from risk_scoring.store import RiskStore
from user_activity.listener import ActivityListenerError
from user_activity.tracker import ActivityTracker

_capture_guard = threading.Lock()
_active_capture_engines = 0
_capture_guard_token = None
_capture_lock_token = None


def _is_dependency_error(exc: Any) -> bool:
    text = str(exc).lower()
    markers = ("npcap", "winpcap", "libpcap", "packet-capture dependency")
    return any(marker in text for marker in markers)


class CANAEngine:
    """Owns capture, detection, persistence, health, and recovery."""

    def __init__(
        self,
        config: Optional[CANAConfig] = None,
        *,
        capture_runner: Optional[Callable[..., list]] = None,
        interface_detector: Optional[Callable[..., list]] = None,
        print_alerts: Optional[bool] = None,
        track_user_activity: bool = True,
    ) -> None:
        self._config = config if config is not None else load_config()
        self._track_user_activity = track_user_activity
        self._config.validate()
        self._capture_runner = capture_runner or start_packet_capture
        self._interface_detector = interface_detector or detect_interfaces
        self._print_alerts = (
            self._config.print_summaries if print_alerts is None else print_alerts
        )

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._watchdog_stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._watchdog: Optional[threading.Thread] = None
        self._config_apply_lock = threading.Lock()
        self._capture_engine: Optional[Any] = None
        self._started_at: Optional[float] = None
        self._last_packet_at: Optional[float] = None
        self._last_checkpoint_at: Optional[float] = None
        self._last_error = ""
        self._capture_error = ""
        self._starting = False
        self._stopping = False
        self._want_running = False
        self._restart_times: list[float] = []
        self._dependency_parked = False
        self._file_lock_held = False
        self._applications: Set[str] = set()
        self._packets_processed = 0
        self._packets_dropped = 0
        self._selected_interface = ""
        self._capture_interface_name = ""
        self._packet_filter = self._config.packet_filter
        self._database_available = False

        self._store: Optional[BaselineStore] = None
        self._risk_store: Optional[RiskStore] = None
        self._baseline: Optional[BaselineTracker] = None
        self._orchestrator: Optional[AnomalyDetectionOrchestrator] = None
        self._risk_scorer: Optional[RiskScorer] = None
        self._correlator: Optional[AlertCorrelator] = None
        self._notifier: Optional[AlertNotifier] = None
        self._activity_tracker: Optional[ActivityTracker] = None
        self._session_manager: Optional[SessionManager] = None
        self._stats_manager: Optional[StatisticsManager] = None
        self._app_mapper: Optional[ApplicationMapper] = None
        self._checkpointer: Optional[BaselineCheckpointer] = None
        self._risk_checkpointer: Optional[RiskCheckpointer] = None
        self._fatal_errors: list = []
        self._session_generation = 0

        configure_service_logging(
            self._config.resolved_logs_dir(), self._config.logging_level
        )

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def start(self, *, reset_parked: bool = True, reset_budget: bool = True) -> None:
        """Start monitoring. Idempotent; at most one capture engine."""
        leftover = None
        capture = None
        with self._lock:
            worker = self._worker
            worker_alive = worker is not None and worker.is_alive()
            already_running = (
                worker_alive
                and self._want_running
                and not self._stopping
                and not self._stop_event.is_set()
            )
            if already_running:
                log_lifecycle("ENGINE_START_IGNORED", "already running")
                return
            if worker_alive:
                leftover = worker
                capture = self._capture_engine
                log_lifecycle("ENGINE_REPLACING_LEFTOVER_WORKER")
            self._want_running = True
            self._starting = True
            self._stopping = False
            if reset_parked:
                self._dependency_parked = False
            if reset_budget:
                self._restart_times = []
            self._last_error = ""
            self._capture_error = ""
            self._fatal_errors = []
            self._session_generation += 1
            generation = self._session_generation
            leftover_stop = self._stop_event
            self._stop_event = threading.Event()
        if leftover is not None:
            if capture is not None:
                try:
                    capture.stop()
                except Exception as exc:  # noqa: BLE001
                    log_lifecycle("CAPTURE_STOP_ERROR", str(exc))
            leftover_stop.set()
            leftover.join(timeout=2)
        with self._lock:
            if not self._want_running:
                self._starting = False
                return
            current = self._worker
            if (
                current is not None
                and current.is_alive()
                and current is not leftover
                and not self._stop_event.is_set()
            ):
                log_lifecycle("ENGINE_START_IGNORED", "already running")
                self._starting = False
                return
            self._starting = True
            self._worker = threading.Thread(
                target=self._run_session,
                args=(generation,),
                name="CANAEngineWorker",
                daemon=True,
            )
            self._worker.start()
            if self._watchdog is None or not self._watchdog.is_alive():
                self._watchdog_stop.clear()
                self._watchdog = threading.Thread(
                    target=self._watchdog_loop,
                    name="CANAEngineWatchdog",
                    daemon=True,
                )
                self._watchdog.start()
        log_lifecycle("ENGINE_STARTED")

    def stop(self) -> None:
        """Stop monitoring cleanly. Does not wait for a new packet."""
        with self._lock:
            self._want_running = False
            self._stopping = True
            self._stop_event.set()
            capture = self._capture_engine
        log_lifecycle("ENGINE_STOPPING")
        if capture is not None:
            try:
                capture.stop()
            except Exception as exc:  # noqa: BLE001
                log_lifecycle("CAPTURE_STOP_ERROR", str(exc))
        worker = self._worker
        if worker is not None and worker.is_alive():
            worker.join(timeout=15)
        with self._lock:
            self._starting = False
            self._stopping = False
            if self._worker is not None and not self._worker.is_alive():
                self._worker = None
            watchdog = self._watchdog
            stop_watchdog = not self._want_running
        if stop_watchdog:
            self._watchdog_stop.set()
            if watchdog is not None and watchdog.is_alive():
                watchdog.join(timeout=WATCHDOG_INTERVAL_SECONDS + 2)
            with self._lock:
                if self._watchdog is not None and not self._watchdog.is_alive():
                    self._watchdog = None
        log_lifecycle("ENGINE_STOPPED")

    def status(self) -> EngineStatus:
        """Return the current engine/capture/health status."""
        health = self.health()
        return EngineStatus(
            state=health.ui_state,
            display_state=health.display_state,
            health=health,
            running=health.engine_alive,
            capture_active=health.capture_alive,
            last_error=health.last_error,
        )

    def health(self) -> HealthSnapshot:
        """Build a live health snapshot from worker/capture/database state."""
        with self._lock:
            worker_alive = self._worker is not None and self._worker.is_alive()
            capture_alive = (
                self._capture_engine is not None
                and bool(getattr(self._capture_engine, "is_running", lambda: False)())
            )
            checkpoint_alive = bool(
                (self._checkpointer is not None and self._checkpointer.is_running())
                or (
                    self._risk_checkpointer is not None
                    and self._risk_checkpointer.is_running()
                )
            )
            dropped = self._packets_dropped
            if self._capture_engine is not None:
                stats = getattr(self._capture_engine, "stats", None)
                if stats is not None:
                    dropped = int(getattr(stats, "packets_dropped_queue_full", dropped))
            capture_error = self._capture_error
            last_error = self._last_error
            starting = self._starting
            monitoring_enabled = self._config.monitoring_enabled
            ui_state = derive_ui_state(
                engine_alive=worker_alive,
                capture_alive=capture_alive,
                monitoring_enabled=monitoring_enabled,
                capture_error=capture_error,
                last_error=last_error,
                starting=starting,
            )
            if self._stopping:
                ui_state = STATE_STOPPING
            snapshot = HealthSnapshot(
                service_alive=True,
                engine_alive=worker_alive,
                capture_alive=capture_alive,
                database_available=self._database_available,
                worker_threads_alive=worker_alive and (capture_alive or checkpoint_alive or starting),
                last_packet_at=self._last_packet_at,
                last_checkpoint_at=self._last_checkpoint_at,
                packets_processed=self._packets_processed,
                packets_dropped=dropped,
                applications_observed=len(self._applications),
                selected_interface=self._selected_interface,
                capture_interface_name=self._capture_interface_name,
                packet_filter=self._packet_filter,
                ui_state=ui_state,
                display_state=DISPLAY_STATES.get(ui_state, ui_state),
                last_error=last_error,
                capture_error=capture_error,
                monitoring_enabled=monitoring_enabled,
                started_at=self._started_at,
            )
        return snapshot

    def wait(self, timeout: Optional[float] = None) -> None:
        """Block until the worker thread exits (CLI foreground mode)."""
        worker = self._worker
        if worker is not None:
            worker.join(timeout=timeout)

    def apply_config_update(
        self, updates: Dict[str, Any], *, wait: bool = True
    ) -> CANAConfig:
        """Validate a candidate, then apply. Invalid updates mutate nothing."""
        candidate = self._config.with_updates(updates)
        return self.replace_config(candidate, wait=wait)

    def replace_config(self, candidate: CANAConfig, *, wait: bool = True) -> CANAConfig:
        """Install an already-validated config, then ensure capture state."""
        candidate.validate()
        with self._lock:
            previous = self._config
            self._config = candidate
            self._packet_filter = candidate.packet_filter
        runtime_changed = (
            previous.monitoring_enabled != candidate.monitoring_enabled
            or previous.capture_interface != candidate.capture_interface
            or previous.packet_filter != candidate.packet_filter
        )
        if not runtime_changed:
            return self._config
        try:
            if wait:
                self._ensure_monitoring_state()
            else:
                threading.Thread(
                    target=self._ensure_monitoring_state,
                    name="CANAConfigApply",
                    daemon=True,
                ).start()
        except Exception:
            with self._lock:
                self._config = previous
                self._packet_filter = previous.packet_filter
            raise
        return self._config

    def _ensure_monitoring_state(self) -> None:
        with self._config_apply_lock:
            if self._config.monitoring_enabled:
                worker_alive = (
                    self._worker is not None and self._worker.is_alive()
                )
                if worker_alive:
                    self.stop()
                    self.start()
                else:
                    self.start()
            else:
                self.stop()

    @property
    def config(self) -> CANAConfig:
        return self._config

    @property
    def store(self) -> Optional[BaselineStore]:
        return self._store

    @property
    def risk_store(self) -> Optional[RiskStore]:
        return self._risk_store

    # ------------------------------------------------------------------ #
    # Session lifecycle
    # ------------------------------------------------------------------ #

    def _session_token(self, generation: int) -> tuple:
        return (id(self), generation)

    def _is_current_session(self, generation: int) -> bool:
        return generation == 0 or self._session_generation == generation

    def _run_session(self, generation: int = 0) -> None:
        global _active_capture_engines, _capture_guard_token, _capture_lock_token
        acquired = False
        file_lock = False
        token = self._session_token(generation)
        try:
            if not self._is_current_session(generation):
                return
            deadline = time.time() + 5.0
            while not _capture_guard.acquire(blocking=False):
                if not self._is_current_session(generation):
                    return
                if not self._want_running and self._stop_event.is_set():
                    return
                holder = _capture_guard_token
                same_engine_leftover = (
                    isinstance(holder, tuple)
                    and len(holder) == 2
                    and holder[0] == id(self)
                    and holder[1] != generation
                )
                if not same_engine_leftover or time.time() >= deadline:
                    self._park_lock_failure(
                        CaptureLockError("duplicate capture engine refused"),
                        generation,
                    )
                    return
                time.sleep(0.05)
            acquired = True
            _capture_guard_token = token
            lock_deadline = time.time() + 5.0
            while True:
                try:
                    if os.name == "nt":
                        acquire_capture_lock()
                    else:
                        lock_dir = self._config.resolved_logs_dir()
                        acquire_capture_lock(lock_dir / "capture.lock")
                    file_lock = True
                    _capture_lock_token = token
                    self._file_lock_held = True
                    break
                except CaptureLockError as exc:
                    if not self._is_current_session(generation):
                        return
                    if not self._want_running and self._stop_event.is_set():
                        return
                    holder = _capture_lock_token
                    same_engine_leftover = (
                        isinstance(holder, tuple)
                        and len(holder) == 2
                        and holder[0] == id(self)
                        and holder[1] != generation
                    )
                    if not same_engine_leftover or time.time() >= lock_deadline:
                        self._park_lock_failure(exc, generation)
                        return
                    time.sleep(0.05)
            _active_capture_engines += 1
            if _active_capture_engines > 1:
                self._park_lock_failure(
                    CaptureLockError("duplicate capture engine refused"), generation
                )
                return
            if not self._is_current_session(generation):
                return
            self._execute_session(generation)
        except Exception as exc:  # noqa: BLE001
            self._fail(f"unexpected engine termination: {exc}", generation)
            log_lifecycle("ENGINE_UNEXPECTED_TERMINATION", str(exc))
        finally:
            if file_lock and _capture_lock_token == token:
                release_capture_lock()
                _capture_lock_token = None
                if self._is_current_session(generation):
                    self._file_lock_held = False
            if acquired and _capture_guard_token == token:
                _active_capture_engines = max(0, _active_capture_engines - 1)
                _capture_guard.release()
                _capture_guard_token = None
            with self._lock:
                if self._is_current_session(generation):
                    self._starting = False
                    self._capture_engine = None

    def _execute_session(self, generation: int = 0) -> None:
        log_lifecycle("SESSION_INIT_BEGIN")
        self._started_at = time.time()
        db_path = self._config.resolved_database_path() if self._config.persist else None
        sessions_dir = self._config.resolved_sessions_dir()
        sessions_dir.mkdir(parents=True, exist_ok=True)
        self._config.resolved_logs_dir().mkdir(parents=True, exist_ok=True)

        store = None if db_path is None else BaselineStore(db_path)
        risk_store = None if db_path is None else RiskStore(db_path)
        self._store = store
        self._risk_store = risk_store
        self._database_available = bool(store is not None and store.available)

        baseline = BaselineTracker()
        if store is not None:
            if self._config.reset_baseline:
                store.reset_baseline()
            else:
                baseline.restore(store.load_baseline())
            self._database_available = store.available
        self._baseline = baseline
        self._orchestrator = AnomalyDetectionOrchestrator(baseline=baseline)

        risk_scorer = RiskScorer(half_life=self._config.risk_half_life_seconds)
        if risk_store is not None:
            restored = risk_scorer.restore(risk_store.load_risk_state())
            if restored:
                log_lifecycle("RISK_STATE_RESTORED", f"entities={restored}")
        self._risk_scorer = risk_scorer
        self._correlator = AlertCorrelator(
            window_seconds=self._config.correlation_window_seconds
        )
        self._notifier = None
        if self._config.notify:
            self._notifier = AlertNotifier(channels=[DesktopNotifier()])

        activity_tracker = self._start_activity_tracker()
        session_manager = SessionManager()
        stats_manager = StatisticsManager()
        app_mapper = ApplicationMapper()
        if self._is_current_session(generation):
            self._activity_tracker = activity_tracker
            self._session_manager = session_manager
            self._stats_manager = stats_manager
            self._app_mapper = app_mapper

        checkpointer = None
        if store is not None:
            checkpointer = BaselineCheckpointer(baseline, store)
            checkpointer.start()
        risk_checkpointer = None
        if risk_store is not None:
            risk_checkpointer = RiskCheckpointer(risk_scorer, risk_store)
            risk_checkpointer.start()
        if self._is_current_session(generation):
            self._checkpointer = checkpointer
            self._risk_checkpointer = risk_checkpointer

        if not self._config.monitoring_enabled:
            log_lifecycle("MONITORING_DISABLED")
            with self._lock:
                if self._is_current_session(generation):
                    self._starting = False
            self._wait_until_stopped()
            self._finish_session(
                generation,
                checkpointer,
                risk_checkpointer,
                activity_tracker,
                session_manager,
                sessions_dir,
            )
            return

        try:
            settings, local_ips = self._prepare_capture(generation)
        except Exception as exc:  # noqa: BLE001
            self._park_dependency_failure(exc, generation)
            self._wait_until_stopped()
            self._finish_session(
                generation,
                checkpointer,
                risk_checkpointer,
                activity_tracker,
                session_manager,
                sessions_dir,
            )
            return

        packet_handler = build_packet_handler(
            self._orchestrator,
            activity_tracker,
            store=store,
            session_manager=session_manager,
            risk_scorer=risk_scorer,
            correlator=self._correlator,
            notifier=self._notifier,
            risk_store=risk_store,
            print_alerts=self._print_alerts,
            on_processed=self._note_packet,
        )

        engine_out: Dict[str, Any] = {}
        binder = threading.Thread(
            target=self._bind_capture_engine,
            args=(engine_out, generation),
            name="CANACaptureBinder",
            daemon=True,
        )
        binder.start()
        with self._lock:
            if self._is_current_session(generation):
                self._starting = False
        log_lifecycle(
            "CAPTURE_STARTING",
            f"interface={settings.display_name} filter={settings.packet_filter}",
        )
        try:
            self._capture_runner(
                settings,
                local_ip=local_ips,
                print_summaries=self._config.print_summaries,
                error_sink=self._fatal_errors,
                session_manager=session_manager,
                app_mapper=app_mapper,
                stats_manager=stats_manager,
                on_packet=packet_handler,
                stop_event=self._stop_event,
                engine_out=engine_out,
            )
        except (OSError, PermissionError) as exc:
            self._park_dependency_failure(exc, generation)
        except Exception as exc:  # noqa: BLE001
            self._fail(f"capture failed: {exc}", generation)
        finally:
            if self._is_current_session(generation) and self._fatal_errors:
                first = self._fatal_errors[0]
                if isinstance(first, (OSError, PermissionError)) or _is_dependency_error(
                    first
                ):
                    self._park_dependency_failure(first, generation)
                else:
                    self._capture_error = str(first)
                    self._last_error = self._capture_error
                    log_lifecycle("CAPTURE_FAILURE", self._capture_error)
            if not self._is_current_session(generation):
                log_lifecycle("STALE_SESSION_EXIT")
            self._finish_session(
                generation,
                checkpointer,
                risk_checkpointer,
                activity_tracker,
                session_manager,
                sessions_dir,
            )
            log_lifecycle("CAPTURE_STOPPED")

    def _prepare_capture(self, generation: int = 0):
        try:
            interfaces = self._interface_detector()
        except InterfaceDetectionError as exc:
            raise RuntimeError(f"packet-capture dependency unavailable: {exc}") from exc
        try:
            chosen = resolve_interface(interfaces, self._config.capture_interface)
        except InterfaceSelectionError as exc:
            raise RuntimeError(str(exc)) from exc
        settings = CaptureSettings(
            interface_name=chosen.name,
            display_name=chosen.display_name,
            packet_filter=self._config.packet_filter,
        )
        local_ips = sorted(set(chosen.all_local_ips) | set(get_all_local_ips()))
        with self._lock:
            if self._is_current_session(generation):
                self._selected_interface = chosen.display_name
                self._capture_interface_name = chosen.name
                self._packet_filter = settings.packet_filter
                self._capture_engine = None
        log_lifecycle(
            "INTERFACE_SELECTED",
            f"{chosen.display_name} ({chosen.name})",
        )
        return settings, local_ips

    def _bind_capture_engine(
        self, engine_out: Dict[str, Any], generation: int = 0
    ) -> None:
        deadline = time.time() + 10
        while time.time() < deadline and not self._stop_event.is_set():
            if not self._is_current_session(generation):
                return
            engine = engine_out.get("engine")
            if engine is not None:
                with self._lock:
                    if self._is_current_session(generation):
                        self._capture_engine = engine
                log_lifecycle("CAPTURE_STARTED")
                return
            time.sleep(0.05)

    def _note_packet(self, packet: Dict[str, Any]) -> None:
        with self._lock:
            self._last_packet_at = time.time()
            self._packets_processed += 1
            app = packet.get("application_name")
            if app and app != UNKNOWN_APPLICATION:
                self._applications.add(str(app))
            if self._checkpointer is not None:
                if self._checkpointer.saves_completed:
                    self._last_checkpoint_at = time.time()

    def _start_activity_tracker(self) -> Optional[ActivityTracker]:
        if not self._track_user_activity:
            log_lifecycle("ACTIVITY_UNKNOWN", "service cannot observe interactive desktop input")
            return None
        tracker = ActivityTracker()
        try:
            tracker.start()
        except ActivityListenerError as exc:
            log_lifecycle("ACTIVITY_TRACKER_UNAVAILABLE", str(exc))
            return None
        return tracker

    def _stop_session_resource(self, resource: Any, event: str) -> None:
        if resource is None:
            return
        try:
            resource.stop()
        except Exception as exc:  # noqa: BLE001
            log_lifecycle(event, str(exc))

    def _finish_session(
        self,
        generation: int,
        checkpointer: Any,
        risk_checkpointer: Any,
        activity_tracker: Any,
        session_manager: Any,
        sessions_dir: Any,
    ) -> None:
        self._stop_session_resource(activity_tracker, "ACTIVITY_TRACKER_STOP_ERROR")
        if checkpointer is not None:
            try:
                checkpointer.stop()
                if self._is_current_session(generation):
                    self._last_checkpoint_at = time.time()
            except Exception as exc:  # noqa: BLE001
                log_lifecycle("BASELINE_CHECKPOINT_STOP_ERROR", str(exc))
        self._stop_session_resource(risk_checkpointer, "RISK_CHECKPOINT_STOP_ERROR")
        if self._is_current_session(generation):
            if self._risk_store is not None and self._correlator is not None:
                for correlated in self._correlator.flush():
                    try:
                        self._risk_store.save_correlated_alert(correlated)
                    except Exception as exc:  # noqa: BLE001
                        log_lifecycle("CORRELATED_FLUSH_ERROR", str(exc))
            self._checkpointer = None
            self._risk_checkpointer = None
            self._activity_tracker = None
        if session_manager is not None:
            try:
                session_manager.save(directory=sessions_dir)
            except Exception as exc:  # noqa: BLE001
                log_lifecycle("SESSION_SAVE_FAILURE", str(exc))

    def _shutdown_persistence(self) -> None:
        self._finish_session(
            self._session_generation,
            self._checkpointer,
            self._risk_checkpointer,
            self._activity_tracker,
            None,
            None,
        )

    def _wait_until_stopped(self) -> None:
        while not self._stop_event.wait(0.25):
            if not self._want_running:
                break

    def _fail(self, message: str, generation: int = 0) -> None:
        with self._lock:
            if not self._is_current_session(generation):
                return
            self._last_error = message
            self._starting = False
        log_lifecycle("STARTUP_FAILURE", message)

    def _park_dependency_failure(self, exc: Exception, generation: int = 0) -> None:
        message = str(exc)
        with self._lock:
            if not self._is_current_session(generation):
                return
            self._capture_error = message
            self._last_error = message
            self._starting = False
            self._dependency_parked = True
        log_lifecycle("CAPTURE_UNAVAILABLE", message)

    def _park_lock_failure(self, exc: Exception, generation: int = 0) -> None:
        """Park on a terminal singleton-lock failure.

        A duplicate engine or a mutex the process is not allowed to create
        will not resolve by restarting, so the watchdog must not spin. A
        fresh user-initiated ``start()`` clears the parked flag.
        """
        message = str(exc)
        with self._lock:
            if not self._is_current_session(generation):
                return
            self._capture_error = message
            self._last_error = message
            self._starting = False
            self._dependency_parked = True
        log_lifecycle("CAPTURE_LOCK_REFUSED", message)

    def _watchdog_loop(self) -> None:
        while not self._watchdog_stop.wait(WATCHDOG_INTERVAL_SECONDS):
            with self._lock:
                want = self._want_running
                stopping = self._stopping
                worker_alive = self._worker is not None and self._worker.is_alive()
                monitoring = self._config.monitoring_enabled
                parked = self._dependency_parked
            if not want:
                continue
            if stopping:
                continue
            capture_alive = (
                self._capture_engine is not None
                and bool(getattr(self._capture_engine, "is_running", lambda: False)())
            )
            if worker_alive:
                if capture_alive and self._restart_times:
                    with self._lock:
                        self._restart_times = []
                continue
            if parked:
                continue
            if not monitoring:
                continue
            now = time.time()
            self._restart_times = [
                stamp
                for stamp in self._restart_times
                if now - stamp < WATCHDOG_RAPID_WINDOW_SECONDS
            ]
            if len(self._restart_times) >= WATCHDOG_MAX_RAPID_RESTARTS:
                self._fail("watchdog refused restart loop; too many recent failures")
                log_lifecycle("WATCHDOG_RESTART_LIMIT", "rapid restart loop avoided")
                with self._lock:
                    self._dependency_parked = True
                    self._capture_error = self._last_error
                continue
            log_lifecycle("WATCHDOG_RECOVERY", "worker dead; restarting engine")
            self._restart_times.append(now)
            if self._watchdog_stop.wait(WATCHDOG_RESTART_DELAY_SECONDS):
                return
            if not self._want_running:
                continue
            self.start(reset_parked=False, reset_budget=False)


__all__ = ["CANAEngine"]
