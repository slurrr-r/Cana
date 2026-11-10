"""
capture.py
==========

The packet capture engine: runs Scapy's ``sniff()`` on a background
thread, applies the user-selected packet filter, and feeds captured
packets into a thread-safe queue for downstream parsing/statistics.

Design notes:
    * Scapy's ``sniff()`` is blocking, so it is run on a dedicated
      ``threading.Thread``. A ``threading.Event`` is used as a
      cooperative stop signal. ``sniff()`` is polled with
      ``timeout=SNIFF_POLL_TIMEOUT_SECONDS`` so stop does not wait for
      a packet on a silent interface; ``stop_filter`` still covers the
      busy path.
    * A bounded ``queue.Queue`` decouples the capture thread from
      whatever consumes packets (console printer, statistics, parser),
      preventing a slow consumer from causing unbounded memory growth.
    * This module deliberately does not parse packet contents - it only
      captures raw Scapy packets and hands them off. Parsing lives in
      ``parser.py``.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from packet_capture.config import (
    CaptureSettings,
    PACKET_QUEUE_MAX_SIZE,
    SNIFF_POLL_TIMEOUT_SECONDS,
)
from packet_capture.logger import get_logger, log_module_event

logger = get_logger(__name__)


class CaptureEngineError(Exception):
    """Raised for unrecoverable capture engine failures."""


_FILTER_TO_BPF: dict[str, Optional[str]] = {
    "ALL": None,
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "DNS": "udp port 53 or tcp port 53",
    "HTTP": "tcp port 80 or tcp port 8080",
    "HTTPS": "tcp port 443 or tcp port 8443",
}


def build_bpf_filter(packet_filter: str) -> Optional[str]:
    """
    Translate a supported filter name into a Berkeley Packet Filter
    (BPF) expression that Scapy's ``sniff(filter=...)`` accepts.

    Args:
        packet_filter: One of the values in ``SUPPORTED_FILTERS``.

    Returns:
        A BPF string, or ``None`` for "ALL" (no filtering).

    Raises:
        CaptureEngineError: If the filter name is not recognized.
    """
    key = packet_filter.upper()
    if key not in _FILTER_TO_BPF:
        raise CaptureEngineError(f"Unrecognized packet filter '{packet_filter}'.")
    return _FILTER_TO_BPF[key]


@dataclass
class CaptureStats:
    """Lightweight, thread-safe-by-convention counters for the engine itself."""

    packets_captured: int = 0
    packets_dropped_queue_full: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None


class PacketCaptureEngine:
    """
    Runs live packet capture on a background thread and exposes
    captured packets through a thread-safe queue.

    Typical usage::

        engine = PacketCaptureEngine(settings, packet_queue)
        engine.start()
        ...
        engine.stop()
        engine.join()
    """

    def __init__(
        self,
        settings: CaptureSettings,
        packet_queue: "queue.Queue[Any]",
        on_error: Optional[Callable[[Exception], None]] = None,
    ) -> None:
        """
        Args:
            settings: Validated capture settings (interface + filter).
            packet_queue: Bounded queue that captured raw packets are
                pushed onto. Consumers (parser/stats/console) pull
                from this queue.
            on_error: Optional callback invoked with any exception
                raised inside the capture thread, for the caller to
                react to (e.g. surface to the user) without the
                exception being silently swallowed.
        """
        self._settings = settings
        self._packet_queue = packet_queue
        self._on_error = on_error
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sniffer: Optional[Any] = None
        self.stats = CaptureStats()

    def _packet_callback(self, raw_packet: Any) -> None:
        """Invoked by Scapy for every captured packet."""
        try:
            self._packet_queue.put_nowait(raw_packet)
            self.stats.packets_captured += 1
        except queue.Full:
            self.stats.packets_dropped_queue_full += 1
            logger.warning(
                "Packet queue full - dropping packet (total dropped: %d).",
                self.stats.packets_dropped_queue_full,
            )

    def _should_stop(self, _raw_packet: Any) -> bool:
        """Scapy stop_filter callback: checked after every packet."""
        return self._stop_event.is_set()

    def _interrupt_sniffer(self) -> None:
        """Force Scapy/Npcap to release the adapter without waiting for a packet."""
        sniffer = self._sniffer
        if sniffer is None:
            return
        stop_cb = getattr(sniffer, "stop_cb", None)
        if callable(stop_cb):
            try:
                stop_cb()
            except Exception:  # noqa: BLE001
                pass
        stop = getattr(sniffer, "stop", None)
        if callable(stop):
            try:
                stop(join=False)
            except TypeError:
                try:
                    stop()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass
        for attr in ("socket", "l2socket"):
            sock = getattr(sniffer, attr, None)
            closer = getattr(sock, "close", None) if sock is not None else None
            if callable(closer):
                try:
                    closer()
                except Exception:  # noqa: BLE001
                    pass

    def _sniff_async(self, async_cls: Any, bpf_filter: Optional[str]) -> None:
        sniffer = async_cls(
            iface=self._settings.interface_name,
            prn=self._packet_callback,
            stop_filter=self._should_stop,
            store=False,
            filter=bpf_filter,
        )
        self._sniffer = sniffer
        start = getattr(sniffer, "start", None)
        if not callable(start):
            raise CaptureEngineError("AsyncSniffer is missing start().")
        start()
        while not self._stop_event.is_set():
            thread = getattr(sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                break
            if thread is None and getattr(sniffer, "running", True) is False:
                break
            self._stop_event.wait(SNIFF_POLL_TIMEOUT_SECONDS)
        self._interrupt_sniffer()
        thread = getattr(sniffer, "thread", None)
        if thread is not None:
            sniffer.join(timeout=SNIFF_POLL_TIMEOUT_SECONDS)

    def _run(self) -> None:
        """The actual thread target: blocks inside Scapy's sniff loop."""
        from scapy.all import sniff

        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            AsyncSniffer = None

        bpf_filter = build_bpf_filter(self._settings.packet_filter)
        self.stats.start_time = time.time()
        log_module_event(
            logger,
            "CAPTURE_STARTED",
            detail=(
                f"interface={self._settings.display_name} "
                f"filter={self._settings.packet_filter}"
            ),
        )
        try:
            sniff_is_native = str(getattr(sniff, "__module__", "")).startswith("scapy")
            if AsyncSniffer is not None and sniff_is_native:
                self._sniff_async(AsyncSniffer, bpf_filter)
            else:
                while not self._stop_event.is_set():
                    sniff(
                        iface=self._settings.interface_name,
                        prn=self._packet_callback,
                        stop_filter=self._should_stop,
                        store=False,
                        filter=bpf_filter,
                        timeout=SNIFF_POLL_TIMEOUT_SECONDS,
                    )
        except PermissionError as exc:
            logger.error("Permission denied opening interface for capture: %s", exc)
            if self._on_error:
                self._on_error(exc)
        except OSError as exc:
            logger.error(
                "OS-level capture error (invalid interface or missing "
                "Npcap driver?): %s",
                exc,
            )
            if self._on_error:
                self._on_error(exc)
        except Exception as exc:  # noqa: BLE001 - never let the thread die silently
            logger.error("Unexpected capture engine error: %s", exc)
            if self._on_error:
                self._on_error(exc)
        finally:
            self._interrupt_sniffer()
            self._sniffer = None
            self.stats.end_time = time.time()
            log_module_event(
                logger,
                "CAPTURE_STOPPED",
                detail=f"packets_captured={self.stats.packets_captured}",
            )

    def start(self) -> None:
        """Start capturing on a background thread. Idempotent-safe."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Capture engine already running; start() ignored.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="PacketCaptureThread", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """
        Signal the capture thread to stop.

        Note: Scapy's ``stop_filter`` is evaluated after each packet.
        The sniff loop also uses ``timeout=SNIFF_POLL_TIMEOUT_SECONDS``
        so an idle/silent interface still returns to check the stop
        event. Shutdown does not wait for a new packet to arrive.
        """
        self._stop_event.set()
        self._interrupt_sniffer()

    def join(self, timeout: Optional[float] = None) -> None:
        """Block until the capture thread has fully terminated."""
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        """Return True if the capture thread is alive."""
        return self._thread is not None and self._thread.is_alive()


def create_packet_queue() -> "queue.Queue[Any]":
    """Factory for the bounded queue used between capture and consumers."""
    return queue.Queue(maxsize=PACKET_QUEUE_MAX_SIZE)


def start_packet_capture(
    settings: CaptureSettings,
    local_ip: Optional[Any] = None,
    max_packets: Optional[int] = None,
    print_summaries: bool = True,
    error_sink: Optional[list] = None,
    session_manager: Optional[Any] = None,
    app_mapper: Optional[Any] = None,
    stats_manager: Optional[Any] = None,
    on_packet: Optional[Any] = None,
    stop_event: Optional[threading.Event] = None,
    engine_out: Optional[dict] = None,
) -> list:
    """
    Public API entry point for Module 1.

    Runs a full capture session end-to-end: starts the capture engine,
    pulls raw packets off the queue, parses/validates/classifies each
    one, updates live statistics, optionally prints a console summary,
    and returns the final list of processed packet dictionaries when
    the session ends (via Ctrl+C, ``max_packets`` being reached, or an
    unrecoverable engine error).

    This is the sole public contract this module exposes to whatever
    consumes it next (e.g. a future application-mapping module)::

        packets = start_packet_capture(settings)

    Args:
        settings: Validated ``CaptureSettings`` (interface + filter)
            chosen by the user.
        local_ip: The local machine's IP address(es) on the capturing
            interface, used for direction classification - a single
            string, or an iterable of strings for a dual-stack
            (IPv4 + IPv6) interface. If unknown/omitted, direction
            will be reported as ``UNKNOWN`` for all packets.
        max_packets: Optional cap - if set, capture stops automatically
            once this many valid packets have been processed (useful
            for bounded demo runs). ``None`` means capture runs until
            interrupted (e.g. Ctrl+C).
        print_summaries: Whether to print a console summary per packet
            as it is processed. When ``app_mapper`` is provided, the
            multi-line, application-aware block format is used instead
            of the single-line summary.
        error_sink: Optional list the caller can pass in to receive
            any fatal capture-engine exceptions (e.g. missing Npcap
            driver, permission denied). If provided, this function
            appends encountered exceptions to it, letting the caller
            (e.g. ``main.py``) show a specific, actionable diagnostic
            rather than silently returning an empty packet list.
        session_manager: Optional externally-created
            ``SessionManager`` instance. If provided, this function
            uses it (and leaves it open for the caller to add further
            actions / re-attach enriched packets / save again after
            this function returns). If omitted, a new one is created
            internally and fully finalized (ended + saved) before this
            function returns, exactly as before.
        app_mapper: Optional ``ApplicationMapper`` instance (Module 2).
            If provided, every packet is enriched with
            ``application_name``/``process_id``/``executable_path``
            *live*, during capture, rather than as a separate pass
            afterward - this is what powers the per-packet
            "which app made this connection" console display. The
            mapper's OS connection-table snapshot is refreshed
            periodically (see ``APP_MAPPER_REFRESH_INTERVAL_SECONDS``
            in ``config.py``) rather than once per packet, since
            ``psutil.net_connections()`` is relatively expensive.
        stats_manager: Optional externally-created ``StatisticsManager``
            instance. If provided, this function updates it during
            capture and leaves it available to the caller afterward
            (e.g. so ``main.py`` can print a final statistics summary
            via ``stats_manager.snapshot()``). If omitted, a new one
            is created and used internally only.
        on_packet: Optional callback invoked with every fully
            processed (classified, and application-mapped if
            ``app_mapper`` was provided) packet dictionary, right
            after processing and before it is appended to the
            returned list or displayed. This is the generic extension
            point for anything that needs to react to packets *live*
            during capture (e.g. Module 4's anomaly detection) without
            this module needing to import that consumer's package
            directly - keeping Module 1 fully standalone. Exceptions
            raised by the callback are logged and swallowed, never
            allowed to interrupt capture.
        stop_event: Optional ``threading.Event``. When set, capture
            stops without waiting for Ctrl+C or a new packet. Used by
            the CANA engine/service so shutdown works on a silent
            interface.
        engine_out: Optional dict populated with the live
            ``PacketCaptureEngine`` (key ``"engine"``) so a caller can
            observe capture liveness without owning the sniff thread.

    Returns:
        A list of classified (and, if ``app_mapper`` was provided,
        application-mapped) packet dictionaries, honoring the
        ``MAX_RETAINED_PACKETS`` in-memory retention cap from
        ``config.py`` to bound memory usage on long sessions.
    """
    from packet_capture.app_mapper import UNKNOWN_APPLICATION
    from packet_capture.classifier import classify_packet
    from packet_capture.config import (
        APP_MAPPER_MISS_REFRESH_COOLDOWN_SECONDS,
        APP_MAPPER_REFRESH_INTERVAL_SECONDS,
        MAX_RETAINED_PACKETS,
    )
    from packet_capture.parser import PacketParsingError, parse_packet
    from packet_capture.session import SessionManager
    from packet_capture.statistics import StatisticsManager
    from packet_capture.utils import LiveConsolePrinter, format_packet_summary
    from packet_capture.validator import is_valid_packet

    fatal_errors: list = []
    packet_queue = create_packet_queue()
    engine = PacketCaptureEngine(
        settings, packet_queue, on_error=lambda exc: fatal_errors.append(exc)
    )
    if engine_out is not None:
        engine_out["engine"] = engine
    if stats_manager is None:
        stats_manager = StatisticsManager()

    owns_session = session_manager is None
    if session_manager is None:
        session_manager = SessionManager()

    session_manager.start_session(settings.display_name, settings.packet_filter)
    session_manager.add_action("Capture engine starting")
    session_manager.add_action(f"Local IP(s) for direction matching: {local_ip!r}")
    if app_mapper is not None:
        app_mapper.refresh()
        session_manager.add_action("Live application mapping enabled")
    last_mapper_refresh = time.time()

    stats_manager.start()
    engine.start()

    # Retention (MAX_RETAINED_PACKETS, below) is a memory policy, not
    # an accounting policy. processed_packet_count is tracked
    # separately from len(processed_packets) so that a requested
    # max_packets above the retention cap still terminates capture
    # correctly, and so session/statistics reporting reflects the true
    # number of packets processed rather than only the number retained
    # in memory.
    processed_packets: list = []
    processed_packet_count = 0
    console_printer = (
        LiveConsolePrinter(suppress_unmapped=True)
        if (print_summaries and app_mapper is not None)
        else None
    )

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                engine.stop()
                session_manager.add_action("Capture stop requested")
                break
            if fatal_errors:
                logger.error(
                    "Capture engine reported a fatal error; stopping session."
                )
                session_manager.add_action(
                    f"Fatal capture error: {fatal_errors[0]}"
                )
                break
            if max_packets is not None and processed_packet_count >= max_packets:
                engine.stop()
                break
            if not engine.is_running() and packet_queue.empty():
                break

            try:
                raw_packet = packet_queue.get(timeout=SNIFF_POLL_TIMEOUT_SECONDS)
            except queue.Empty:
                continue

            try:
                parsed = parse_packet(raw_packet)
            except PacketParsingError as exc:
                logger.warning("Dropping unparseable packet: %s", exc)
                continue

            if not is_valid_packet(parsed):
                continue

            classified = classify_packet(parsed, local_ip=local_ip)
            stats_manager.update(classified)

            if app_mapper is not None:
                now = time.time()
                if now - last_mapper_refresh >= APP_MAPPER_REFRESH_INTERVAL_SECONDS:
                    app_mapper.refresh()
                    last_mapper_refresh = now
                classified = app_mapper.enrich_packet(classified)

                if classified.get("application_name") == UNKNOWN_APPLICATION:
                    # Likely a very recently-opened connection the last
                    # snapshot missed (common for short UDP/QUIC flows).
                    # Try one cooldown-gated immediate refresh + retry
                    # rather than waiting for the next scheduled one.
                    if app_mapper.refresh_if_stale(
                        APP_MAPPER_MISS_REFRESH_COOLDOWN_SECONDS
                    ):
                        last_mapper_refresh = time.time()
                        classified = app_mapper.enrich_packet(classified)

            if on_packet is not None:
                try:
                    on_packet(classified)
                except Exception as exc:  # noqa: BLE001 - a callback bug must never kill capture
                    logger.error("on_packet callback raised an error: %s", exc)

            processed_packet_count += 1

            if (
                MAX_RETAINED_PACKETS <= 0
                or len(processed_packets) < MAX_RETAINED_PACKETS
            ):
                processed_packets.append(classified)

            if print_summaries:
                if console_printer is not None:
                    console_printer.display(classified)
                else:
                    print(format_packet_summary(classified))

    except KeyboardInterrupt:
        log_module_event(logger, "CAPTURE_INTERRUPTED", detail="KeyboardInterrupt")
        session_manager.add_action("Capture interrupted by user (Ctrl+C)")
    finally:
        if console_printer is not None:
            console_printer.finalize()
        engine.stop()
        engine.join(timeout=5)
        session_manager.add_action(
            f"Capture stopped - {processed_packet_count} packets processed "
            f"({len(processed_packets)} retained)"
        )
        session_manager.attach_packets(processed_packets)
        session_manager.end_session(total_packets=processed_packet_count)
        if owns_session:
            try:
                session_manager.save()
            except Exception as exc:  # noqa: BLE001 - never fail capture over session save
                logger.error("Failed to save session metadata: %s", exc)
        if error_sink is not None:
            error_sink.extend(fatal_errors)

    return processed_packets
