"""
main.py
=======

Developer/debug launcher for CANA.

The Windows service owns monitoring. This file is the CLI compatibility
layer: ``python main.py`` still works, but it starts the same
``CANAEngine`` the service uses rather than owning capture itself.

Options::

    python main.py
    python main.py --debug
    python main.py --service
    python main.py --ui
    python main.py --reset-baseline
    python main.py --no-persist
    python main.py --db PATH
    python main.py --notify
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Optional


def build_packet_handler(*args: Any, **kwargs: Any):
    """
    Shared packet-handler factory, re-exported from ``cana_engine.handler``.

    The Windows service and developer CLI both use this rising-edge
    alert / risk / correlation path. The implementation lives in
    ``cana_engine.handler`` so detection is not duplicated. Import is
    deferred so a frozen ``CANA.exe`` SCM launch can report
    SERVICE_RUNNING before capture/detection modules load.
    """
    from cana_engine.handler import build_packet_handler as _impl

    return _impl(*args, **kwargs)


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    """
    Parse command-line options.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        The parsed options namespace.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            "Context-Aware Network Behavior Analyzer - live capture with "
            "application attribution, user-activity context, and "
            "baseline-driven anomaly detection."
        ),
    )
    parser.add_argument(
        "--reset-baseline",
        action="store_true",
        help=(
            "Discard the baseline learned by previous runs before starting. "
            "Recorded alert history is preserved. Useful for demonstrating "
            "cold-start behavior, or after a period of atypical traffic has "
            "polluted what the tool considers 'normal'."
        ),
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help=(
            "Run entirely in memory: don't load a baseline, don't save one, "
            "and don't record alerts to the database."
        ),
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Use an alternative database file instead of the default "
            "data/baseline.db."
        ),
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help=(
            "Send best-effort desktop notifications for correlated "
            "alerts (requires the optional 'plyer' package). Always "
            "console + database regardless."
        ),
    )
    parser.add_argument(
        "--risk-half-life",
        type=float,
        default=300.0,
        metavar="SECONDS",
        help=(
            "Half-life of risk scores in seconds - how quickly recent "
            "alerts dominate over old ones (default: 300)."
        ),
    )
    parser.add_argument(
        "--correlation-window",
        type=float,
        default=60.0,
        metavar="SECONDS",
        help=(
            "Correlation window in seconds - rule signals for the same "
            "app/destination within this window are combined into one "
            "incident (default: 60)."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Developer debug mode: verbose logging, same CANA engine.",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help="Developer debug: run CANAEngine in the foreground (not the Windows SCM service).",
    )
    parser.add_argument(
        "--ui",
        action="store_true",
        help="Open the CANA UI only; monitoring stays in the background service.",
    )
    parser.add_argument(
        "--install-service",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def _print_capture_error_help(exc: Exception) -> None:
    """
    Translate a fatal capture-engine exception into a specific,
    actionable message for the user, rather than a raw stack-trace-
    style error string.

    Args:
        extra: The exception the capture engine reported.
    """
    message = str(exc).lower()

    if "winpcap" in message or "npcap" in message or "libpcap" in message:
        print("\n[ERROR] Packet capture driver problem detected.")
        print(
            "Scapy could not find a working Npcap installation. This "
            "usually means one of the following:"
        )
        print("  1. Npcap is not installed at all.")
        print(
            "  2. Npcap was installed WITHOUT the 'WinPcap API-compatible "
            "Mode' option checked."
        )
        print("  3. A previous WinPcap/Npcap install is conflicting.")
        print("\nTo fix this:")
        print("  - Uninstall any existing Npcap/WinPcap from Control Panel.")
        print("  - Download Npcap from https://npcap.com")
        print(
            "  - During install, check 'Install Npcap in WinPcap "
            "API-compatible Mode'."
        )
        print(
            "  - Restart your computer, then run this program again as "
            "Administrator."
        )
    elif isinstance(exc, PermissionError) or "permission" in message:
        print("\n[ERROR] Permission denied while opening the network interface.")
        print("Close this program and re-open your terminal as Administrator.")
    else:
        print(f"\n[ERROR] Capture engine failed: {exc}")


def _prompt_filter_selection() -> str:
    """Prompt the user to choose a packet filter before capture starts."""
    from packet_capture.config import SUPPORTED_FILTERS

    print("\nAvailable Packet Filters:")
    print("-" * 40)
    for idx, name in enumerate(SUPPORTED_FILTERS, start=1):
        print(f"[{idx}] {name}")

    while True:
        raw = input("\nSelect a filter (number): ").strip()
        try:
            choice = int(raw)
            if 1 <= choice <= len(SUPPORTED_FILTERS):
                return SUPPORTED_FILTERS[choice - 1]
        except ValueError:
            pass
        print(
            f"Invalid selection. Enter a number between 1 and "
            f"{len(SUPPORTED_FILTERS)}."
        )


def _interactive_settings(config) -> Optional[int]:
    """Prompt for interface/filter in developer CLI mode."""
    from packet_capture.interface import (
        InterfaceDetectionError,
        InterfaceSelectionError,
        detect_interfaces,
        format_interface_menu,
        select_interface,
    )

    try:
        interfaces = detect_interfaces()
    except InterfaceDetectionError as extra:
        print(f"\n[ERROR] Could not detect network interfaces: {extra}")
        print(
            "On Windows, ensure Npcap is installed and this program is "
            "run as Administrator."
        )
        return 1

    print("\n" + format_interface_menu(interfaces))

    try:
        raw_selection = input("\nSelect an interface (number): ")
        chosen_interface = select_interface(interfaces, raw_selection)
    except InterfaceSelectionError as extra:
        print(f"\n[ERROR] Invalid interface selection: {extra}")
        return 1

    packet_filter = _prompt_filter_selection()
    config.capture_interface = chosen_interface.name
    config.packet_filter = packet_filter
    print(
        f"\nStarting capture on '{chosen_interface.display_name}' "
        f"with filter '{packet_filter}'. Press Ctrl+C to stop.\n"
        f"Each packet will show which application generated it.\n"
        f"Anomalies will be shown as [ALERT] blocks when detected.\n"
        f"Risk scores and correlated incidents are tracked per "
        f"application/destination and persisted to the database.\n"
    )
    return None


def main(argv: Optional[list] = None) -> int:
    """
    Run CANA through the shared engine.

    Args:
        argv: Command-line arguments. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code: ``0`` on a clean run, non-zero on an
        unrecoverable startup error.
    """
    if (
        argv is None
        and getattr(sys, "frozen", False)
        and not sys.argv[1:]
    ):
        from cana_service.service import NotStartedBySCM, run_as_windows_service

        try:
            return run_as_windows_service()
        except NotStartedBySCM:
            from cana_ui.app import run_ui

            return run_ui()

    args = parse_args(argv)

    if args.ui:
        from cana_ui.app import run_ui

        return run_ui()

    if args.install_service:
        from cana_service.install import install_packaged_service

        return install_packaged_service()

    if args.service:
        from cana_engine.config import config_from_cli_args
        from cana_service.service import run_service_entry

        return run_service_entry(config_from_cli_args(args))

    import time

    from cana_engine.config import config_from_cli_args, save_config
    from cana_engine.engine import CANAEngine
    from packet_capture.logger import get_logger, log_module_event
    from packet_capture.utils import format_duration, format_statistics_line
    from risk_scoring.utils import format_risk_summary

    logger = get_logger(__name__)
    log_module_event(logger, "MODULE_STARTED")
    print("=" * 60)
    print("Context-Aware Network Behavior Analyzer")
    print("=" * 60)

    config = config_from_cli_args(args)
    config.print_summaries = True
    if args.debug:
        config.logging_level = "DEBUG"

    interactive_error = _interactive_settings(config)
    if interactive_error:
        return interactive_error

    engine = CANAEngine(config, print_alerts=True)
    start_time = time.time()

    engine.start()
    try:
        while engine.status().running or engine.health().ui_state == "starting":
            time.sleep(0.25)
            health = engine.health()
            if health.capture_error and not health.capture_alive:
                _print_capture_error_help(RuntimeError(health.capture_error))
                break
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Stopping engine.")
    finally:
        engine.stop()

    health = engine.health()
    elapsed = time.time() - start_time
    snapshot = None
    if engine._stats_manager is not None:
        snapshot = engine._stats_manager.snapshot()
    baseline_summary = (
        engine._baseline.summary() if engine._baseline is not None else None
    )
    total_processed = health.packets_processed
    if snapshot is not None:
        total_processed = snapshot.total_packets

    print("\n" + "=" * 60)
    print("Capture session ended.")
    print(f"Total packets processed: {total_processed}")
    print(f"Elapsed time (wall clock): {format_duration(elapsed)}")
    if snapshot is not None:
        print(
            f"Elapsed time (capture engine): "
            f"{format_duration(snapshot.capture_duration_seconds)}"
        )
        print("\nTraffic statistics:")
        print(f"  {format_statistics_line(snapshot)}")
    if engine._orchestrator is not None:
        print(
            f"\nAnomaly detection: {engine._orchestrator.total_triggers} rule "
            f"trigger(s) across {engine._orchestrator.packets_processed} "
            f"packets analyzed"
        )
    if baseline_summary is not None:
        print(
            f"Baseline now holds: {baseline_summary.metric_count} metric(s), "
            f"{baseline_summary.established_bucket_count} established "
            f"hour-bucket(s), {baseline_summary.total_observations:,} observation(s)"
        )
    if engine._risk_scorer is not None:
        print("\n" + format_risk_summary(engine._risk_scorer.snapshot()))
    store = engine.store
    if store is None:
        print(
            "Baseline NOT saved (--no-persist) - the next run will start cold."
        )
    elif store.available:
        print(f"Baseline saved to: {store.db_path}")
    else:
        print(
            "[WARNING] Baseline could NOT be saved (see logs) - the next run "
            "will start from whatever was last written successfully."
        )
    print("Logs saved to the 'logs/' directory.")
    print("=" * 60)

    try:
        save_config(config)
    except Exception:  # noqa: BLE001
        pass

    log_module_event(logger, "MODULE_FINISHED", detail=f"packets={total_processed}")
    if health.last_error and total_processed == 0:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting safely.")
        sys.exit(0)
