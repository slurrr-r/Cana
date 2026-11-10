"""
app.py
======

Native CANA UI.

Opens a Windows desktop window and system tray. Closing the UI does
not stop monitoring. Packet capture is never started from here.
"""

from __future__ import annotations

import logging
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from cana_ui.controller import UIController
from cana_ui.window import CANAWindow, tray_status_text

_UI_LOG_FILE_NAME = "cana_ui.log"
_ui_handler: Optional[logging.Handler] = None


def configure_ui_logging(logs_dir: Optional[Path] = None) -> logging.Logger:
    """Give the UI its own log file.

    A PyInstaller ``console=False`` build has no console, so an unhandled
    startup exception vanishes and the window just flickers away. Writing
    ``cana_ui.log`` (plus an ``sys.excepthook``) makes those crashes
    diagnosable.
    """
    global _ui_handler
    logger = logging.getLogger("cana.ui")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if _ui_handler is None:
        try:
            target = Path(logs_dir) if logs_dir is not None else _default_ui_logs_dir()
            target.mkdir(parents=True, exist_ok=True)
            handler: logging.Handler = RotatingFileHandler(
                filename=str(target / _UI_LOG_FILE_NAME),
                maxBytes=1_000_000,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
        except Exception:  # noqa: BLE001 - never let logging stop the UI
            handler = logging.NullHandler()
        logger.addHandler(handler)
        _ui_handler = handler
    return logger


def _default_ui_logs_dir() -> Path:
    import os

    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "CANA" / "logs"


def _install_ui_excepthook(logger: logging.Logger) -> None:
    """Record unhandled exceptions instead of losing them silently."""

    def _hook(exc_type, exc_value, exc_tb) -> None:  # noqa: ANN001
        logger.error(
            "EVENT=UI_UNHANDLED_EXCEPTION",
            exc_info=(exc_type, exc_value, exc_tb),
        )

    sys.excepthook = _hook

    def _thread_hook(args) -> None:  # noqa: ANN001
        if args.exc_type is SystemExit:
            return
        logger.error(
            "EVENT=UI_THREAD_EXCEPTION",
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    try:
        threading.excepthook = _thread_hook
    except Exception:  # noqa: BLE001
        pass


def _install_tk_exception_logger(window: CANAWindow, logger: logging.Logger) -> None:
    """Route Tk callback exceptions to the UI log.

    Tkinter reports exceptions raised inside widget callbacks through
    ``report_callback_exception``, not ``sys.excepthook``. Without this,
    a fault in a button handler or the poll loop is printed to a console
    that a windowed (``console=False``) build does not have.
    """
    root = getattr(window, "_root", None)
    if root is None:
        return

    def _report(exc_type, exc_value, exc_tb) -> None:  # noqa: ANN001
        logger.error(
            "EVENT=UI_CALLBACK_EXCEPTION",
            exc_info=(exc_type, exc_value, exc_tb),
        )

    try:
        root.report_callback_exception = _report
    except Exception:  # noqa: BLE001
        pass


def _tray_image():
    from cana_ui.brand import tray_image, render_mark

    image = tray_image()
    if image is not None:
        return image
    try:
        from PIL import Image

        return Image.frombytes("RGBA", (64, 64), render_mark(64))
    except Exception:
        return None


def _start_tray(window: CANAWindow, controller: UIController):
    try:
        import pystray
    except ImportError:
        window.hide_on_close = False
        return None

    def _on_ui(callback) -> None:
        root = getattr(window, "_root", None)
        if root is not None:
            root.after(0, callback)
        else:
            callback()

    def open_cana(icon, item):  # noqa: ARG001
        _on_ui(window.show)

    def show_status(icon, item):  # noqa: ARG001
        def work() -> None:
            payload = controller.snapshot()
            icon.title = tray_status_text(payload)

        _on_ui(work)

    def start_monitoring(icon, item):  # noqa: ARG001
        def work() -> None:
            payload = controller.start_monitoring()
            icon.title = tray_status_text(payload)
            window.refresh()

        _on_ui(work)

    def stop_monitoring(icon, item):  # noqa: ARG001
        def work() -> None:
            payload = controller.stop_monitoring()
            icon.title = tray_status_text(payload)
            window.refresh()

        _on_ui(work)

    def open_settings(icon, item):  # noqa: ARG001
        def work() -> None:
            window.show()
            window._open_settings()

        _on_ui(work)

    def exit_ui(icon, item):  # noqa: ARG001
        icon.stop()
        window._root.after(0, window.destroy)

    image = _tray_image()
    if image is None:
        window.hide_on_close = False
        return None
    menu = pystray.Menu(
        pystray.MenuItem("Open CANA", open_cana, default=True),
        pystray.MenuItem("Monitoring Status", show_status),
        pystray.MenuItem("Start Monitoring", start_monitoring),
        pystray.MenuItem("Stop Monitoring", stop_monitoring),
        pystray.MenuItem("Settings", open_settings),
        pystray.MenuItem("Exit CANA UI", exit_ui),
    )
    icon = pystray.Icon("CANA", image, "CANA", menu)
    thread = threading.Thread(target=icon.run, name="CANATray", daemon=True)
    thread.start()
    return icon


def run_ui() -> int:
    """Start the native UI without owning capture."""
    _ui_logger = configure_ui_logging()
    _install_ui_excepthook(_ui_logger)
    _ui_logger.info("EVENT=UI_STARTED")
    controller = UIController()
    payload = controller.snapshot()
    if payload.get("service_unavailable"):
        message = payload.get("last_error") or "CANA service is not running."
        _ui_logger.warning("EVENT=UI_SERVICE_UNAVAILABLE message=%s", message)
        print(message)
    window = CANAWindow(controller, hide_on_close=True)
    window.create()
    _install_tk_exception_logger(window, _ui_logger)
    icon = _start_tray(window, controller)
    if icon is None:
        window.hide_on_close = False
        if window._root is not None:
            window._root.protocol("WM_DELETE_WINDOW", window.destroy)
    try:
        window.mainloop()
    finally:
        if icon is not None:
            try:
                icon.stop()
            except Exception:
                pass
        _ui_logger.info("EVENT=UI_STOPPED")
    return 0


def main(argv: Optional[list] = None) -> int:
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
