"""
window.py
=========

Native CANA console window.

A single light-theme window: a classic menu bar, a horizontal top nav
(Home | Apps | Alerts | History | Settings), the active page, and a
bottom status bar. It talks to the Windows service only through
:class:`~cana_ui.controller.UIController`; it never owns packet capture.
Closing the window does not stop monitoring.
"""

from __future__ import annotations

import csv
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cana_ui import theme
from cana_ui.brand import apply_window_icon, header_photo
from cana_ui.controller import (
    UIController,
    display_state_for,
    header_status,
    request_windows_service_install,
    runtime_states,
    technical_details,
    try_start_windows_service,
    user_facing_error,
)
from cana_ui.explain import (
    explain_alert,
    format_technical_details,
    known_application_name,
    learning_status,
)
from cana_ui.incidents import (
    SEVERITY_FILTERS,
    STATUS_FILTERS,
    build_incidents,
    build_kpis,
    filter_incidents,
)
from cana_ui.traffic import (
    DEFAULT_RANGE,
    RANGE_ORDER,
    SessionTrafficStore,
    format_bytes,
)
from cana_ui.widgets import (
    ActivityRow,
    AreaChart,
    CheckBox,
    EmptyState,
    FilterChip,
    KpiCard,
    LinkLabel,
    PillButton,
    RangePills,
    ScrollableFrame,
    SearchBox,
    SeverityBars,
    StatusBar,
    StatusDot,
    StatusTile,
    TopNav,
    TrafficChart,
)
# Packet filters offered by the service. Mirrors
# packet_capture.config.SUPPORTED_FILTERS without importing capture code
# into the UI client process.
PACKET_FILTERS = ("ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS")
LOGGING_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def validate_settings(updates: Dict[str, Any]) -> Optional[str]:
    """Return a user-facing problem with the Settings form, or ``None``.

    Validating locally keeps obviously bad values from reaching the
    service, so the UI never shows a raw config-apply failure.
    """
    packet_filter = str(updates.get("packet_filter") or "").strip().upper()
    if packet_filter not in PACKET_FILTERS:
        return "Choose a supported packet filter."
    logging_level = str(updates.get("logging_level") or "").strip().upper()
    if logging_level not in LOGGING_LEVELS:
        return "Choose a supported logging level."
    return None


_NAV_ITEMS = (
    ("home", "Home"),
    ("apps", "Apps"),
    ("alerts", "Alerts"),
    ("history", "History"),
    ("settings", "Settings"),
)

_MENUS = {
    "File": (
        ("Start service", "_menu_start_service", "Ctrl+Shift+S"),
        ("Start monitoring", "_menu_start", "Ctrl+M"),
        ("Stop monitoring", "_menu_stop", "Ctrl+T"),
        ("separator", None, None),
        ("Hide window", "_menu_hide", None),
        ("Exit", "_menu_exit", None),
    ),
    "View": (
        ("Home", "home", None),
        ("Apps", "apps", None),
        ("Alerts", "alerts", None),
        ("History", "history", None),
        ("Settings", "settings", None),
    ),
    "Tools": (
        ("Refresh now", "_menu_refresh", "F5"),
        ("Download alerts...", "_menu_download", None),
        ("separator", None, None),
        ("Settings", "settings", None),
    ),
    "Help": (
        ("About CANA", "_menu_about", None),
        ("View technical details", "_menu_details", None),
    ),
}

# Column widths (px) shared by the header and every row of the alerts table.
_ALERT_COL_SEVERITY = 110
_ALERT_COL_STATUS = 118
_ALERT_COL_SEEN = 122
_ALERT_COL_TAGS = 160

# Column widths (px) shared by the header and every row of the apps list.
_APPS_COL_BYTES = 82

# Column widths (px) shared by the header and every row of the history list.
_HISTORY_COL_IFACE = 150
_HISTORY_COL_PACKETS = 80
_HISTORY_COL_WHEN = 148
_HISTORY_COL_SIZE = 80


def _relative_time(value: Any) -> str:
    """Short, human timestamp such as ``today 14:02`` or ``2026-09-14 09:11``."""
    if not value:
        return "-"
    try:
        if isinstance(value, str) and not value.replace(".", "", 1).isdigit():
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
        else:
            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        local = moment.astimezone()
    except (TypeError, ValueError, OSError):
        return str(value)
    now = datetime.now(local.tzinfo)
    if local.date() == now.date():
        return local.strftime("today %H:%M")
    return local.strftime("%Y-%m-%d %H:%M")


def _human_size(size: int) -> str:
    """Compact byte size such as ``18.4 KB``."""
    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def alert_sentence(alert: Dict[str, Any]) -> str:
    """User-facing one-liner. Engine jargon stays in technical details."""
    explained = explain_alert(alert)
    return explained["title"]


def alert_meta(alert: Dict[str, Any]) -> str:
    """Readable ``source · time`` metadata; raw IPs stay in details."""
    source = known_application_name(alert.get("application_name") or alert.get("application"))
    if not source:
        source = "Unknown application"
    when = alert.get("triggered_at_epoch") or alert.get("triggered_at")
    return f"{source} · {_relative_time(when)}"


def home_headline(payload: Dict[str, Any], header: Dict[str, str]) -> Dict[str, str]:
    """Headline icon/title/subtitle and their semantic colors."""
    runtime = runtime_states(payload)
    del header
    if runtime["service"] == "not_installed":
        return {
            "icon": "stop",
            "title": "CANA service is not installed",
            "subtitle": "Install the CANA Windows service to begin monitoring.",
            "color": theme.RED,
        }
    if runtime["service"] == "starting":
        return {
            "icon": "alert",
            "title": "Service starting",
            "subtitle": "Waiting for the CANA Windows service to reach RUNNING.",
            "color": theme.AMBER,
        }
    if runtime["service"] == "start_failed":
        return {
            "icon": "stop",
            "title": "Service start failed",
            "subtitle": str(payload.get("last_error") or "The CANA Windows service did not start."),
            "color": theme.RED,
        }
    if runtime["service"] == "stop_failed":
        return {
            "icon": "stop",
            "title": "Service stop failed",
            "subtitle": str(payload.get("last_error") or "The CANA Windows service did not stop."),
            "color": theme.RED,
        }
    if runtime["service"] == "error":
        return {
            "icon": "stop",
            "title": "Service error",
            "subtitle": str(payload.get("last_error") or "The CANA Windows service reported an error."),
            "color": theme.RED,
        }
    if runtime["service"] == "unknown":
        return {
            "icon": "alert",
            "title": "Service state unknown",
            "subtitle": "Windows service state could not be determined.",
            "color": theme.AMBER,
        }
    if runtime["service"] == "stopping":
        return {
            "icon": "alert",
            "title": "Service stopping",
            "subtitle": "Waiting for the CANA Windows service to stop.",
            "color": theme.AMBER,
        }
    if runtime["service"] != "running":
        return {
            "icon": "stop",
            "title": "Service stopped",
            "subtitle": "Start the CANA service to begin monitoring.",
            "color": theme.RED,
        }
    last_error = str(payload.get("last_error") or "")
    if runtime.get("connection") == "disconnected":
        return {
            "icon": "stop",
            "title": "Connection lost",
            "subtitle": "CANA could not reach the background service.",
            "color": theme.RED,
        }
    if runtime.get("connection") == "reconnecting" or "reconnect" in last_error.lower() or "temporarily unavailable" in last_error.lower():
        return {
            "icon": "alert",
            "title": "Reconnecting",
            "subtitle": "CANA service connection was temporarily unavailable. Reconnecting...",
            "color": theme.AMBER,
        }
    if runtime.get("connection") == "connecting":
        return {
            "icon": "alert",
            "title": "Connecting...",
            "subtitle": "Checking monitoring status...",
            "color": theme.AMBER,
        }
    if runtime["monitoring"] == "unknown":
        return {
            "icon": "alert",
            "title": "Checking monitoring status...",
            "subtitle": "Waiting for the CANA Windows service to report its state.",
            "color": theme.AMBER,
        }
    if runtime["monitoring"] == "starting":
        return {
            "icon": "alert",
            "title": "Monitoring starting",
            "subtitle": "Waiting for the service to confirm monitoring.",
            "color": theme.AMBER,
        }
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return {
            "icon": "shield",
            "title": "Monitoring active",
            "subtitle": (
                "3 alert rules enabled: TCP port probes and unusual TCP flags."
            ),
            "color": theme.GREEN,
        }
    if runtime["monitoring"] == "running":
        return {
            "icon": "alert",
            "title": "Capture unavailable",
            "subtitle": "Packet capture is unavailable.",
            "color": theme.AMBER,
        }
    return {
        "icon": "stop",
        "title": "Monitoring stopped",
        "subtitle": "Start monitoring to begin capturing traffic.",
        "color": theme.AMBER,
    }


def status_bar_text(payload: Dict[str, Any]) -> str:
    """Current monitoring state only. Historical Apps data does not change this."""
    runtime = runtime_states(payload)
    if runtime["service"] == "not_installed":
        return "Service not installed"
    if runtime["service"] == "starting":
        return "Service starting"
    if runtime["service"] == "start_failed":
        return "Service start failed"
    if runtime["service"] == "stop_failed":
        return "Service stop failed"
    if runtime["service"] == "error":
        return "Service error"
    if runtime.get("connection") == "disconnected":
        return "Connection lost"
    if runtime["service"] == "unknown":
        return "Connecting..."
    if runtime["service"] == "stopping":
        return "Service stopping"
    if runtime["service"] != "running":
        return "Service stopped"
    last_error = str(payload.get("last_error") or "")
    if runtime.get("connection") == "reconnecting" or "reconnect" in last_error.lower() or "temporarily unavailable" in last_error.lower():
        return "Reconnecting"
    if runtime["monitoring"] == "unknown":
        return "Checking monitoring status..."
    if runtime["monitoring"] == "starting":
        return "Monitoring starting"
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Capture running"
    if runtime["monitoring"] == "running" and runtime["capture"] in {"failed", "unavailable"}:
        return "Capture unavailable"
    if runtime["monitoring"] == "running":
        return "Monitoring running"
    return "Monitoring stopped"


def apps_source_caption(payload: Dict[str, Any], has_data: bool) -> str:
    runtime = runtime_states(payload)
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Live application traffic"
    if has_data:
        return "Historical application traffic"
    return "No stored session traffic"


def apps_source_subtitle(payload: Dict[str, Any], has_data: bool) -> str:
    runtime = runtime_states(payload)
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Live application traffic from the current monitoring session."
    if has_data:
        return "Traffic captured during previous CANA sessions."
    return "No stored session traffic in this range."


def alerts_source_caption(payload: Dict[str, Any]) -> str:
    runtime = runtime_states(payload)
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Current monitoring alerts"
    return "Historical alerts"


def history_source_caption(payload: Dict[str, Any], has_data: bool) -> str:
    runtime = runtime_states(payload)
    if runtime["monitoring"] == "running" and runtime["capture"] == "running":
        return "Current session plus earlier capture sessions written to disk."
    if has_data:
        return "Capture sessions CANA has already written to disk."
    return "No capture sessions recorded yet."


def tray_status_text(payload: Dict[str, Any]) -> str:
    return f"CANA - {display_state_for(payload)}"


def home_actions(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Primary/secondary Home buttons from the same runtime snapshot."""
    runtime = runtime_states(payload)
    service = runtime.get("service")
    monitoring = runtime.get("monitoring")
    if monitoring in {"running", "starting"}:
        return {
            "primary": "Stop monitoring",
            "primary_enabled": monitoring == "running",
            "secondary": "Start monitoring",
            "secondary_enabled": False,
        }
    if service == "running":
        return {
            "primary": "Service running",
            "primary_enabled": False,
            "secondary": "Start monitoring",
            "secondary_enabled": True,
        }
    if service == "starting":
        return {
            "primary": "Service starting",
            "primary_enabled": False,
            "secondary": "Start monitoring",
            "secondary_enabled": False,
        }
    if service == "stopping":
        return {
            "primary": "Service stopping",
            "primary_enabled": False,
            "secondary": "Start monitoring",
            "secondary_enabled": False,
        }
    if service == "not_installed":
        return {
            "primary": "Install service",
            "primary_enabled": True,
            "secondary": "Start monitoring",
            "secondary_enabled": False,
        }
    return {
        "primary": "Start service",
        "primary_enabled": True,
        "secondary": "Start monitoring",
        "secondary_enabled": False,
    }


def activity_list_signature(alerts: List[Dict[str, Any]]) -> tuple:
    return tuple(
        (
            str(alert.get("severity") or ""),
            alert_sentence(alert),
            alert_meta(alert),
        )
        for alert in alerts
    )


def apps_list_signature(
    apps: List[Any],
    query: str,
    selected: Optional[str],
    range_key: str,
) -> tuple:
    return (
        range_key,
        query.lower(),
        selected or "",
        tuple(
            (
                getattr(app, "name", ""),
                int(getattr(app, "down_bytes", 0) or 0),
                int(getattr(app, "up_bytes", 0) or 0),
            )
            for app in apps
        ),
    )


def alerts_list_signature(
    incidents: List[Any],
    severity: str,
    status: str,
    search: str,
) -> tuple:
    return (
        severity,
        status,
        search,
        tuple(
            (
                getattr(incident, "key", ""),
                getattr(incident, "name", ""),
                getattr(incident, "severity", ""),
                getattr(incident, "status", ""),
                getattr(incident, "first_seen_epoch", None),
                tuple(getattr(incident, "tags", ()) or ()),
            )
            for incident in incidents
        ),
    )


def history_list_signature(rows: List[Dict[str, Any]]) -> tuple:
    return tuple(
        (
            str(row.get("session_id") or row.get("name") or ""),
            str(row.get("interface") or "Unknown"),
            str(row.get("packet_count") or 0),
            row.get("started_at_epoch") or row.get("started_at"),
            int(row.get("size_bytes") or 0),
        )
        for row in rows
    )


class CANAWindow:
    def __init__(
        self,
        controller: Optional[UIController] = None,
        *,
        on_exit: Optional[Callable[[], None]] = None,
        poll_ms: int = 2000,
        hide_on_close: bool = True,
    ) -> None:
        self.controller = controller or UIController()
        self.on_exit = on_exit
        self.poll_ms = poll_ms
        self.hide_on_close = hide_on_close
        self._root = None
        self._widgets: Dict[str, Any] = {}
        self._pages: Dict[str, Any] = {}
        self._closed = False
        self._busy = False
        self._ipc_seq = 0
        self._poll_after_id = None
        self._current_page = ""
        self._list_signatures: Dict[str, Any] = {}
        self._technical_details = ""

        # Service data
        self._payload: Dict[str, Any] = {}
        self._correlated_rows: List[Dict[str, Any]] = []
        self._alert_incidents: List[Any] = []
        self._kpis: List[Dict[str, str]] = []

        # Apps page state
        self._traffic = SessionTrafficStore()
        self._apps_range = DEFAULT_RANGE
        self._selected_app: Optional[str] = None
        self._apps_data: List[Any] = []
        self._apps_seq = 0
        self._apps_pending: Optional[Dict[str, Any]] = None
        self._apps_inflight = 0
        self._apps_drain_scheduled = False

        # Alerts page state
        self._alert_severity = "All"
        self._alert_status = "All"
        self._alert_search = ""

        # History page state
        self._history_rows: List[Dict[str, Any]] = []

        # Live traffic sampler
        self._traffic_samples: List[float] = []
        self._traffic_rate = 0.0
        self._last_packets: Optional[int] = None
        self._last_sample_at: Optional[float] = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def create(self):
        import tkinter as tk

        root = tk.Tk()
        theme.init_dpi(root)
        root.title("CANA")
        root.geometry(f"{theme.WINDOW_WIDTH}x{theme.WINDOW_HEIGHT}")
        root.minsize(theme.MIN_WIDTH, theme.MIN_HEIGHT)
        root.configure(bg=theme.SURFACE_2)
        self._root = root
        apply_window_icon(root)
        self._style(root)

        shell = tk.Frame(root, bg=theme.SURFACE_2)
        shell.pack(fill="both", expand=True)

        self._build_menu_bar(root, tk)
        self._build_header(shell, tk)
        self._build_status_bar(shell, tk)

        host = tk.Frame(shell, bg=theme.SURFACE_2)
        host.pack(fill="both", expand=True)
        self._build_pages(host, tk)

        root.protocol("WM_DELETE_WINDOW", self.hide if self.hide_on_close else self.destroy)
        self._schedule_poll()
        self._show_page("home")
        # Paint from the last known payload so the first frame is not blank
        # while the off-thread snapshot is in flight.
        self._apply_bundle(
            {
                "payload": dict(self.controller.last_payload or {}),
                "apps": [],
                "series": None,
                "correlated": [],
                "history": [],
            }
        )
        self.refresh()
        return root

    def _style(self, root) -> None:
        import tkinter as tk
        from tkinter import ttk

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Light.TCombobox",
            fieldbackground=theme.SURFACE_2,
            background=theme.SURFACE_2,
            foreground=theme.TEXT_PRIMARY,
            arrowcolor=theme.TEXT_SECONDARY,
            bordercolor=theme.BORDER,
            lightcolor=theme.BORDER,
            darkcolor=theme.BORDER,
            padding=(6, 3),
        )
        style.map(
            "Light.TCombobox",
            fieldbackground=[("readonly", theme.SURFACE_2), ("!disabled", theme.SURFACE_2)],
            foreground=[("readonly", theme.TEXT_PRIMARY)],
            selectbackground=[("readonly", theme.SURFACE_2)],
            selectforeground=[("readonly", theme.TEXT_PRIMARY)],
        )
        root.option_add("*TCombobox*Listbox.background", theme.SURFACE_2)
        root.option_add("*TCombobox*Listbox.foreground", theme.TEXT_PRIMARY)
        root.option_add("*TCombobox*Listbox.selectBackground", theme.ACCENT_TINT)
        root.option_add("*TCombobox*Listbox.selectForeground", theme.ACCENT_TEXT)

    # ------------------------------------------------------------------
    # Chrome: menu bar, top nav, status bar
    # ------------------------------------------------------------------
    def _build_menu_bar(self, root, tk) -> None:
        menubar = tk.Menu(root, tearoff=0)
        self._widgets["menubar"] = menubar
        self._menu_items = {}
        for name, entries in _MENUS.items():
            cascade = tk.Menu(menubar, tearoff=0, font=theme.FONT_MENU)
            self._widgets[f"menu_{name.lower()}"] = cascade
            for entry in entries:
                text, action, accelerator = entry
                if text == "separator":
                    cascade.add_separator()
                    continue
                if action in _NAV_KEYS:
                    command = lambda a=action: self._show_page(a)
                else:
                    command = self._menu_action(action)
                kwargs = {"label": text, "command": command}
                if accelerator:
                    kwargs["accelerator"] = accelerator
                    self._bind_accelerator(root, accelerator, command)
                cascade.add_command(**kwargs)
                self._menu_items[action] = (cascade, cascade.index("end"))
            menubar.add_cascade(label=name, menu=cascade)
        root.config(menu=menubar)
        self._sync_menu_state()

    def _bind_accelerator(self, root, accelerator: str, command: Callable[[], None]) -> None:
        sequence = accelerator.lower().replace("ctrl+", "Control-").replace("shift+", "Shift-")
        if sequence.startswith("f") and sequence[1:].isdigit():
            sequence = f"<{accelerator}>"
        else:
            sequence = f"<{sequence}>"
        root.bind_all(sequence, lambda _e, fn=command: fn())

    def _menu_action(self, action: str) -> Callable[[], None]:
        table = {
            "_menu_start_service": self._on_start_service,
            "_menu_start": self._on_start,
            "_menu_stop": self._on_stop,
            "_menu_hide": self.hide,
            "_menu_exit": self.destroy,
            "_menu_refresh": self.refresh,
            "_menu_download": self._download_activity,
            "_menu_about": self._show_about,
            "_menu_details": self._show_technical_details,
        }
        return table.get(action, lambda: None)

    def _sync_menu_state(self, header: Optional[Dict[str, str]] = None) -> None:
        items = getattr(self, "_menu_items", None)
        if not items:
            return
        header = header or {}
        runtime = runtime_states(self._payload or {})
        monitoring = runtime.get("monitoring") == "running" or header.get("monitoring") == "Active"
        service_up = runtime.get("service") == "running" or header.get("service") == "Running"
        mapping = {
            "_menu_start_service": "disabled" if service_up else "normal",
            "_menu_start": "disabled" if monitoring or not service_up else "normal",
            "_menu_stop": "normal" if monitoring else "disabled",
        }
        for action, state in mapping.items():
            pair = items.get(action)
            if pair is None:
                continue
            menu, index = pair
            try:
                menu.entryconfig(index, state=state)
            except Exception:
                pass

    def _build_header(self, parent, tk) -> None:
        bar = tk.Frame(parent, bg=theme.SURFACE_2)
        bar.pack(fill="x")
        brand = tk.Frame(bar, bg=theme.SURFACE_2)
        brand.pack(side="left", padx=(16, 8), pady=(10, 8))
        logo = header_photo(20)
        if logo is not None:
            self._widgets["header_logo"] = logo
            tk.Label(brand, image=logo, bg=theme.SURFACE_2).pack(side="left", padx=(0, 7))
        tk.Label(
            brand, text="CANA", font=(theme.FONT_FAMILY, 12, "bold"),
            fg=theme.TEXT_PRIMARY, bg=theme.SURFACE_2,
        ).pack(side="left")
        tk.Label(
            brand, text="Network Monitor", font=theme.FONT_SMALL,
            fg=theme.TEXT_MUTED, bg=theme.SURFACE_2,
        ).pack(side="left", padx=(8, 0), pady=(2, 0))
        self._widgets["nav"] = TopNav(bar, _NAV_ITEMS, self._show_page)
        self._widgets["nav"].pack(side="left", padx=(18, 0), fill="y")
        theme.hairline(parent, theme.BORDER).pack(fill="x")

    def _show_about(self) -> None:
        from tkinter import messagebox

        messagebox.showinfo(
            "About CANA",
            "CANA — Context-Aware Network Behavior Analyzer\n\n"
            "Status and control for the CANA background service.",
            parent=self._root,
        )

    def _show_technical_details(self) -> None:
        from tkinter import messagebox

        payload = self._payload or {}
        detail = str(
            payload.get("technical_details")
            or self._technical_details
            or payload.get("last_error")
            or "No technical details are available."
        )
        messagebox.showinfo("Technical details", detail, parent=self._root)

    def _build_status_bar(self, parent, tk) -> None:
        self._widgets["statusbar"] = StatusBar(parent)
        self._widgets["statusbar"].pack(side="bottom", fill="x")

    # ------------------------------------------------------------------
    # Pages
    # ------------------------------------------------------------------
    def _build_pages(self, parent, tk) -> None:
        self._build_status(parent, tk)
        self._build_apps(parent, tk)
        self._build_alerts(parent, tk)
        self._build_history(parent, tk)
        self._build_settings_page(parent, tk)

    def _new_page(self, parent, tk, key: str):
        page = tk.Frame(parent, bg=theme.SURFACE_2)
        self._pages[key] = page
        return page

    def _page_title(self, parent, tk, title: str, subtitle: str) -> Any:
        block = tk.Frame(parent, bg=theme.SURFACE_2)
        block.pack(fill="x", padx=20, pady=(18, 12))
        tk.Label(
            block, text=title, font=theme.FONT_TITLE, fg=theme.TEXT_PRIMARY, bg=theme.SURFACE_2,
            anchor="w",
        ).pack(anchor="w")
        subtitle_label = tk.Label(
            block, text=subtitle, font=theme.FONT_SUBTITLE, fg=theme.TEXT_SECONDARY,
            bg=theme.SURFACE_2, anchor="w",
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))
        block.subtitle = subtitle_label
        return block

    # -- Home -----------------------------------------------------------
    def _build_status(self, parent, tk) -> None:
        page = self._new_page(parent, tk, "home")
        self._widgets["status"] = page

        head = tk.Frame(page, bg=theme.SURFACE_2)
        head.pack(fill="x", padx=20, pady=(18, 14))
        col = tk.Frame(head, bg=theme.SURFACE_2)
        col.pack(side="left", fill="x", expand=True)
        self._widgets["headline"] = tk.Label(
            col, text="Service stopped", font=theme.FONT_TITLE, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2, anchor="w",
        )
        self._widgets["headline"].pack(anchor="w")
        self._widgets["subtitle"] = tk.Label(
            col,
            text="Monitoring and detection are off until the service starts.",
            font=theme.FONT_SUBTITLE,
            fg=theme.TEXT_SECONDARY,
            bg=theme.SURFACE_2,
            anchor="w",
        )
        self._widgets["subtitle"].pack(anchor="w", pady=(1, 0))

        actions = tk.Frame(col, bg=theme.SURFACE_2)
        actions.pack(anchor="w", pady=(12, 0))
        self._widgets["btn_primary"] = PillButton(actions, "Start service", self._on_start_service)
        self._widgets["btn_primary"].pack(side="left")
        self._widgets["btn_secondary"] = PillButton(
            actions, "Start monitoring", self._on_start, variant="outline"
        )
        self._widgets["btn_secondary"].pack(side="left", padx=(8, 0))
        self._widgets["message"] = tk.Label(
            col, text="", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED, bg=theme.SURFACE_2, anchor="w",
        )
        self._widgets["message"].pack(anchor="w", pady=(8, 0))

        theme.hairline(page, theme.BORDER).pack(fill="x")
        tiles = tk.Frame(page, bg=theme.SURFACE_2)
        tiles.pack(fill="x", padx=20, pady=12)
        tiles.columnconfigure(0, weight=1)
        tiles.columnconfigure(1, weight=1)
        tiles.columnconfigure(2, weight=1)
        self._widgets["tile_monitoring"] = StatusTile(tiles, "Monitoring")
        self._widgets["tile_monitoring"].grid(row=0, column=0, sticky="w")
        self._widgets["tile_detection"] = StatusTile(tiles, "Detection")
        self._widgets["tile_detection"].grid(row=0, column=1, sticky="w")
        self._widgets["tile_capture"] = StatusTile(tiles, "Capture")
        self._widgets["tile_capture"].grid(row=0, column=2, sticky="w")

        theme.hairline(page, theme.BORDER).pack(fill="x")
        chart_block = tk.Frame(page, bg=theme.SURFACE_2)
        chart_block.pack(fill="x", padx=20, pady=12)
        title_row = tk.Frame(chart_block, bg=theme.SURFACE_2)
        title_row.pack(fill="x", pady=(0, 8))
        tk.Label(
            title_row, text="Network traffic", font=theme.FONT_SECTION, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2,
        ).pack(side="left")
        tk.Label(
            title_row, text="— last hour", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2,
        ).pack(side="left", padx=(6, 0))
        self._widgets["chart"] = TrafficChart(chart_block)
        self._widgets["chart"].pack(fill="x")

        theme.hairline(page, theme.BORDER).pack(fill="x")
        activity = tk.Frame(page, bg=theme.SURFACE_2)
        activity.pack(fill="both", expand=True)
        header_row = tk.Frame(activity, bg=theme.SURFACE_2)
        header_row.pack(fill="x", padx=20, pady=(10, 6))
        tk.Label(
            header_row, text="Recent activity", font=theme.FONT_SECTION, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2,
        ).pack(side="left")
        LinkLabel(header_row, "See all alerts", self._show_alerts).pack(side="right")
        LinkLabel(
            header_row, "Download", self._download_activity, icon="download"
        ).pack(side="right", padx=(0, 14))
        self._widgets["activity_list"] = tk.Frame(activity, bg=theme.SURFACE_2)
        self._widgets["activity_list"].pack(fill="both", expand=True)

    # -- Apps -----------------------------------------------------------
    def _build_apps(self, parent, tk) -> None:
        page = self._new_page(parent, tk, "apps")
        apps_title = self._page_title(
            page,
            tk,
            "Applications",
            "Traffic captured during previous CANA sessions.",
        )
        self._widgets["apps_subtitle"] = apps_title.subtitle
        theme.hairline(page, theme.BORDER).pack(fill="x")

        toolbar = tk.Frame(page, bg=theme.SURFACE_2)
        toolbar.pack(fill="x", padx=16, pady=10)
        search = SearchBox(toolbar, placeholder="Search applications", width=22)
        search.pack(side="left")
        search.bind_search(self._on_apps_search)
        self._widgets["apps_search"] = search
        self._widgets["range_pills"] = RangePills(
            toolbar, RANGE_ORDER, self._on_range_change, selected=self._apps_range
        )
        self._widgets["range_pills"].pack(side="right")

        theme.hairline(page, theme.BORDER).pack(fill="x")
        body = tk.Frame(page, bg=theme.SURFACE_2)
        body.pack(fill="both", expand=True)

        left = tk.Frame(body, bg=theme.SURFACE_2, width=theme.APPS_PANEL_WIDTH)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        theme.vhairline(left, theme.BORDER).pack(side="right", fill="y")
        self._apps_header(left, tk)
        theme.hairline(left, theme.BORDER).pack(fill="x")
        self._widgets["apps_list"] = ScrollableFrame(left)
        self._widgets["apps_list"].pack(fill="both", expand=True)

        right = tk.Frame(body, bg=theme.SURFACE_2)
        right.pack(side="left", fill="both", expand=True, padx=16, pady=12)
        top = tk.Frame(right, bg=theme.SURFACE_2)
        top.pack(fill="x")
        self._widgets["apps_total"] = tk.Label(
            top, text="0 B total", font=theme.FONT_SECTION, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2,
        )
        self._widgets["apps_total"].pack(side="left")
        self._widgets["apps_caption"] = tk.Label(
            top, text="All applications", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2,
        )
        self._widgets["apps_caption"].pack(side="left", padx=(8, 0))
        self._widgets["apps_chart"] = AreaChart(right, height=240)
        self._widgets["apps_chart"].pack(fill="both", expand=True, pady=(10, 0))
        legend = tk.Frame(right, bg=theme.SURFACE_2)
        legend.pack(fill="x", pady=(8, 0))
        swatch_in = tk.Frame(legend, bg=theme.ACCENT, width=10, height=10)
        swatch_in.pack(side="left")
        swatch_in.pack_propagate(False)
        self._widgets["apps_legend_in"] = tk.Label(
            legend, text="Received 0 B", font=theme.FONT_SMALL, fg=theme.TEXT_SECONDARY,
            bg=theme.SURFACE_2,
        )
        self._widgets["apps_legend_in"].pack(side="left", padx=(6, 16))
        swatch_out = tk.Frame(legend, bg=theme.GREEN, width=10, height=10)
        swatch_out.pack(side="left")
        swatch_out.pack_propagate(False)
        self._widgets["apps_legend_out"] = tk.Label(
            legend, text="Sent 0 B", font=theme.FONT_SMALL, fg=theme.TEXT_SECONDARY,
            bg=theme.SURFACE_2,
        )
        self._widgets["apps_legend_out"].pack(side="left", padx=(6, 0))
        self._widgets["apps_legend"] = self._widgets["apps_legend_in"]

    def _apps_header(self, parent, tk) -> None:
        header = tk.Frame(parent, bg=theme.SURFACE_2)
        header.pack(fill="x", padx=12, pady=(9, 7))
        tk.Label(
            header, text="Application", font=theme.FONT_TILE_LABEL, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        ).pack(side="left", fill="x", expand=True)
        for title in ("In", "Out"):
            cell = tk.Frame(header, bg=theme.SURFACE_2, width=_APPS_COL_BYTES, height=14)
            cell.pack(side="left")
            cell.pack_propagate(False)
            tk.Label(
                cell, text=title, font=theme.FONT_TILE_LABEL, fg=theme.TEXT_MUTED,
                bg=theme.SURFACE_2, anchor="e",
            ).pack(fill="both", expand=True)

    # -- Alerts ---------------------------------------------------------
    def _build_alerts(self, parent, tk) -> None:
        page = self._new_page(parent, tk, "alerts")
        alerts_title = self._page_title(
            page, tk, "Alerts", "Historical alerts."
        )
        self._widgets["alerts_subtitle"] = alerts_title.subtitle

        kpi_row = tk.Frame(page, bg=theme.SURFACE_2)
        kpi_row.pack(fill="x", padx=16, pady=(0, 12))
        for column in range(4):
            kpi_row.columnconfigure(column, weight=1, uniform="kpi")
        self._kpi_cards: List[KpiCard] = []
        for column, label in enumerate(
            ("Alerts this week", "Auto-resolved", "Devices flagged", "Avg. time to detect")
        ):
            card = KpiCard(kpi_row, label, "—")
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 5, 0))
            self._kpi_cards.append(card)
        self._kpis = [{"label": label, "value": "—"} for label in (
            "Alerts this week", "Auto-resolved", "Devices flagged", "Avg. time to detect"
        )]

        filters = tk.Frame(page, bg=theme.SURFACE_2)
        filters.pack(fill="x", padx=16)
        self._widgets["sev_chip"] = FilterChip(
            filters, "Severity: All", self._cycle_severity, bg=theme.SURFACE_2
        )
        self._widgets["sev_chip"].pack(side="left", padx=(0, 6))
        self._widgets["status_chip"] = FilterChip(
            filters, "Status: All", self._cycle_status, bg=theme.SURFACE_2
        )
        self._widgets["status_chip"].pack(side="left")
        LinkLabel(
            filters, "Export", self._download_activity, icon="download"
        ).pack(side="right")
        search = SearchBox(filters, placeholder="Search alerts", width=20)
        search.pack(side="right", padx=(0, 14))
        search.bind_search(self._on_alerts_search)
        self._widgets["alerts_search"] = search

        self._widgets["alerts_count"] = tk.Label(
            page, text="", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED, bg=theme.SURFACE_2,
            anchor="w",
        )
        self._widgets["alerts_count"].pack(fill="x", padx=16, pady=(9, 0))

        theme.hairline(page, theme.BORDER).pack(fill="x", pady=(6, 0))
        self._alerts_header(page, tk)
        theme.hairline(page, theme.BORDER).pack(fill="x")
        self._widgets["alerts_list"] = ScrollableFrame(page)
        self._widgets["alerts_list"].pack(fill="both", expand=True)

    def _alerts_header(self, parent, tk) -> None:
        header = tk.Frame(parent, bg=theme.SURFACE_2)
        header.pack(fill="x", padx=16, pady=7)
        CheckBox(header, bg=theme.SURFACE_2).canvas.pack(side="left", padx=(0, 10))
        tk.Label(
            header, text="Alert name", font=theme.FONT_TABLE_HEAD, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        ).pack(side="left", fill="x", expand=True)
        for text, width in (
            ("Severity", _ALERT_COL_SEVERITY),
            ("Status", _ALERT_COL_STATUS),
            ("First seen", _ALERT_COL_SEEN),
            ("Tags", _ALERT_COL_TAGS),
        ):
            cell = tk.Frame(header, bg=theme.SURFACE_2, width=width, height=15)
            cell.pack(side="left")
            cell.pack_propagate(False)
            tk.Label(
                cell, text=text, font=theme.FONT_TABLE_HEAD, fg=theme.TEXT_MUTED,
                bg=theme.SURFACE_2, anchor="w",
                    ).pack(fill="both", expand=True)

    # -- History --------------------------------------------------------
    def _build_history(self, parent, tk) -> None:
        page = self._new_page(parent, tk, "history")
        history_title = self._page_title(
            page,
            tk,
            "History",
            "Capture sessions CANA has already written to disk.",
        )
        self._widgets["history_subtitle"] = history_title.subtitle
        theme.hairline(page, theme.BORDER).pack(fill="x")
        self._widgets["history_count"] = tk.Label(
            page, text="", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED, bg=theme.SURFACE_2,
            anchor="w",
        )
        self._widgets["history_count"].pack(fill="x", padx=16, pady=(9, 0))
        theme.hairline(page, theme.BORDER).pack(fill="x", pady=(6, 0))
        self._history_header(page, tk)
        theme.hairline(page, theme.BORDER).pack(fill="x")
        self._widgets["history_list"] = ScrollableFrame(page)
        self._widgets["history_list"].pack(fill="both", expand=True)

    def _history_header(self, parent, tk) -> None:
        header = tk.Frame(parent, bg=theme.SURFACE_2)
        header.pack(fill="x", padx=16, pady=7)
        tk.Label(
            header, text="Session", font=theme.FONT_TABLE_HEAD, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        ).pack(side="left", fill="x", expand=True)
        for text, width in (
            ("Interface", _HISTORY_COL_IFACE),
            ("Packets", _HISTORY_COL_PACKETS),
            ("Started", _HISTORY_COL_WHEN),
            ("Size", _HISTORY_COL_SIZE),
        ):
            cell = tk.Frame(header, bg=theme.SURFACE_2, width=width, height=15)
            cell.pack(side="left")
            cell.pack_propagate(False)
            tk.Label(
                cell, text=text, font=theme.FONT_TABLE_HEAD, fg=theme.TEXT_MUTED,
                bg=theme.SURFACE_2, anchor="w",
            ).pack(fill="both", expand=True)

    # -- Settings -------------------------------------------------------
    def _build_settings_page(self, parent, tk) -> None:
        page = self._new_page(parent, tk, "settings")
        self._page_title(
            page, tk, "Settings", "Capture, logging, and startup preferences for the service."
        )
        theme.hairline(page, theme.BORDER).pack(fill="x")
        form = tk.Frame(page, bg=theme.SURFACE_2)
        form.pack(fill="x", padx=20, pady=14)
        self._build_settings_form(form, tk)

    def _build_settings_form(self, parent, tk) -> None:
        self._widgets["set_iface"] = self._entry(parent, tk, "Capture interface")
        self._widgets["set_filter"] = self._choice(
            parent, tk, "Packet filter", list(PACKET_FILTERS)
        )
        self._widgets["set_level"] = self._choice(
            parent, tk, "Logging level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        )
        for key, label in (
            ("set_monitor", "Monitoring enabled"),
            ("set_startup", "Automatic startup"),
            ("set_persist", "Persistence"),
            ("set_notify", "Desktop notifications"),
        ):
            self._widgets[key] = self._check(parent, tk, label)
        actions = tk.Frame(parent, bg=theme.SURFACE_2)
        actions.pack(fill="x", pady=(14, 0))
        PillButton(actions, "Apply", self._on_apply_settings).pack(side="left")
        self._widgets["set_msg"] = tk.Label(
            actions, text="", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED, bg=theme.SURFACE_2,
        )
        self._widgets["set_msg"].pack(side="left", padx=10)
        self._load_settings()

    # -- settings form primitives ---------------------------------------
    def _entry(self, parent, tk, label: str):
        row = tk.Frame(parent, bg=theme.SURFACE_2)
        row.pack(fill="x", pady=5)
        tk.Label(
            row, text=label, font=theme.FONT_BODY, fg=theme.TEXT_SECONDARY, bg=theme.SURFACE_2,
            width=20, anchor="w",
        ).pack(side="left")
        var = tk.StringVar()
        entry = tk.Entry(
            row, textvariable=var, font=theme.FONT_BODY, bg=theme.SURFACE_SUNKEN,
            fg=theme.TEXT_PRIMARY, insertbackground=theme.TEXT_PRIMARY, relief="flat",
            highlightthickness=1, highlightbackground=theme.BORDER,
            highlightcolor=theme.ACCENT,
        )
        entry.pack(side="left", ipady=4, fill="x", expand=True)
        return var

    def _choice(self, parent, tk, label: str, values):
        from tkinter import ttk

        row = tk.Frame(parent, bg=theme.SURFACE_2)
        row.pack(fill="x", pady=5)
        tk.Label(
            row, text=label, font=theme.FONT_BODY, fg=theme.TEXT_SECONDARY, bg=theme.SURFACE_2,
            width=20, anchor="w",
        ).pack(side="left")
        var = tk.StringVar()
        box = ttk.Combobox(
            row, textvariable=var, values=values, state="readonly", width=22,
            style="Light.TCombobox", font=theme.FONT_BODY,
        )
        box.pack(side="left")
        return var

    def _check(self, parent, tk, label: str):
        row = tk.Frame(parent, bg=theme.SURFACE_2)
        row.pack(fill="x", pady=3)
        var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            row, text=label, variable=var, font=theme.FONT_BODY, bg=theme.SURFACE_2,
            fg=theme.TEXT_PRIMARY, activebackground=theme.SURFACE_2,
            activeforeground=theme.TEXT_PRIMARY, selectcolor=theme.SURFACE_2,
            highlightthickness=0,
        ).pack(anchor="w")
        return var

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def _show_page(self, key: str) -> None:
        if key not in self._pages:
            return
        already = key == self._current_page
        self._current_page = key
        if not already:
            for name, page in self._pages.items():
                if name == key:
                    page.pack(fill="both", expand=True)
                else:
                    page.pack_forget()
            nav = self._widgets.get("nav")
            if nav is not None:
                nav.set_active(key)
        if key == "settings":
            self._load_settings()
        elif already:
            return
        elif key == "apps":
            self._refresh_apps_off_thread()
        elif key == "alerts":
            self._render_alerts()
        elif key == "history":
            self._render_history()

    def _show_status(self) -> None:
        self._show_page("home")

    def _open_settings(self) -> None:
        if self._root is None:
            return
        self._show_page("settings")
        self._run_off_thread(
            self.controller.get_config, self._apply_settings_config, force=True
        )

    # ------------------------------------------------------------------
    # Show / hide / lifecycle
    # ------------------------------------------------------------------
    def show(self) -> None:
        if self._root is None:
            self.create()
        assert self._root is not None
        self._closed = False
        self._root.deiconify()
        self._root.lift()
        self._root.focus_force()

    def hide(self) -> None:
        if self._root is None:
            return
        self._root.withdraw()

    def destroy(self) -> None:
        self._closed = True
        if self._root is not None:
            if self._poll_after_id is not None:
                try:
                    self._root.after_cancel(self._poll_after_id)
                except Exception:  # noqa: BLE001
                    pass
                self._poll_after_id = None
            self._root.destroy()
            self._root = None
        if self.on_exit is not None:
            self.on_exit()

    def mainloop(self) -> None:
        if self._root is None:
            self.create()
        assert self._root is not None
        self._root.mainloop()

    # ------------------------------------------------------------------
    # Polling and IPC
    # ------------------------------------------------------------------
    def _schedule_poll(self) -> None:
        if self._root is None or self._closed:
            return
        if self._poll_after_id is not None:
            try:
                self._root.after_cancel(self._poll_after_id)
            except Exception:  # noqa: BLE001
                pass
            self._poll_after_id = None
        self._poll_after_id = self._root.after(self.poll_ms, self._poll)

    def _poll(self) -> None:
        if self._closed or self._root is None:
            return
        self._poll_after_id = None
        self.refresh()
        self._schedule_poll()

    def _run_off_thread(
        self,
        work: Callable[[], Any],
        done: Callable[[Any], None],
        *,
        force: bool = False,
    ) -> None:
        if self._root is None:
            return
        if self._busy and not force:
            return
        self._busy = True
        self._ipc_seq += 1
        seq = self._ipc_seq

        def worker() -> None:
            result = None
            try:
                result = work()
            except Exception as extra:  # noqa: BLE001
                result = extra
            root = self._root
            if root is None or self._closed:
                if seq == self._ipc_seq:
                    self._busy = False
                return
            try:
                root.after(0, lambda: self._finish_off_thread(done, result, seq))
            except Exception:  # noqa: BLE001
                if seq == self._ipc_seq:
                    self._busy = False

        threading.Thread(target=worker, name="CANAUIPipe", daemon=True).start()

    def _finish_off_thread(
        self, done: Callable[[Any], None], result: Any, seq: int
    ) -> None:
        if seq != self._ipc_seq:
            return
        self._busy = False
        if self._closed or self._root is None:
            return
        done(result)

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------
    def _collect(self) -> Dict[str, Any]:
        payload = self.controller.snapshot()
        range_key = self._apps_range
        try:
            apps = self._traffic.apps(range_key)
            series = self._traffic.series(self._selected_app, range_key)
        except Exception:  # noqa: BLE001
            apps, series = [], None
        correlated = list(payload.get("correlated") or [])
        try:
            history = self._traffic.sessions()
        except Exception:  # noqa: BLE001
            history = []
        payload["has_session_data"] = bool(apps) or bool(history)
        return {
            "payload": payload,
            "apps": apps,
            "series": series,
            "correlated": correlated,
            "history": history,
            "apps_range": range_key,
        }

    def refresh(self) -> None:
        if self._root is None:
            self._apply_bundle(self._collect())
            return
        self._run_off_thread(self._collect, self._apply_bundle)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def _apply_bundle(self, bundle: Dict[str, Any]) -> None:
        if isinstance(bundle, Exception):
            self._show_user_error(bundle)
            return
        payload = bundle.get("payload") if isinstance(bundle, dict) else None
        if not isinstance(payload, dict):
            return
        self._payload = payload
        self._correlated_rows = list(bundle.get("correlated") or [])
        header = header_status(payload)
        alerts = list(payload.get("alerts") or [])
        self._alert_incidents = build_incidents(alerts, self._correlated_rows)
        self._kpis = build_kpis(alerts, self._correlated_rows)

        self._sync_menu_state(header)
        self._render_home(payload, header, runtime_states(payload))
        self._history_rows = list(bundle.get("history") or [])
        page = self._current_page
        if page == "apps":
            # Prefer the current range from the session cache so a snapshot
            # that started before a range change cannot paint stale totals.
            stamped = bundle.get("apps_range")
            if stamped == self._apps_range:
                apps = list(bundle.get("apps") or [])
                series = bundle.get("series")
            else:
                try:
                    apps = self._traffic.apps(self._apps_range)
                    series = self._traffic.series(self._selected_app, self._apps_range)
                except Exception:  # noqa: BLE001
                    apps = list(bundle.get("apps") or [])
                    series = bundle.get("series")
            self._render_apps(apps, series)
        elif page == "alerts":
            self._render_alerts()
        elif page == "history":
            self._render_history()
        self._render_status_bar(payload, header)

    def _render_home(
        self,
        payload: Dict[str, Any],
        header: Dict[str, str],
        runtime: Optional[Dict[str, str]] = None,
    ) -> None:
        runtime = runtime or runtime_states(payload)
        info = home_headline(payload, header)
        if self._list_signatures.get("headline") != info["title"]:
            self._list_signatures["headline"] = info["title"]
            self._widgets["headline"].configure(text=info["title"])
        if self._list_signatures.get("subtitle") != info["subtitle"]:
            self._list_signatures["subtitle"] = info["subtitle"]
            self._widgets["subtitle"].configure(text=info["subtitle"])
        self._sync_status_message(runtime, payload)

        primary = self._widgets["btn_primary"]
        secondary = self._widgets["btn_secondary"]
        actions = home_actions(payload)
        monitoring = runtime.get("monitoring")
        if monitoring in {"running", "starting"}:
            primary.configure(text=actions["primary"], enabled=actions["primary_enabled"])
            primary.command = self._on_stop
            secondary.configure(text=actions["secondary"], enabled=actions["secondary_enabled"])
            secondary.command = self._on_start
        else:
            primary.configure(text=actions["primary"], enabled=actions["primary_enabled"])
            primary.command = self._on_start_service
            secondary.configure(text=actions["secondary"], enabled=actions["secondary_enabled"])
            secondary.command = self._on_start

        self._widgets["tile_monitoring"].set(
            header["monitoring"], theme.state_color(header["monitoring"])
        )
        self._widgets["tile_detection"].set(
            header["detection"], theme.state_color(header["detection"])
        )
        self._widgets["tile_capture"].set(
            header["capture"], theme.state_color(header["capture"])
        )

        self._render_traffic(payload, header)

        alerts = list(payload.get("alerts") or [])
        self._render_activity(alerts[:5])

    def _render_traffic(self, payload: Dict[str, Any], header: Dict[str, str]) -> None:
        health = payload.get("health") or {}
        packets = int(health.get("packets_processed", payload.get("packets_processed", 0)) or 0)
        now = time.monotonic()
        rate = 0.0
        runtime_preview = runtime_states(payload)
        running = (
            runtime_preview["monitoring"] == "running"
            and runtime_preview["capture"] == "running"
        )
        if self._last_packets is not None and self._last_sample_at is not None:
            elapsed = now - self._last_sample_at
            if elapsed > 0:
                delta = packets - self._last_packets
                if running or delta != 0:
                    rate = max(0.0, delta / elapsed)
                    last = self._traffic_samples[-1] if self._traffic_samples else None
                    if last != rate:
                        self._traffic_samples.append(rate)
                        self._traffic_samples = self._traffic_samples[-1800:]
                else:
                    rate = 0.0
        self._last_packets = packets
        self._last_sample_at = now
        self._traffic_rate = rate

        runtime = runtime_preview
        series = [v for v in self._traffic_samples[-240:] if v >= 0]
        self._widgets["chart"].set_series(series, running=running)
        if series and (running or max(series) > 0):
            self._widgets["chart"].set_caption(
                f"Current rate {rate:.1f} pkt/s · averaging the last hour."
            )
        elif runtime["service"] != "running":
            self._widgets["chart"].set_caption("Start the CANA service to begin monitoring.")
        elif runtime["monitoring"] != "running":
            self._widgets["chart"].set_caption("Start monitoring to begin capturing traffic.")
        elif runtime["capture"] != "running":
            self._widgets["chart"].set_caption("Packet capture is unavailable.")
        else:
            self._widgets["chart"].set_caption("Capturing network traffic.")

    def _render_activity(self, alerts: List[Dict[str, Any]]) -> None:
        container = self._widgets["activity_list"]
        signature = activity_list_signature(alerts)
        if self._list_signatures.get("activity") == signature:
            return
        self._list_signatures["activity"] = signature
        for child in container.winfo_children():
            child.destroy()
        if not alerts:
            EmptyState(container, "No activity recorded yet.").pack(fill="x")
            return
        for index, alert in enumerate(alerts):
            if index:
                theme.hairline(container, theme.BORDER).pack(fill="x", padx=20)
            row = ActivityRow(
                container,
                severity=alert.get("severity", ""),
                sentence=alert_sentence(alert),
                meta=alert_meta(alert),
                command=self._show_alerts,
            )
            row.pack(fill="x", padx=20, pady=8)

    # -- Apps rendering -------------------------------------------------
    def _render_apps(self, apps: List[Any], series: Any) -> None:
        self._apps_data = list(apps or [])
        listing = self._widgets["apps_list"]
        total = sum(getattr(app, "total_bytes", 0) for app in self._apps_data)
        has_data = total > 0
        payload = self._payload or {}
        source = apps_source_caption(payload, has_data)
        subtitle_text = apps_source_subtitle(payload, has_data)
        subtitle = self._widgets.get("apps_subtitle")
        if subtitle is not None and self._list_signatures.get("apps_subtitle") != subtitle_text:
            self._list_signatures["apps_subtitle"] = subtitle_text
            subtitle.configure(text=subtitle_text)
        total_text = f"{format_bytes(total)} total"
        if self._list_signatures.get("apps_total") != total_text:
            self._list_signatures["apps_total"] = total_text
            self._widgets["apps_total"].configure(text=total_text)
        selected = self._selected_app or "All applications"
        caption = f"{source} · {selected}"
        if self._list_signatures.get("apps_caption") != caption:
            self._list_signatures["apps_caption"] = caption
            self._widgets["apps_caption"].configure(text=caption)

        query = (self._widgets.get("apps_search").value() if self._widgets.get("apps_search") else "")
        visible = [
            app for app in self._apps_data
            if not query or query.lower() in app.name.lower()
        ]
        signature = apps_list_signature(
            visible, query, self._selected_app, self._apps_range
        )
        if self._list_signatures.get("apps") != signature:
            self._list_signatures["apps"] = signature
            listing.clear()
            if not visible:
                message = (
                    "No applications match this search." if query
                    else apps_source_subtitle(self._payload or {}, False)
                )
                EmptyState(listing.inner, message).pack(fill="x")
            else:
                for app in visible:
                    self._apps_row(listing.inner, app).pack(fill="x")

        if series is not None and not getattr(series, "is_empty", True):
            self._widgets["apps_chart"].set_series(series.down, series.up, series.labels)
            down = sum(series.down)
            up = sum(series.up)
            legend_in = self._widgets.get("apps_legend_in") or self._widgets.get("apps_legend")
            legend_out = self._widgets.get("apps_legend_out")
            if legend_in is not None:
                legend_in.configure(text=f"Received {format_bytes(down)}")
            if legend_out is not None:
                legend_out.configure(text=f"Sent {format_bytes(up)}")
        else:
            self._widgets["apps_chart"].set_series([], [], [])
            legend_in = self._widgets.get("apps_legend_in") or self._widgets.get("apps_legend")
            legend_out = self._widgets.get("apps_legend_out")
            if legend_in is not None:
                legend_in.configure(text="Received 0 B")
            if legend_out is not None:
                legend_out.configure(text="Sent 0 B")

    def _apps_row(self, parent, app: Any):
        import tkinter as tk

        selected = self._selected_app is not None and app.name == self._selected_app
        idle = theme.ACCENT_TINT if selected else theme.SURFACE_2
        fg = theme.ACCENT_TEXT if selected else theme.TEXT_PRIMARY
        row = tk.Frame(parent, bg=idle, cursor="hand2")
        name = tk.Label(
            row, text=app.name, font=theme.FONT_TABLE, fg=fg, bg=idle, anchor="w",
        )
        name.pack(side="left", fill="x", expand=True, padx=(12, 8), pady=8)
        painted = [row, name]
        cells = [
            (format_bytes(app.down_bytes), theme.TEXT_SECONDARY),
            (format_bytes(app.up_bytes), theme.TEXT_SECONDARY),
        ]
        for text, color in cells:
            cell = tk.Frame(row, bg=idle, width=_APPS_COL_BYTES, height=18)
            cell.pack(side="left")
            cell.pack_propagate(False)
            label = tk.Label(
                cell, text=text, font=theme.FONT_MONO, fg=fg if selected else color,
                bg=idle, anchor="e",
            )
            label.pack(fill="both", expand=True, padx=(0, 10))
            painted.extend((cell, label))

        def paint(color: str) -> None:
            for widget in painted:
                widget.configure(bg=color)

        def pointer_inside() -> bool:
            x, y = row.winfo_pointerxy()
            return (
                row.winfo_rootx() <= x <= row.winfo_rootx() + row.winfo_width()
                and row.winfo_rooty() <= y <= row.winfo_rooty() + row.winfo_height()
            )

        def on_enter(_event) -> None:
            if not selected:
                paint(theme.SURFACE_SUNKEN)

        def on_leave(_event) -> None:
            if not pointer_inside():
                paint(idle)

        for widget in painted:
            widget.bind("<Button-1>", lambda _e, n=app.name: self._on_app_click(n))
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
        return row

    def _on_app_click(self, name: str) -> None:
        self._selected_app = None if self._selected_app == name else name
        self._refresh_apps_off_thread()

    def _on_range_change(self, value: str) -> None:
        if value not in RANGE_ORDER:
            return
        self._apps_range = value
        pills = self._widgets.get("range_pills")
        if pills is not None:
            pills.set_selected(value)
        self._refresh_apps_off_thread()

    def _on_apps_search(self, _event=None) -> None:
        self._render_apps(self._apps_data, self._traffic.series(self._selected_app, self._apps_range))

    def _refresh_apps_off_thread(self) -> None:
        """Reload session totals without stealing the pipe IPC sequence.

        Tk ``after()`` is not thread-safe, so the worker only stores a
        result and the UI thread registers the apply callback.
        """

        self._apps_seq += 1
        seq = self._apps_seq
        range_key = self._apps_range
        selected = self._selected_app

        if self._root is None:
            self._render_apps(
                self._traffic.apps(range_key),
                self._traffic.series(selected, range_key),
            )
            return

        self._apps_inflight += 1

        def work() -> None:
            try:
                bundle = {
                    "apps": self._traffic.apps(range_key),
                    "series": self._traffic.series(selected, range_key),
                    "apps_range": range_key,
                    "seq": seq,
                }
            except Exception:  # noqa: BLE001
                bundle = None
            try:
                if bundle is not None and seq == self._apps_seq:
                    self._apps_pending = bundle
            finally:
                self._apps_inflight = max(0, self._apps_inflight - 1)

        threading.Thread(target=work, name="CANAUITraffic", daemon=True).start()
        self._schedule_apps_drain()

    def _schedule_apps_drain(self) -> None:
        if self._apps_drain_scheduled or self._root is None or self._closed:
            return
        self._apps_drain_scheduled = True
        try:
            self._root.after(20, self._drain_apps_pending)
        except Exception:  # noqa: BLE001
            self._apps_drain_scheduled = False

    def _drain_apps_pending(self) -> None:
        self._apps_drain_scheduled = False
        if self._closed or self._root is None:
            return
        bundle = self._apps_pending
        if bundle is None:
            if self._apps_inflight > 0:
                self._schedule_apps_drain()
            return
        if bundle.get("seq") != self._apps_seq or bundle.get("apps_range") != self._apps_range:
            if self._apps_pending is bundle:
                self._apps_pending = None
            if self._apps_inflight > 0:
                self._schedule_apps_drain()
            return
        if self._apps_pending is bundle:
            self._apps_pending = None
        self._render_apps(bundle.get("apps") or [], bundle.get("series"))

    # -- Alerts rendering -----------------------------------------------
    def _render_alerts(self) -> None:
        for card, kpi in zip(self._kpi_cards, self._kpis):
            card.set(kpi.get("value", "—"))

        self._widgets["sev_chip"].label.configure(text=f"Severity: {self._alert_severity}")
        self._widgets["status_chip"].label.configure(text=f"Status: {self._alert_status}")

        payload = self._payload or {}
        caption = alerts_source_caption(payload)
        subtitle = self._widgets.get("alerts_subtitle")
        if subtitle is not None and self._list_signatures.get("alerts_subtitle") != caption:
            self._list_signatures["alerts_subtitle"] = caption
            subtitle.configure(text=caption)
        incidents = self._alert_incidents
        filtered = filter_incidents(
            incidents,
            severity=self._alert_severity,
            status=self._alert_status,
            search=self._alert_search,
        )
        self._widgets["alerts_count"].configure(
            text=f"Showing {len(filtered)} of {len(incidents)} recorded alerts."
        )
        listing = self._widgets["alerts_list"]
        signature = alerts_list_signature(
            filtered, self._alert_severity, self._alert_status, self._alert_search
        )
        if self._list_signatures.get("alerts") == signature:
            return
        self._list_signatures["alerts"] = signature
        listing.clear()
        if not filtered:
            empty = (
                "No unusual activity detected."
                if not incidents
                else "No alerts match these filters."
            )
            EmptyState(listing.inner, empty).pack(fill="x")
            return
        for incident in filtered:
            self._alert_row(listing.inner, incident).pack(fill="x")

    def _alert_row(self, parent, incident: Any):
        import tkinter as tk

        high = incident.severity == "High"
        bg = theme.RED_TINT if high else theme.SURFACE_2
        row = tk.Frame(parent, bg=bg)
        CheckBox(row, bg=bg).canvas.pack(side="left", padx=(16, 10), pady=11)

        text_col = tk.Frame(row, bg=bg)
        text_col.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=8)
        name = tk.Label(
            text_col, text=incident.name, font=theme.FONT_TABLE, fg=theme.TEXT_PRIMARY,
            bg=bg, anchor="w", justify="left",
        )
        name.pack(anchor="w", fill="x")
        why = str(getattr(incident, "why", "") or "")
        if why:
            tk.Label(
                text_col,
                text=why,
                font=theme.FONT_SMALL,
                fg=theme.TEXT_SECONDARY,
                bg=bg,
                anchor="w",
                justify="left",
                wraplength=420,
            ).pack(anchor="w", fill="x", pady=(2, 0))
        LinkLabel(
            text_col,
            "Details",
            lambda item=incident: self._show_alert_details(item),
        ).pack(anchor="w", pady=(4, 0))

        severity_cell = tk.Frame(row, bg=bg, width=_ALERT_COL_SEVERITY, height=20)
        severity_cell.pack(side="left")
        severity_cell.pack_propagate(False)
        SeverityBars(severity_cell, incident.severity, bg=bg).pack(side="left")

        status_cell = tk.Frame(row, bg=bg, width=_ALERT_COL_STATUS, height=20)
        status_cell.pack(side="left")
        status_cell.pack_propagate(False)
        StatusDot(status_cell, incident.status, bg=bg).pack(side="left")

        seen_cell = tk.Frame(row, bg=bg, width=_ALERT_COL_SEEN, height=20)
        seen_cell.pack(side="left")
        seen_cell.pack_propagate(False)
        tk.Label(
            seen_cell, text=_relative_time(incident.first_seen_epoch), font=theme.FONT_MONO,
            fg=theme.TEXT_SECONDARY, bg=bg, anchor="w",
        ).pack(fill="both", expand=True)

        tags_cell = tk.Frame(row, bg=bg, width=_ALERT_COL_TAGS, height=22)
        tags_cell.pack(side="left")
        tags_cell.pack_propagate(False)
        for tag in incident.tags[:2]:
            tk.Label(
                tags_cell, text=tag, font=theme.FONT_BADGE, fg=theme.TEXT_SECONDARY,
                bg=theme.CHIP_BG, padx=6, pady=1,
            ).pack(side="left", padx=(0, 4), pady=5)

        name.bind("<Configure>", lambda e: name.configure(wraplength=max(120, e.width - 8)))
        return row

    def _show_alert_details(self, incident: Any) -> None:
        from tkinter import messagebox

        title = str(getattr(incident, "title", "") or incident.name)
        why = str(getattr(incident, "why", "") or "")
        note = str(getattr(incident, "severity_note", "") or "")
        action = str(getattr(incident, "action", "") or "")
        technical = str(getattr(incident, "technical", "") or incident.reason or "")
        body = (
            "WHAT HAPPENED\n"
            f"{title}.\n\n"
            "WHY CANA NOTICED IT\n"
            f"{why}\n\n"
            "SEVERITY\n"
            f"{incident.severity}\n"
            f"{note}\n\n"
            "WHAT SHOULD I DO?\n"
            f"{action}\n\n"
            "TECHNICAL DETAILS\n"
            f"{technical or format_technical_details({'reason': incident.reason, 'rule_name': incident.rule_name, 'application_name': incident.application_name, 'source_ip': incident.source_ip, 'destination_ip': incident.destination_ip, 'severity': incident.severity})}"
        )
        messagebox.showinfo("Alert details", body, parent=self._root)

    def _cycle_severity(self) -> None:
        values = list(SEVERITY_FILTERS)
        index = values.index(self._alert_severity) if self._alert_severity in values else 0
        self._alert_severity = values[(index + 1) % len(values)]
        self._render_alerts()

    def _cycle_status(self) -> None:
        values = list(STATUS_FILTERS)
        index = values.index(self._alert_status) if self._alert_status in values else 0
        self._alert_status = values[(index + 1) % len(values)]
        self._render_alerts()

    def _on_alerts_search(self, _event=None) -> None:
        search = self._widgets.get("alerts_search")
        self._alert_search = search.value() if search is not None else ""
        self._render_alerts()

    def _render_history(self) -> None:
        listing = self._widgets.get("history_list")
        if listing is None:
            return
        rows = list(self._history_rows or [])
        payload = self._payload or {}
        caption = history_source_caption(payload, bool(rows))
        subtitle = self._widgets.get("history_subtitle")
        if subtitle is not None and self._list_signatures.get("history_subtitle") != caption:
            self._list_signatures["history_subtitle"] = caption
            subtitle.configure(text=caption)
        count = self._widgets.get("history_count")
        if count is not None:
            count.configure(
                text=f"{len(rows)} recorded session{'s' if len(rows) != 1 else ''}."
            )
        signature = history_list_signature(rows)
        if self._list_signatures.get("history") == signature:
            return
        self._list_signatures["history"] = signature
        listing.clear()
        if not rows:
            EmptyState(listing.inner, "No capture sessions recorded yet.").pack(fill="x")
            return
        for record in rows:
            self._history_row(listing.inner, record).pack(fill="x")

    def _history_row(self, parent, record: Dict[str, Any]):
        import tkinter as tk

        row = tk.Frame(parent, bg=theme.SURFACE_2)
        tk.Label(
            row,
            text=str(record.get("session_id") or record.get("name") or ""),
            font=theme.FONT_TABLE,
            fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2,
            anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=(16, 0), pady=8)
        cells = (
            (str(record.get("interface") or "Unknown"), _HISTORY_COL_IFACE),
            (str(record.get("packet_count") or 0), _HISTORY_COL_PACKETS),
            (_relative_time(record.get("started_at_epoch") or record.get("started_at")), _HISTORY_COL_WHEN),
            (format_bytes(record.get("size_bytes") or 0), _HISTORY_COL_SIZE),
        )
        for text, width in cells:
            cell = tk.Frame(row, bg=theme.SURFACE_2, width=width, height=20)
            cell.pack(side="left")
            cell.pack_propagate(False)
            tk.Label(
                cell, text=text, font=theme.FONT_MONO, fg=theme.TEXT_SECONDARY,
                bg=theme.SURFACE_2, anchor="w",
            ).pack(fill="both", expand=True)
        return row

    def _render_status_bar(self, payload: Dict[str, Any], header: Dict[str, str]) -> None:
        runtime = runtime_states(payload)
        state = status_bar_text(payload)
        color = theme.state_color(header.get("monitoring") or runtime["monitoring_label"])
        if runtime["service"] in {"not_installed", "stopped", "start_failed", "stop_failed"}:
            color = theme.RED
        elif runtime["service"] == "unknown" or runtime["monitoring"] == "unknown":
            color = theme.AMBER
        elif runtime["monitoring"] == "running" and runtime["capture"] == "running":
            color = theme.GREEN
        elif runtime["capture"] in {"failed", "unavailable"}:
            color = theme.AMBER
        health = payload.get("health") or {}
        interface = (
            health.get("selected_interface")
            or health.get("capture_interface_name")
            or payload.get("selected_interface")
            or "No interface"
        )
        bar = self._widgets["statusbar"]
        bar.set(state, color, f"{interface} · {self._traffic_rate:.0f} pkt/s")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _load_settings(self) -> None:
        payload = self.controller.last_payload or {}
        config = dict(payload.get("config") or {})
        health = payload.get("health") or {}
        if not str(config.get("capture_interface") or "").strip():
            config["capture_interface"] = (
                health.get("selected_interface")
                or health.get("capture_interface_name")
                or payload.get("selected_interface")
                or ""
            )
        self._apply_settings_config(config)

    def _apply_settings_config(self, config: Any) -> None:
        if isinstance(config, Exception) or not isinstance(config, dict):
            return
        if "set_iface" not in self._widgets:
            return
        self._widgets["set_iface"].set(config.get("capture_interface", ""))
        self._widgets["set_filter"].set(config.get("packet_filter", "ALL"))
        self._widgets["set_level"].set(config.get("logging_level", "INFO"))
        self._widgets["set_monitor"].set(bool(config.get("monitoring_enabled", True)))
        self._widgets["set_startup"].set(bool(config.get("automatic_startup", True)))
        self._widgets["set_persist"].set(bool(config.get("persist", True)))
        self._widgets["set_notify"].set(bool(config.get("notify", False)))

    def _show_message(self, text: str, color: str = theme.TEXT_MUTED) -> None:
        message = self._widgets.get("message")
        if message is None:
            return
        signature = (text, color)
        if self._list_signatures.get("home_message") == signature:
            return
        self._list_signatures["home_message"] = signature
        message.configure(text=text, fg=color)

    def _sync_status_message(self, runtime: Dict[str, str], payload: Dict[str, Any]) -> None:
        """Keep the Home status line consistent with the live runtime.

        A leftover "Monitoring stopped." must never sit under Monitoring active.
        """
        current = ""
        widget = self._widgets.get("message")
        if widget is not None:
            try:
                current = str(widget.cget("text") or "")
            except Exception:
                current = ""
        lowered = current.lower()
        monitoring = runtime.get("monitoring")
        capture = runtime.get("capture")
        last_error = str(payload.get("last_error") or "")
        if runtime.get("connection") == "reconnecting" or "reconnect" in last_error.lower():
            self._show_message(last_error or "CANA service connection was temporarily unavailable. Reconnecting...", theme.AMBER)
            return
        if monitoring in {"running", "starting", "unknown"} and lowered.startswith(
            ("monitoring stopped", "monitoring starting", "checking monitoring status")
        ):
            if monitoring == "running" and capture == "running":
                self._show_message("")
            elif monitoring == "starting":
                self._show_message("Monitoring starting...", theme.AMBER)
            elif monitoring == "unknown":
                self._show_message("Checking monitoring status...", theme.AMBER)
            else:
                self._show_message(last_error or "Packet capture is unavailable.", theme.AMBER)
            return
        if monitoring == "stopped" and lowered.startswith(
            ("monitoring running", "monitoring starting", "monitoring stopping")
        ):
            self._show_message("Monitoring stopped.")

    def _show_user_error(self, raw: Any, fallback: str = "") -> None:
        self._technical_details = technical_details(raw)
        self._show_message(user_facing_error(raw, fallback), theme.RED)

    def _on_start(self) -> None:
        self._show_message("Monitoring starting...")

        def done(payload: Any) -> None:
            if isinstance(payload, Exception):
                self._show_user_error(payload, "CANA couldn't start monitoring.")
                self.refresh()
                return
            if not isinstance(payload, dict):
                self.refresh()
                return
            raw_error = str(payload.get("last_error") or "")
            detail = payload.get("technical_details") or raw_error
            if detail:
                self._technical_details = str(detail)
            error = user_facing_error(raw_error, "CANA couldn't start monitoring.") if raw_error else ""
            runtime = runtime_states(payload)
            if payload.get("ok") is False or runtime["monitoring"] == "start_failed":
                self._show_message(error or "CANA couldn't start monitoring.", theme.RED)
            elif runtime["monitoring"] == "running":
                if runtime["capture"] == "running":
                    self._show_message("Monitoring running.", theme.GREEN)
                else:
                    self._show_message(
                        error or "Packet capture is unavailable.",
                        theme.AMBER,
                    )
            else:
                self._show_message(error or "Monitoring stopped.", theme.AMBER)
            self.refresh()

        self._run_off_thread(self.controller.start_monitoring, done, force=True)

    def _on_stop(self) -> None:
        self._show_message("Monitoring stopping...")

        def done(payload: Any) -> None:
            if isinstance(payload, Exception):
                self._show_user_error(payload, "CANA couldn't stop monitoring.")
                self.refresh()
                return
            if not isinstance(payload, dict):
                self.refresh()
                return
            raw_error = str(payload.get("last_error") or "")
            detail = payload.get("technical_details") or raw_error
            if detail:
                self._technical_details = str(detail)
            error = user_facing_error(raw_error, "CANA couldn't stop monitoring.") if raw_error else ""
            runtime = runtime_states(payload)
            if payload.get("ok") is False or runtime["monitoring"] == "stop_failed":
                self._show_message(error or "CANA couldn't stop monitoring.", theme.RED)
            else:
                self._show_message("Monitoring stopped.")
            self.refresh()

        self._run_off_thread(self.controller.stop_monitoring, done, force=True)

    def _on_start_service(self) -> None:
        if runtime_states(self._payload).get("service") == "not_installed":
            self._on_install_service()
            return
        self._show_message("Service starting...")

        def work() -> str:
            return try_start_windows_service()

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                self._show_user_error(result, "CANA couldn't connect to the background service.")
                self.refresh()
                return
            text = str(result or "")
            if text == "already_running":
                self._show_message("CANA service is already running.")
            elif text:
                self._technical_details = text
                self._show_message(user_facing_error(text, "CANA service start failed."), theme.RED)
            else:
                self._show_message("CANA service is running.", theme.GREEN)
            self.refresh()

        self._run_off_thread(work, done, force=True)

    def _on_install_service(self) -> None:
        self._show_message("Requesting administrator approval to install the service...")

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                self._show_user_error(result, "CANA couldn't install the background service.")
                return
            text = str(result or "")
            if not text:
                self._show_message("CANA service installed.", theme.GREEN)
                self.refresh()
                return
            self._technical_details = text
            self._show_message(
                user_facing_error(text, "CANA couldn't install the background service."),
                theme.RED,
            )

        self._run_off_thread(request_windows_service_install, done, force=True)

    def _on_apply_settings(self) -> None:
        if "set_iface" not in self._widgets:
            return
        updates = {
            "capture_interface": self._widgets["set_iface"].get().strip(),
            "packet_filter": self._widgets["set_filter"].get().strip().upper() or "ALL",
            "logging_level": self._widgets["set_level"].get().strip().upper() or "INFO",
            "monitoring_enabled": bool(self._widgets["set_monitor"].get()),
            "automatic_startup": bool(self._widgets["set_startup"].get()),
            "persist": bool(self._widgets["set_persist"].get()),
            "notify": bool(self._widgets["set_notify"].get()),
        }
        problem = validate_settings(updates)
        if problem is not None:
            self._widgets["set_msg"].configure(text=problem, fg=theme.RED)
            return

        def work() -> Any:
            return self.controller.apply_config(updates)

        def done(result: Any) -> None:
            if isinstance(result, Exception):
                self._technical_details = technical_details(result)
                self._widgets["set_msg"].configure(
                    text=user_facing_error(result), fg=theme.RED
                )
                return
            if isinstance(result, dict):
                if result.get("ok") is False:
                    message = user_facing_error(
                        result.get("last_error") or result.get("error") or "",
                        "CANA couldn't apply the settings.",
                    )
                    self._technical_details = technical_details(
                        result.get("technical_details")
                        or result.get("last_error")
                        or ""
                    )
                    self._widgets["set_msg"].configure(text=message, fg=theme.RED)
                    return
                # Reflect the service's authoritative config back into the
                # form so the UI and service never silently diverge.
                applied = result.get("config")
                if isinstance(applied, dict):
                    self._apply_settings_config(applied)
            self._widgets["set_msg"].configure(text="Settings applied.", fg=theme.GREEN)
            self.refresh()

        self._run_off_thread(work, done, force=True)

    def _show_alerts(self) -> None:
        self._show_page("alerts")

    def _download_activity(self) -> None:
        from tkinter import filedialog, messagebox

        alerts = list(self._payload.get("alerts") or [])
        if not alerts:
            messagebox.showinfo(
                "Download alerts", "There is no activity to download.", parent=self._root
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self._root,
            title="Download alerts",
            defaultextension=".csv",
            initialfile="cana_alerts.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        columns = (
            "triggered_at",
            "severity",
            "rule_name",
            "application_name",
            "source_ip",
            "destination_ip",
            "reason",
        )
        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for alert in alerts:
                    writer.writerow({key: alert.get(key, "") for key in columns})
        except OSError as exc:
            messagebox.showerror("Download alerts", str(exc), parent=self._root)
            return
        messagebox.showinfo(
            "Download alerts", f"Saved {len(alerts)} alerts to:\n{path}", parent=self._root
        )


_NAV_KEYS = {key for key, _label in _NAV_ITEMS}

__all__ = [
    "CANAWindow",
    "activity_list_signature",
    "alert_meta",
    "alert_sentence",
    "alerts_list_signature",
    "alerts_source_caption",
    "apps_list_signature",
    "apps_source_caption",
    "apps_source_subtitle",
    "history_list_signature",
    "history_source_caption",
    "home_actions",
    "home_headline",
    "status_bar_text",
    "tray_status_text",
]
