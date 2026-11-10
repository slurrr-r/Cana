"""
theme.py
========

Design tokens for the native CANA console.

Colors and type come from the approved mockups (GlassWire-style Apps tab
and Microsoft Defender-style Alerts tab). Every color, font, and
hairline used by ``cana_ui`` is defined here so the console reads as one
surface. Font sizes are in points so Tk scales them through ``tk scaling``,
and :func:`init_dpi` keeps those sizes physically consistent on
high-DPI displays.
"""

from __future__ import annotations

import sys

# Surfaces -----------------------------------------------------------------
# Panel background is off-white; cards/tables sit on top in pure white.
SURFACE_1 = "#F7F6F2"
SURFACE_2 = "#FFFFFF"
SURFACE_SUNKEN = "#F0F0EC"

# Hairlines ----------------------------------------------------------------
BORDER = "#E2E2DD"
BORDER_STRONG = "#D3D1C7"

# Text ---------------------------------------------------------------------
TEXT_PRIMARY = "#1A1A18"
TEXT_SECONDARY = "#5F5E5A"
TEXT_MUTED = "#888780"
TEXT_ON_ACCENT = "#FFFFFF"

# Accent (links, selected nav, active pills) -------------------------------
ACCENT = "#185FA5"
ACCENT_HOVER = "#134B80"
ACCENT_TINT = "#E6F1FB"
ACCENT_TEXT = "#185FA5"

# Semantic roles -----------------------------------------------------------
RED = "#A32D2D"
RED_HOVER = "#8A2525"
RED_TINT = "#FCEBEB"
RED_DOT = "#E24B4A"

AMBER = "#854F0B"
AMBER_HOVER = "#6E4109"
AMBER_TINT = "#FCF1DF"
AMBER_DOT = "#EF9F27"

GREEN = "#2E7D5B"
GREEN_TINT = "#E6F4EC"

GRAY_DOT = "#9AA1AB"
CHIP_BG = "#F0F0EC"

# Severity -> token mapping used by rows, bars, and icons.
SEVERITY_COLORS = {
    "HIGH": RED,
    "CRITICAL": RED,
    "MEDIUM": AMBER,
    "LOW": TEXT_SECONDARY,
    "INFO": TEXT_SECONDARY,
}

# Number of filled severity squares out of three.
SEVERITY_LEVELS = {
    "HIGH": 3,
    "CRITICAL": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 1,
}

# Incident status dot colors.
STATUS_COLORS = {
    "Active": ACCENT,
    "In progress": AMBER_DOT,
    "Resolved": GREEN,
    "Unknown": GRAY_DOT,
}

# Fonts --------------------------------------------------------------------
# Sizes are in POINTS so Tk scales them through ``tk scaling`` (set from
# the real monitor DPI in :func:`init_dpi`). Pixel-comment values are the
# intended size at 96 DPI. Positive point sizes are what keeps text both
# correctly sized *and* crisp on high-DPI monitors.
FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
MONO_FAMILY = "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"

FONT_MENU = (FONT_FAMILY, 9)  # 12px
FONT_NAV = (FONT_FAMILY, 10)  # 13px
FONT_TITLE = (FONT_FAMILY, 13, "bold")  # 17px
FONT_SUBTITLE = (FONT_FAMILY, 10)  # 13px
FONT_TILE_LABEL = (FONT_FAMILY, 8)  # 11px
FONT_TILE_VALUE = (FONT_FAMILY, 11)  # 15px
FONT_KPI_VALUE = (FONT_FAMILY, 15)  # 20px
FONT_SECTION = (FONT_FAMILY, 10, "bold")  # 13px
FONT_BODY = (FONT_FAMILY, 10)  # 13px
FONT_TABLE = (FONT_FAMILY, 9)  # 12px
FONT_TABLE_HEAD = (FONT_FAMILY, 9)  # 12px
FONT_SMALL = (FONT_FAMILY, 9)  # 12px
FONT_MONO = (MONO_FAMILY, 9)  # 12px
FONT_BADGE = (FONT_FAMILY, 8)  # 11px

# Geometry -----------------------------------------------------------------
RAIL_WIDTH = 128
APPS_PANEL_WIDTH = 280
WINDOW_WIDTH = 1060
WINDOW_HEIGHT = 720
MIN_WIDTH = 900
MIN_HEIGHT = 620

_DPI_INITIALIZED = False


def init_dpi(root) -> float:
    """
    Make the window DPI-aware and align Tk's scaling with the monitor.

    On Windows, a non-DPI-aware process gets bitmap-stretched by the OS,
    which is exactly what makes Tk text and icons look blurry on scaled
    displays. Declaring per-monitor awareness *before* the window is
    drawn (plus matching Tk's ``tk scaling``) keeps glyphs crisp.

    Returns the scaling factor that was applied. Safe to call on any
    platform, and safe to call more than once.
    """
    global _DPI_INITIALIZED
    if _DPI_INITIALIZED:
        return float(root.tk.call("tk", "scaling"))

    scale = 1.0
    try:
        import ctypes
        import sys

        if sys.platform == "win32":
            # 2 = PROCESS_PER_MONITOR_DPI_AWARE (Windows 8.1+). Fall back
            # to the older system-DPI call if shcore is unavailable.
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:  # noqa: BLE001
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:  # noqa: BLE001
                    pass
            try:
                scale = ctypes.windll.shcore.GetScaleFactorForDevice(0) / 100.0
            except Exception:  # noqa: BLE001
                scale = 1.0
    except Exception:  # noqa: BLE001
        scale = 1.0

    # Tk's default scaling is 96 DPI -> 1.333... px per point. Keeping
    # this consistent with the real DPI avoids the fractional-scaling
    # blur that shows up when only one of the two is aware.
    try:
        if scale and scale != 1.0:
            root.tk.call("tk", "scaling", 1.3333 * scale)
    except Exception:  # noqa: BLE001
        pass

    _DPI_INITIALIZED = True
    return scale


def hairline(parent, background: str = BORDER):
    """Return a 1px horizontal rule that mimics a 0.5px hairline."""
    import tkinter as tk

    return tk.Frame(parent, height=1, bd=0, highlightthickness=0, bg=background)


def vhairline(parent, background: str = BORDER):
    """Return a 1px vertical rule."""
    import tkinter as tk

    return tk.Frame(parent, width=1, bd=0, highlightthickness=0, bg=background)


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(str(severity or "").upper(), TEXT_SECONDARY)


def severity_level(severity: str) -> int:
    return SEVERITY_LEVELS.get(str(severity or "").upper(), 1)


# Severity -> display word. Engine severities (including CRITICAL/INFO)
# collapse onto the three levels the console shows.
SEVERITY_LABELS = {
    "HIGH": "High",
    "CRITICAL": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
}


def severity_label_text(severity: str) -> str:
    return SEVERITY_LABELS.get(str(severity or "").upper(), "Low")


def status_color(status: str) -> str:
    return STATUS_COLORS.get(str(status or ""), GRAY_DOT)


def state_color(value: str) -> str:
    """Color a state word: stopped/unavailable/down are red, else green."""
    text = str(value or "").strip().lower()
    if text in {
        "stopped",
        "unavailable",
        "not running",
        "down",
        "capture unavailable",
        "failed",
        "not installed",
        "start failed",
        "stop failed",
    }:
        return RED
    if text in {"active", "running", "protected", "monitoring", "available"}:
        return GREEN
    if text in {"starting", "degraded", "initializing", "stopping"}:
        return AMBER
    return TEXT_SECONDARY


__all__ = [
    "ACCENT",
    "ACCENT_HOVER",
    "ACCENT_TEXT",
    "ACCENT_TINT",
    "AMBER",
    "AMBER_DOT",
    "AMBER_HOVER",
    "AMBER_TINT",
    "APPS_PANEL_WIDTH",
    "BORDER",
    "BORDER_STRONG",
    "CHIP_BG",
    "FONT_BADGE",
    "FONT_BODY",
    "FONT_FAMILY",
    "FONT_KPI_VALUE",
    "FONT_MENU",
    "FONT_MONO",
    "FONT_NAV",
    "FONT_SECTION",
    "FONT_SMALL",
    "FONT_SUBTITLE",
    "FONT_TABLE",
    "FONT_TABLE_HEAD",
    "FONT_TILE_LABEL",
    "FONT_TILE_VALUE",
    "FONT_TITLE",
    "GRAY_DOT",
    "GREEN",
    "GREEN_TINT",
    "MIN_HEIGHT",
    "MIN_WIDTH",
    "MONO_FAMILY",
    "RAIL_WIDTH",
    "RED",
    "RED_DOT",
    "RED_HOVER",
    "RED_TINT",
    "SEVERITY_COLORS",
    "SEVERITY_LABELS",
    "SEVERITY_LEVELS",
    "STATUS_COLORS",
    "SURFACE_1",
    "SURFACE_2",
    "SURFACE_SUNKEN",
    "TEXT_MUTED",
    "TEXT_ON_ACCENT",
    "TEXT_PRIMARY",
    "TEXT_SECONDARY",
    "WINDOW_HEIGHT",
    "WINDOW_WIDTH",
    "hairline",
    "init_dpi",
    "severity_color",
    "severity_label_text",
    "severity_level",
    "state_color",
    "status_color",
    "vhairline",
]
