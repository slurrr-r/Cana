"""
icons.py
========

Small line icons drawn directly onto a Tk canvas.

The project ships no image assets, so every glyph in the rail, header,
activity list, and status bar is vector-drawn from a shared 24x24
viewbox. The result matches the design's stroke weight and scales
cleanly with the requested pixel size.
"""

from __future__ import annotations

from typing import Callable, Dict

VIEWBOX = 24.0


def _draw_home(c, s, color, w):
    c.create_line(4 * s, 11 * s, 12 * s, 4 * s, 20 * s, 11 * s, fill=color, width=w,
                  capstyle="round", joinstyle="round")
    c.create_line(6.5 * s, 10.5 * s, 6.5 * s, 19 * s, 17.5 * s, 19 * s, 17.5 * s, 10.5 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")
    c.create_line(10 * s, 19 * s, 10 * s, 14 * s, 14 * s, 14 * s, 14 * s, 19 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")


def _draw_alert(c, s, color, w):
    c.create_polygon(12 * s, 3.5 * s, 21 * s, 19.5 * s, 3 * s, 19.5 * s,
                     outline=color, fill="", width=w, joinstyle="round")
    c.create_line(12 * s, 9.5 * s, 12 * s, 14 * s, fill=color, width=w, capstyle="round")
    c.create_oval(11.2 * s, 16 * s, 12.8 * s, 17.6 * s, fill=color, outline=color)


def _draw_alert_circle(c, s, color, w):
    c.create_oval(3.5 * s, 3.5 * s, 20.5 * s, 20.5 * s, outline=color, width=w)
    c.create_line(12 * s, 7 * s, 12 * s, 13 * s, fill=color, width=w, capstyle="round")
    c.create_oval(11.2 * s, 15.4 * s, 12.8 * s, 17 * s, fill=color, outline=color)


def _draw_apps(c, s, color, w):
    c.create_rectangle(3.5 * s, 4.5 * s, 20.5 * s, 19.5 * s, outline=color, width=w)
    c.create_line(3.5 * s, 8.5 * s, 20.5 * s, 8.5 * s, fill=color, width=w)
    for x in (6, 8.5, 11):
        c.create_oval(x * s - 0.7 * s, 6.0 * s, x * s + 0.7 * s, 7.4 * s, fill=color, outline=color)


def _draw_history(c, s, color, w):
    c.create_oval(3.5 * s, 3.5 * s, 20.5 * s, 20.5 * s, outline=color, width=w)
    c.create_line(12 * s, 7.5 * s, 12 * s, 12.5 * s, 15.5 * s, 14.5 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")


def _draw_settings(c, s, color, w):
    cx = cy = 12 * s
    c.create_oval(8.5 * s, 8.5 * s, 15.5 * s, 15.5 * s, outline=color, width=w)
    import math

    for i in range(8):
        angle = math.radians(i * 45)
        x1 = cx + math.cos(angle) * 7.0 * s
        y1 = cy + math.sin(angle) * 7.0 * s
        x2 = cx + math.cos(angle) * 10.0 * s
        y2 = cy + math.sin(angle) * 10.0 * s
        c.create_line(x1, y1, x2, y2, fill=color, width=w, capstyle="round")


def _draw_stop(c, s, color, w):
    c.create_oval(2.5 * s, 2.5 * s, 21.5 * s, 21.5 * s, outline=color, width=w + 0.4)
    c.create_rectangle(8.5 * s, 8.5 * s, 15.5 * s, 15.5 * s, fill=color, outline=color)


def _draw_download(c, s, color, w):
    c.create_line(12 * s, 3.5 * s, 12 * s, 14.5 * s, fill=color, width=w, capstyle="round")
    c.create_line(7.5 * s, 10.5 * s, 12 * s, 15 * s, 16.5 * s, 10.5 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")
    c.create_line(5 * s, 19.5 * s, 19 * s, 19.5 * s, fill=color, width=w, capstyle="round")


def _draw_info(c, s, color, w):
    c.create_oval(3.5 * s, 3.5 * s, 20.5 * s, 20.5 * s, outline=color, width=w)
    c.create_oval(11.2 * s, 7.0 * s, 12.8 * s, 8.6 * s, fill=color, outline=color)
    c.create_line(12 * s, 11 * s, 12 * s, 16.5 * s, fill=color, width=w, capstyle="round")


def _draw_shield(c, s, color, w):
    c.create_polygon(12 * s, 3 * s, 20 * s, 6 * s, 20 * s, 12 * s, 12 * s, 21 * s,
                     4 * s, 12 * s, 4 * s, 6 * s, outline=color, fill="",
                     width=w, joinstyle="round")


def _draw_dot(c, s, color, w):
    c.create_oval(7 * s, 7 * s, 17 * s, 17 * s, fill=color, outline=color)


def _draw_arrow_right(c, s, color, w):
    c.create_line(7 * s, 5 * s, 14 * s, 12 * s, 7 * s, 19 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")


def _draw_refresh(c, s, color, w):
    c.create_arc(4 * s, 4 * s, 20 * s, 20 * s, start=60, extent=260,
                 outline=color, width=w, style="arc")
    c.create_polygon(15.5 * s, 3.5 * s, 20.5 * s, 6.5 * s, 15.5 * s, 9.0 * s,
                     fill=color, outline=color)


def _draw_x(c, s, color, w):
    c.create_line(6 * s, 6 * s, 18 * s, 18 * s, fill=color, width=w, capstyle="round")
    c.create_line(18 * s, 6 * s, 6 * s, 18 * s, fill=color, width=w, capstyle="round")


def _draw_search(c, s, color, w):
    c.create_oval(4.5 * s, 4.5 * s, 15 * s, 15 * s, outline=color, width=w)
    c.create_line(14 * s, 14 * s, 19.5 * s, 19.5 * s, fill=color, width=w, capstyle="round")


def _draw_check(c, s, color, w):
    c.create_line(5 * s, 12.5 * s, 10 * s, 17.5 * s, 19 * s, 6.5 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")


def _draw_chevron_down(c, s, color, w):
    c.create_line(6 * s, 9.5 * s, 12 * s, 15.5 * s, 18 * s, 9.5 * s,
                  fill=color, width=w, capstyle="round", joinstyle="round")


def _draw_pause(c, s, color, w):
    c.create_rectangle(7.5 * s, 5.5 * s, 10.5 * s, 18.5 * s, fill=color, outline=color)
    c.create_rectangle(13.5 * s, 5.5 * s, 16.5 * s, 18.5 * s, fill=color, outline=color)


def _draw_play(c, s, color, w):
    c.create_polygon(7.5 * s, 4.5 * s, 19 * s, 12 * s, 7.5 * s, 19.5 * s,
                     fill=color, outline=color, joinstyle="round")


_DRAWERS: Dict[str, Callable] = {
    "home": _draw_home,
    "alert": _draw_alert,
    "alert-circle": _draw_alert_circle,
    "apps": _draw_apps,
    "history": _draw_history,
    "settings": _draw_settings,
    "stop": _draw_stop,
    "download": _draw_download,
    "info": _draw_info,
    "shield": _draw_shield,
    "dot": _draw_dot,
    "arrow-right": _draw_arrow_right,
    "refresh": _draw_refresh,
    "x": _draw_x,
    "search": _draw_search,
    "check": _draw_check,
    "chevron-down": _draw_chevron_down,
    "pause": _draw_pause,
    "play": _draw_play,
}

# Semantic name -> glyph for alert severities.
SEVERITY_ICONS = {
    "HIGH": "alert",
    "CRITICAL": "alert",
    "MEDIUM": "alert-circle",
    "LOW": "info",
    "INFO": "info",
}


def draw_icon(
    canvas,
    name: str,
    size: int,
    color: str,
    *,
    width: float = 1.5,
    x: int = 0,
    y: int = 0,
) -> int:
    """
    Draw ``name`` onto ``canvas`` at ``(x, y)``.

    Returns the canvas item id (or 0 for an unknown glyph so callers do
    not have to special-case missing icons).
    """
    drawer = _DRAWERS.get(name)
    if drawer is None:
        return 0
    scale = size / VIEWBOX
    items = []
    before = canvas.find_all()

    # Translate into place by drawing at origin then moving the new items.
    drawer(canvas, scale, color, width)
    for item in canvas.find_all():
        if item not in before:
            items.append(item)
    if x or y:
        for item in items:
            canvas.move(item, x, y)
    return items[0] if items else 0


def severity_icon(severity: str) -> str:
    return SEVERITY_ICONS.get(str(severity or "").upper(), "info")


__all__ = ["draw_icon", "severity_icon", "SEVERITY_ICONS"]
