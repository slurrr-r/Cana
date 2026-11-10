"""
widgets.py
==========

Reusable building blocks for the CANA console.

These wrap Tk primitives so ``window.py`` can describe the layout in
product terms (nav tab, KPI card, app row, table row) instead of raw
canvas coordinates. Nothing here talks to the service; widgets only
render what the window hands them.
"""

from __future__ import annotations

import math
from typing import Callable, List, Optional, Sequence, Tuple

from cana_ui import theme

# tkinter ships with CPython on Windows but is absent from some Linux
# builds. The window is only ever constructed on a machine that has it,
# so importing lazily keeps headless test runs working.
try:  # pragma: no cover - exercised only when tkinter is present
    import tkinter as tk
    import tkinter.font as tkfont
except ImportError:  # pragma: no cover - headless test/Docker images
    tk = None  # type: ignore[assignment]
    tkfont = None  # type: ignore[assignment]


def _rounded_points(
    x1: float, y1: float, x2: float, y2: float, r: float, steps: int = 6
) -> List[float]:
    """Build polygon points for a rounded rectangle."""
    r = max(0.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    points: List[float] = []

    def arc(cx: float, cy: float, start: float, extent: float) -> None:
        for i in range(steps + 1):
            angle = math.radians(start + extent * (i / steps))
            points.extend((cx + r * math.cos(angle), cy + r * math.sin(angle)))

    arc(x2 - r, y1 + r, -90, 90)
    arc(x2 - r, y2 - r, 0, 90)
    arc(x1 + r, y2 - r, 90, 90)
    arc(x1 + r, y1 + r, 180, 90)
    return points


def round_rect(canvas, x1, y1, x2, y2, r, **kwargs):
    return canvas.create_polygon(_rounded_points(x1, y1, x2, y2, r), **kwargs)


def nice_peak(values: Sequence[float]) -> float:
    """Smallest 1-2-5 magnitude that covers ``values`` (never zero)."""
    peak = 0.0
    for value in values:
        try:
            peak = max(peak, float(value))
        except (TypeError, ValueError):
            continue
    if peak <= 0:
        return 1.0
    exp = math.floor(math.log10(peak))
    unit = 10 ** exp
    frac = peak / unit
    if frac <= 1:
        nice = 1
    elif frac <= 2:
        nice = 2
    elif frac <= 5:
        nice = 5
    else:
        nice = 10
    return float(nice * unit)


def series_points(
    values: Sequence[float],
    peak: float,
    left: float,
    top: float,
    width: float,
    height: float,
) -> List[float]:
    """Flattened ``[x, y, ...]`` canvas coords; a single sample spans the plot."""
    if not values or peak <= 0 or width <= 0 or height <= 0:
        return []
    baseline = top + height

    def y_at(value: float) -> float:
        try:
            amount = max(0.0, float(value))
        except (TypeError, ValueError):
            amount = 0.0
        return baseline - min(1.0, amount / peak) * height

    if len(values) == 1:
        y = y_at(values[0])
        return [left, y, left + width, y]
    step = width / (len(values) - 1)
    points: List[float] = []
    for index, value in enumerate(values):
        points.extend((left + index * step, y_at(value)))
    return points


class PillButton:
    """A canvas-drawn rounded button (primary / outline / ghost / danger)."""

    def __init__(
        self,
        parent,
        text: str,
        command: Optional[Callable[[], None]] = None,
        *,
        variant: str = "primary",
        icon: Optional[str] = None,
    ) -> None:
        self.parent = parent
        self.text = text
        self.command = command
        self.variant = variant
        self.icon = icon
        self._enabled = True
        self._hover = False

        self._font = tkfont.Font(font=theme.FONT_BODY)
        self._pad = 14
        self._height = 30
        icon_space = 18 if icon else 0
        self._width = self._font.measure(text) + self._pad * 2 + icon_space

        self.canvas = tk.Canvas(
            parent,
            width=self._width,
            height=self._height,
            bd=0,
            highlightthickness=0,
            bg=parent.cget("bg"),
            cursor="hand2",
        )
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Enter>", self._on_enter)
        self.canvas.bind("<Leave>", self._on_leave)
        self._render()

    def _palette(self) -> Tuple[str, str, Optional[str]]:
        if not self._enabled:
            return theme.SURFACE_SUNKEN, theme.TEXT_MUTED, theme.BORDER
        if self.variant == "primary":
            return (
                theme.ACCENT_HOVER if self._hover else theme.ACCENT,
                theme.TEXT_ON_ACCENT,
                None,
            )
        if self.variant == "outline":
            bg = theme.ACCENT_TINT if self._hover else theme.SURFACE_2
            return bg, theme.TEXT_PRIMARY, theme.BORDER_STRONG
        if self.variant == "danger":
            bg = theme.RED_HOVER if self._hover else theme.RED
            return bg, theme.TEXT_ON_ACCENT, None
        return self.parent.cget("bg"), theme.ACCENT_TEXT, None

    def _render(self) -> None:
        self.canvas.delete("all")
        bg, fg, border = self._palette()
        round_rect(
            self.canvas, 1, 1, self._width - 1, self._height - 1, 5,
            fill=bg, outline=border or bg, width=1,
        )
        text_x = self._width / 2
        if self.icon:
            from cana_ui.icons import draw_icon

            draw_icon(self.canvas, self.icon, 14, fg, width=1.5, x=12, y=(self._height - 14) // 2)
            text_x += 9
        self.canvas.create_text(
            text_x, self._height / 2, text=self.text, fill=fg, font=theme.FONT_BODY, anchor="c"
        )

    def configure(self, *, text: Optional[str] = None, enabled: Optional[bool] = None) -> None:
        changed = False
        if text is not None and text != self.text:
            self.text = text
            self._width = self._font.measure(text) + self._pad * 2 + (18 if self.icon else 0)
            self.canvas.configure(width=self._width)
            changed = True
        if enabled is not None:
            enabled = bool(enabled)
            if enabled != self._enabled:
                self._enabled = enabled
                self.canvas.configure(cursor="hand2" if self._enabled else "arrow")
                changed = True
        if changed:
            self._render()

    def pack(self, **kwargs):
        self.canvas.pack(**kwargs)
        return self

    def pack_forget(self) -> None:
        self.canvas.pack_forget()

    def _on_click(self, _event) -> None:
        if self._enabled and self.command is not None:
            self.command()

    def _on_enter(self, _event) -> None:
        if self._enabled:
            self._hover = True
            self._render()

    def _on_leave(self, _event) -> None:
        self._hover = False
        self._render()


class IconCanvas:
    """A fixed-size canvas holding one vector icon."""

    def __init__(
        self, parent, name: str, size: int, color: str, *, bg: Optional[str] = None, width: float = 1.5
    ) -> None:
        self.size = size
        self.name = ""
        self.color = ""
        self._width = width
        self.canvas = tk.Canvas(
            parent, width=size, height=size, bd=0, highlightthickness=0,
            bg=bg or parent.cget("bg"),
        )
        self.set(name, color)

    def set(self, name: str, color: str) -> None:
        from cana_ui.icons import draw_icon

        if name == self.name and color == self.color:
            return
        self.name = name
        self.color = color
        self.canvas.delete("all")
        draw_icon(self.canvas, name, self.size, color, width=self._width)

    def bind(self, sequence, func) -> None:
        self.canvas.bind(sequence, func)

    def pack(self, **kwargs):
        self.canvas.pack(**kwargs)
        return self


class TopNav:
    """
    Horizontal navigation with an active underline (GlassWire-style).

    Each tab owns its underline so the indicator cannot drift when the
    window resizes or a label's glyph width changes.
    """

    def __init__(
        self, parent, items: Sequence[Tuple[str, str]], command: Callable[[str], None]
    ) -> None:
        self.command = command
        self._tabs = {}
        self._active = ""
        self.frame = tk.Frame(parent, bg=theme.SURFACE_2)

        for key, label in items:
            holder = tk.Frame(self.frame, bg=theme.SURFACE_2, cursor="hand2")
            holder.pack(side="left", padx=(0, 4), fill="y")
            text = tk.Label(
                holder, text=label, font=theme.FONT_NAV, fg=theme.TEXT_SECONDARY,
                bg=theme.SURFACE_2, cursor="hand2", padx=12,
            )
            text.pack(pady=(10, 6))
            bar = tk.Frame(holder, bg=theme.SURFACE_2, height=2)
            bar.pack(fill="x", side="bottom")
            for widget in (holder, text, bar):
                widget.bind("<Button-1>", lambda _e, k=key: self.command(k))
                widget.bind("<Enter>", lambda _e, k=key: self._hover(k, True))
                widget.bind("<Leave>", lambda _e, k=key: self._hover(k, False))
            self._tabs[key] = {"holder": holder, "label": text, "bar": bar}

    def _hover(self, key: str, entering: bool) -> None:
        if key == self._active:
            return
        tab = self._tabs.get(key)
        if tab is None:
            return
        tab["label"].configure(fg=theme.TEXT_PRIMARY if entering else theme.TEXT_SECONDARY)

    def set_active(self, key: str) -> None:
        if key == self._active:
            return
        self._active = key
        for name, tab in self._tabs.items():
            selected = name == key
            tab["label"].configure(
                fg=theme.ACCENT if selected else theme.TEXT_SECONDARY,
                font=theme.FONT_NAV,
            )
            tab["bar"].configure(bg=theme.ACCENT if selected else theme.SURFACE_2)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class LinkLabel:
    """A colored, clickable text link with an optional leading icon."""

    def __init__(
        self,
        parent,
        text: str,
        command: Optional[Callable[[], None]] = None,
        *,
        icon: Optional[str] = None,
        font=None,
        color: Optional[str] = None,
    ) -> None:
        self.command = command
        self._color = color or theme.ACCENT_TEXT
        self.frame = tk.Frame(parent, bg=parent.cget("bg"), cursor="hand2")
        self.icon = None
        if icon:
            self.icon = IconCanvas(self.frame, icon, 14, self._color, bg=parent.cget("bg"))
            self.icon.pack(side="left", padx=(0, 5))
        self.label = tk.Label(
            self.frame, text=text, font=font or theme.FONT_SMALL,
            fg=self._color, bg=parent.cget("bg"), cursor="hand2",
        )
        self.label.pack(side="left")
        targets = [self.frame, self.label]
        if self.icon:
            targets.append(self.icon.canvas)
        for widget in targets:
            widget.bind("<Button-1>", self._on_click)
            widget.bind("<Enter>", lambda _e: self._tint(theme.ACCENT_HOVER))
            widget.bind("<Leave>", lambda _e: self._tint(self._color))

    def _tint(self, color: str) -> None:
        self.label.configure(fg=color)
        if self.icon:
            self.icon.set(self.icon.name, color)

    def _on_click(self, _event) -> None:
        if self.command is not None:
            self.command()

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def pack_forget(self) -> None:
        self.frame.pack_forget()


class StatusTile:
    """Label-above-value metric tile."""

    def __init__(self, parent, label: str) -> None:
        self.frame = tk.Frame(parent, bg=theme.SURFACE_2)
        tk.Label(
            self.frame, text=label, font=theme.FONT_TILE_LABEL,
            fg=theme.TEXT_SECONDARY, bg=theme.SURFACE_2, anchor="w",
        ).pack(anchor="w")
        self.value = tk.Label(
            self.frame, text="-", font=theme.FONT_TILE_VALUE,
            fg=theme.TEXT_PRIMARY, bg=theme.SURFACE_2, anchor="w",
        )
        self.value.pack(anchor="w")

    def set(self, value: str, color: str = theme.TEXT_PRIMARY) -> None:
        text = str(value)
        if getattr(self, "_text", None) == text and getattr(self, "_color", None) == color:
            return
        self._text = text
        self._color = color
        self.value.configure(text=text, fg=color)

    def grid(self, **kwargs) -> None:
        self.frame.grid(**kwargs)


class KpiCard:
    """Bordered card with a small label and a large value."""

    def __init__(self, parent, label: str, value: str = "-") -> None:
        self.frame = tk.Frame(
            parent, bg=theme.SURFACE_2, highlightbackground=theme.BORDER,
            highlightcolor=theme.BORDER, highlightthickness=1, bd=0,
        )
        inner = tk.Frame(self.frame, bg=theme.SURFACE_2)
        inner.pack(fill="both", expand=True, padx=11, pady=9)
        self.label = tk.Label(
            inner, text=label, font=theme.FONT_TILE_LABEL, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        )
        self.label.pack(anchor="w", fill="x")
        self.value = tk.Label(
            inner, text=value, font=theme.FONT_KPI_VALUE, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2, anchor="w",
        )
        self.value.pack(anchor="w", fill="x", pady=(2, 0))

    def set(self, value: str) -> None:
        text = str(value)
        if getattr(self, "_value", None) == text:
            return
        self._value = text
        self.value.configure(text=text)

    def grid(self, **kwargs) -> None:
        self.frame.grid(**kwargs)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class TrafficChart:
    """Compact live traffic chart used on Home (flat dashed no-data state)."""

    def __init__(self, parent, *, height: int = 64) -> None:
        self.frame = tk.Frame(parent, bg=theme.SURFACE_2)
        self.canvas = tk.Canvas(
            self.frame, height=height, bd=0, highlightthickness=0, bg=theme.SURFACE_2
        )
        self.canvas.pack(fill="x", expand=True)
        self.caption = tk.Label(
            self.frame, text="", font=theme.FONT_SMALL, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        )
        self.caption.pack(anchor="w", pady=(4, 0))
        self.canvas.bind("<Configure>", lambda _e: self._redraw())
        self._values: Sequence[float] = ()
        self._running = False
        self._drawn_key = None

    def set_series(self, values: Sequence[float], *, running: bool) -> None:
        series = list(values)
        if series == list(self._values) and running == self._running:
            return
        self._values = series
        self._running = running
        self._redraw()

    def set_caption(self, text: str) -> None:
        if getattr(self, "_caption", None) == text:
            return
        self._caption = text
        self.caption.configure(text=text)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def _redraw(self) -> None:
        canvas = self.canvas
        width = max(int(canvas.winfo_width()), 10)
        height = max(int(canvas.winfo_height()), 10)
        key = (width, height, tuple(float(v) for v in self._values), self._running)
        if self._drawn_key == key:
            return
        self._drawn_key = key
        canvas.delete("all")
        left, top, right, bottom = 2.0, 6.0, float(width - 2), float(height - 4)
        plot_w = max(right - left, 1.0)
        plot_h = max(bottom - top, 1.0)
        canvas.create_line(left, bottom, right, bottom, fill=theme.BORDER, width=1)
        values = [max(0.0, float(v)) for v in self._values]
        if not values or max(values) <= 0:
            mid = top + plot_h / 2
            canvas.create_line(left, mid, right, mid, fill=theme.BORDER_STRONG, width=1.5, dash=(4, 4))
            return
        peak = nice_peak(values)
        points = series_points(values, peak, left, top, plot_w, plot_h)
        if len(points) >= 4:
            canvas.create_line(*points, fill=theme.ACCENT, width=1.6, smooth=False)
            canvas.create_oval(
                points[-2] - 2.5, points[-1] - 2.5, points[-2] + 2.5, points[-1] + 2.5,
                fill=theme.ACCENT, outline=theme.ACCENT,
            )


class AreaChart:
    """
    Dual-series area chart (received + sent) with axes and time labels.

    Scales to the real ``SessionTrafficStore`` series. Empty, single-bucket,
    and tiny values still fill the plot instead of collapsing to a line.
    """

    def __init__(self, parent, *, height: int = 170) -> None:
        self.frame = tk.Frame(parent, bg=theme.SURFACE_2)
        self.canvas = tk.Canvas(
            self.frame, height=height, bd=0, highlightthickness=0, bg=theme.SURFACE_2
        )
        self.canvas.pack(fill="both", expand=True)
        self._down: Sequence[int] = ()
        self._up: Sequence[int] = ()
        self._labels: Sequence[str] = ()
        self._empty_text = "No traffic recorded in this range."
        self._drawn_key = None
        self.canvas.bind("<Configure>", lambda _e: self._redraw())

    def set_series(
        self, down: Sequence[int], up: Sequence[int], labels: Sequence[str]
    ) -> None:
        next_down = list(down)
        next_up = list(up)
        next_labels = list(labels)
        if (
            next_down == list(self._down)
            and next_up == list(self._up)
            and next_labels == list(self._labels)
        ):
            return
        self._down = next_down
        self._up = next_up
        self._labels = next_labels
        self._redraw()

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def _redraw(self) -> None:
        from cana_ui.traffic import format_bytes

        canvas = self.canvas
        width = max(int(canvas.winfo_width()), 40)
        height = max(int(canvas.winfo_height()), 40)
        key = (width, height, tuple(self._down), tuple(self._up), tuple(self._labels))
        if self._drawn_key == key:
            return
        self._drawn_key = key
        canvas.delete("all")
        left, right = 56.0, float(width - 10)
        top, bottom = 10.0, float(height - 22)
        plot_w = max(right - left, 1.0)
        plot_h = max(bottom - top, 1.0)

        down = [max(0, int(v)) for v in self._down]
        up = [max(0, int(v)) for v in self._up]
        n = max(len(down), len(up), len(self._labels))
        if len(down) < n:
            down = down + [0] * (n - len(down))
        if len(up) < n:
            up = up + [0] * (n - len(up))
        combined = [d + u for d, u in zip(down, up)]
        empty = n == 0 or max(combined, default=0) <= 0

        canvas.create_line(left, top, left, bottom, fill=theme.BORDER_STRONG, width=1)
        canvas.create_line(left, bottom, right, bottom, fill=theme.BORDER_STRONG, width=1)

        if empty:
            canvas.create_text(
                (left + right) / 2, (top + bottom) / 2, text=self._empty_text,
                fill=theme.TEXT_MUTED, font=theme.FONT_SMALL,
            )
            self._draw_labels(canvas, left, right, height)
            return

        peak = nice_peak(combined)
        for frac, tag in ((1.0, peak), (0.5, peak / 2.0), (0.0, 0.0)):
            y = bottom - plot_h * frac
            if frac > 0:
                canvas.create_line(left, y, right, y, fill=theme.BORDER, width=1)
            canvas.create_text(
                left - 6, y, text=format_bytes(tag), fill=theme.TEXT_MUTED,
                font=theme.FONT_TILE_LABEL, anchor="e",
            )

        down_pts = series_points(down, peak, left, top, plot_w, plot_h)
        up_pts = series_points(up, peak, left, top, plot_w, plot_h)
        if len(down_pts) >= 4:
            poly = [left, bottom] + down_pts + [right, bottom]
            canvas.create_polygon(poly, fill=theme.ACCENT_TINT, outline="")
            canvas.create_line(*down_pts, fill=theme.ACCENT, width=1.8, smooth=False)
        if len(up_pts) >= 4:
            canvas.create_line(*up_pts, fill=theme.GREEN, width=1.6, smooth=False)
        self._draw_labels(canvas, left, right, height)

    def _draw_labels(self, canvas, left: float, right: float, height: int) -> None:
        labels = list(self._labels)
        if not labels:
            return
        width = max(right - left, 1.0)
        count = len(labels)
        step = width / max(count - 1, 1)
        max_labels = 6
        stride = max(1, math.ceil(count / max_labels))
        shown = set(range(0, count, stride))
        shown.add(0)
        shown.add(count - 1)
        y = height - 6
        for index in sorted(shown):
            x = left + index * step
            anchor = "center"
            if index == 0:
                anchor = "w"
            elif index >= count - 1:
                anchor = "e"
            canvas.create_text(
                min(max(x, left), right), y, text=labels[index],
                fill=theme.TEXT_MUTED, font=theme.FONT_TILE_LABEL, anchor=anchor,
            )


class RangePills:
    """Segmented range selector (Month / Week / 24 Hours / 3 Hours)."""

    def __init__(
        self, parent, values: Sequence[str], command: Callable[[str], None], *, selected: str
    ) -> None:
        self.command = command
        self.frame = tk.Frame(parent, bg=parent.cget("bg"))
        self._pills = {}
        self._selected = selected
        for value in values:
            canvas = tk.Canvas(
                self.frame, height=26, bd=0, highlightthickness=0,
                bg=parent.cget("bg"), cursor="hand2",
            )
            self._pills[value] = canvas
            canvas.pack(side="left", padx=(0, 6))
            canvas.bind("<Button-1>", lambda _e, v=value: self.command(v))
            canvas.bind("<Enter>", lambda _e, v=value: self._hover(v, True))
            canvas.bind("<Leave>", lambda _e, v=value: self._hover(v, False))
        self._hovered = None
        self._render_all()

    def _hover(self, value: str, entering: bool) -> None:
        self._hovered = value if entering else None
        self._render_all()

    def set_selected(self, value: str) -> None:
        self._selected = value
        self._render_all()

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def _render_all(self) -> None:
        font = tkfont.Font(font=theme.FONT_SMALL)
        for value, canvas in self._pills.items():
            width = font.measure(value) + 24
            canvas.configure(width=width)
            canvas.delete("all")
            selected = value == self._selected
            if selected:
                bg, fg, outline = theme.ACCENT, theme.TEXT_ON_ACCENT, theme.ACCENT
            elif value == self._hovered:
                bg, fg, outline = theme.ACCENT_TINT, theme.ACCENT_TEXT, theme.ACCENT_TINT
            else:
                bg, fg, outline = theme.SURFACE_SUNKEN, theme.TEXT_SECONDARY, theme.BORDER
            round_rect(canvas, 0.5, 0.5, width - 0.5, 25.5, 4, fill=bg, outline=outline)
            canvas.create_text(width / 2, 13, text=value, fill=fg, font=theme.FONT_SMALL)


class CheckBox:
    """A canvas-drawn checkbox (kept readable on the light theme)."""

    def __init__(self, parent, *, bg: Optional[str] = None) -> None:
        self._bg = bg or parent.cget("bg")
        self._checked = False
        self.canvas = tk.Canvas(
            parent, width=14, height=14, bd=0, highlightthickness=0, bg=self._bg, cursor="hand2"
        )
        self.canvas.bind("<Button-1>", self._toggle)
        self._render()

    def _render(self) -> None:
        self.canvas.delete("all")
        if self._checked:
            round_rect(self.canvas, 0.5, 0.5, 13.5, 13.5, 2, fill=theme.ACCENT, outline=theme.ACCENT)
            self.canvas.create_line(
                3.5, 7, 6, 9.6, 10.5, 4.2, fill="#FFFFFF", width=1.6,
                capstyle="round", joinstyle="round",
            )
        else:
            round_rect(
                self.canvas, 0.5, 0.5, 13.5, 13.5, 2,
                fill=theme.SURFACE_2, outline=theme.BORDER_STRONG, width=1,
            )

    def _toggle(self, _event) -> None:
        self._checked = not self._checked
        self._render()

    @property
    def checked(self) -> bool:
        return self._checked

    def set(self, value: bool) -> None:
        self._checked = bool(value)
        self._render()

    def pack(self, **kwargs):
        self.canvas.pack(**kwargs)
        return self


class SeverityBars:
    """Three small squares, filled to indicate severity (mockup style)."""

    def __init__(self, parent, severity: str, *, bg: Optional[str] = None) -> None:
        self._bg = bg or parent.cget("bg")
        self.frame = tk.Frame(parent, bg=self._bg)
        self.bars = tk.Canvas(
            self.frame, width=26, height=12, bd=0, highlightthickness=0, bg=self._bg
        )
        self.bars.pack(side="left")
        self.label = tk.Label(
            self.frame, text="", font=theme.FONT_TABLE, fg=theme.TEXT_PRIMARY, bg=self._bg
        )
        self.label.pack(side="left", padx=(5, 0))
        self.set(severity)

    def set(self, severity: str) -> None:
        level = theme.severity_level(severity)
        color = theme.severity_color(severity)
        self.bars.delete("all")
        for index in range(3):
            x = index * 9
            fill = color if index < level else theme.BORDER_STRONG
            self.bars.create_rectangle(x, 1, x + 6, 11, fill=fill, outline=fill)
        self.label.configure(text=theme.severity_label_text(severity))

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class StatusDot:
    """Colored dot + status text."""

    def __init__(self, parent, status: str, *, bg: Optional[str] = None) -> None:
        self._bg = bg or parent.cget("bg")
        self.frame = tk.Frame(parent, bg=self._bg)
        self.dot = tk.Canvas(self.frame, width=9, height=9, bd=0, highlightthickness=0, bg=self._bg)
        self.dot.pack(side="left")
        self.label = tk.Label(
            self.frame, text=status, font=theme.FONT_TABLE, fg=theme.TEXT_PRIMARY, bg=self._bg
        )
        self.label.pack(side="left", padx=(5, 0))
        self.set(status)

    def set(self, status: str) -> None:
        color = theme.status_color(status)
        self.dot.delete("all")
        self.dot.create_oval(0, 0, 9, 9, fill=color, outline=color)
        self.label.configure(text=status)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class FilterChip:
    """Borderless chip showing an active filter, e.g. ``Status: All``."""

    def __init__(
        self,
        parent,
        text: str,
        command: Optional[Callable[[], None]] = None,
        *,
        bg: Optional[str] = None,
    ) -> None:
        self.command = command
        self._bg = bg or parent.cget("bg")
        self.frame = tk.Frame(
            parent, bg=self._bg, highlightbackground=theme.BORDER_STRONG,
            highlightcolor=theme.BORDER_STRONG, highlightthickness=1, bd=0, cursor="hand2",
        )
        inner = tk.Frame(self.frame, bg=theme.SURFACE_1)
        inner.pack()
        self.label = tk.Label(
            inner, text=text, font=theme.FONT_TILE_LABEL, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_1, cursor="hand2",
        )
        self.label.pack(side="left", padx=(8, 4), pady=3)
        self.icon = IconCanvas(inner, "x", 10, theme.TEXT_MUTED, bg=theme.SURFACE_1)
        self.icon.pack(side="left", padx=(0, 6))
        for widget in (self.frame, inner, self.label, self.icon.canvas):
            widget.bind("<Button-1>", lambda _e: command() if command else None)
        inner.configure(bg=theme.SURFACE_1)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def pack_forget(self) -> None:
        self.frame.pack_forget()


class SearchBox:
    """Entry with a leading search glyph and placeholder text."""

    def __init__(self, parent, *, placeholder: str = "Search", width: int = 20) -> None:
        self.frame = tk.Frame(
            parent, bg=theme.SURFACE_2, highlightbackground=theme.BORDER,
            highlightcolor=theme.ACCENT, highlightthickness=1, bd=0,
        )
        self.icon = IconCanvas(self.frame, "search", 13, theme.TEXT_MUTED, bg=theme.SURFACE_2)
        self.icon.pack(side="left", padx=(8, 4), pady=5)
        self.var = tk.StringVar()
        self.entry = tk.Entry(
            self.frame, textvariable=self.var, font=theme.FONT_SMALL, width=width,
            bg=theme.SURFACE_2, fg=theme.TEXT_PRIMARY, relief="flat",
            insertbackground=theme.TEXT_PRIMARY,
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=5)
        self._placeholder = placeholder
        self._show_placeholder()
        self.entry.bind("<FocusIn>", self._clear_placeholder)
        self.entry.bind("<FocusOut>", self._restore_placeholder)
        self.entry.bind("<Return>", lambda _e: self.frame.event_generate("<<Search>>"))
        self.entry.bind("<KeyRelease>", lambda _e: self.frame.event_generate("<<Search>>"))

    def _show_placeholder(self) -> None:
        if not self.var.get():
            self.entry.insert(0, self._placeholder)
            self.entry.configure(fg=theme.TEXT_MUTED)
            self._is_placeholder = True

    def _clear_placeholder(self, _event) -> None:
        if getattr(self, "_is_placeholder", False):
            self.entry.delete(0, "end")
            self.entry.configure(fg=theme.TEXT_PRIMARY)
            self._is_placeholder = False

    def _restore_placeholder(self, _event) -> None:
        if not self.var.get():
            self._show_placeholder()

    def value(self) -> str:
        if getattr(self, "_is_placeholder", False):
            return ""
        return self.var.get().strip()

    def bind_search(self, func) -> None:
        self.frame.bind("<<Search>>", func)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class ScrollableFrame:
    """Vertically scrollable region; scrollbar appears only when needed."""

    def __init__(self, parent, *, bg: str = theme.SURFACE_2) -> None:
        self.frame = tk.Frame(parent, bg=bg)
        self.canvas = tk.Canvas(self.frame, bg=bg, bd=0, highlightthickness=0)
        self.scrollbar = tk.Scrollbar(
            self.frame, orient="vertical", command=self.canvas.yview, width=10,
            bd=0, highlightthickness=0, troughcolor=theme.SURFACE_1,
            bg=theme.BORDER_STRONG, activebackground=theme.TEXT_MUTED, relief="flat",
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<Button-4>", self._on_wheel)
        self.canvas.bind("<Button-5>", self._on_wheel)

    def _on_inner_configure(self, _event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._sync_scrollbar()

    def _on_canvas_configure(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        self._sync_scrollbar()

    def _sync_scrollbar(self) -> None:
        bounds = self.canvas.bbox("all")
        if not bounds:
            return
        needed = bounds[3] > max(int(self.canvas.winfo_height()), 1)
        if needed and not self.scrollbar.winfo_ismapped():
            self.scrollbar.pack(side="right", fill="y", before=self.canvas)
        elif not needed and self.scrollbar.winfo_ismapped():
            self.scrollbar.pack_forget()

    def _on_wheel(self, event) -> None:
        if getattr(event, "num", None) == 4:
            delta = -1
        elif getattr(event, "num", None) == 5:
            delta = 1
        else:
            delta = -1 if event.delta > 0 else 1
        self.canvas.yview_scroll(delta, "units")

    def clear(self) -> None:
        for child in self.inner.winfo_children():
            child.destroy()

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class EmptyState:
    """Muted placeholder for an empty list or table."""

    def __init__(self, parent, text: str, *, bg: str = theme.SURFACE_2) -> None:
        self.frame = tk.Frame(parent, bg=bg)
        tk.Label(
            self.frame, text=text, font=theme.FONT_SMALL, fg=theme.TEXT_MUTED,
            bg=bg, anchor="w", justify="left", wraplength=200,
        ).pack(anchor="w", padx=12, pady=12)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class StateView:
    """
    Full-region loading/error/empty state.

    Used so pages never look broken while the first snapshot is in
    flight or when the pipe is unreachable.
    """

    def __init__(self, parent, *, bg: str = theme.SURFACE_2) -> None:
        self.frame = tk.Frame(parent, bg=bg)
        self.icon = IconCanvas(self.frame, "info", 22, theme.TEXT_MUTED, bg=bg)
        self.icon.pack(pady=(0, 8))
        self.title = tk.Label(
            self.frame, text="", font=theme.FONT_SECTION, fg=theme.TEXT_PRIMARY, bg=bg
        )
        self.title.pack()
        self.detail = tk.Label(
            self.frame, text="", font=theme.FONT_SMALL, fg=theme.TEXT_SECONDARY, bg=bg,
            wraplength=420, justify="center",
        )
        self.detail.pack(pady=(3, 0))

    def show(self, kind: str, title: str, detail: str = "") -> None:
        icon_name, color = {
            "loading": ("refresh", theme.TEXT_MUTED),
            "error": ("alert", theme.RED),
            "empty": ("info", theme.TEXT_MUTED),
        }.get(kind, ("info", theme.TEXT_MUTED))
        self.icon.set(icon_name, color)
        self.title.configure(text=title)
        self.detail.configure(text=detail)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self

    def pack_forget(self) -> None:
        self.frame.pack_forget()


class ActivityRow:
    """Severity icon + plain-English sentence + mono metadata + link."""

    def __init__(
        self,
        parent,
        *,
        severity: str,
        sentence: str,
        meta: str,
        link_text: str = "Details",
        command: Optional[Callable[[], None]] = None,
    ) -> None:
        from cana_ui.icons import severity_icon

        color = theme.severity_color(severity)
        self.frame = tk.Frame(parent, bg=theme.SURFACE_2)
        self.icon = IconCanvas(self.frame, severity_icon(severity), 16, color)
        self.icon.pack(side="left", padx=(0, 10), anchor="n", pady=2)
        text_col = tk.Frame(self.frame, bg=theme.SURFACE_2)
        text_col.pack(side="left", fill="x", expand=True)
        self.sentence = tk.Label(
            text_col, text=sentence, font=theme.FONT_BODY, fg=theme.TEXT_PRIMARY,
            bg=theme.SURFACE_2, anchor="w", justify="left", wraplength=520,
        )
        self.sentence.pack(anchor="w", fill="x")
        self.meta = tk.Label(
            text_col, text=meta, font=theme.FONT_MONO, fg=theme.TEXT_MUTED,
            bg=theme.SURFACE_2, anchor="w",
        )
        self.meta.pack(anchor="w", pady=(1, 0))
        self.link = LinkLabel(self.frame, link_text, command)
        self.link.pack(side="right", anchor="n", pady=2)
        text_col.bind(
            "<Configure>", lambda e: self.sentence.configure(wraplength=max(120, e.width - 10))
        )

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


class StatusBar:
    """Bottom bar: colored dot + state text + right-aligned mono detail."""

    def __init__(self, parent) -> None:
        self.frame = tk.Frame(parent, bg=theme.SURFACE_1)
        theme.hairline(self.frame, theme.BORDER).pack(fill="x", side="top")
        inner = tk.Frame(self.frame, bg=theme.SURFACE_1)
        inner.pack(fill="x", padx=12, pady=5)
        self.dot = tk.Canvas(
            inner, width=8, height=8, bd=0, highlightthickness=0, bg=theme.SURFACE_1
        )
        self.dot.pack(side="left")
        self._dot_color = theme.RED
        self._dot_drawn = None
        self.dot.bind("<Configure>", lambda _e: self._draw_dot())
        self._draw_dot()
        self.state = tk.Label(
            inner, text="", font=theme.FONT_SMALL, fg=theme.TEXT_SECONDARY, bg=theme.SURFACE_1
        )
        self.state.pack(side="left", padx=(8, 0))
        self.detail = tk.Label(
            inner, text="", font=theme.FONT_MONO, fg=theme.TEXT_SECONDARY, bg=theme.SURFACE_1
        )
        self.detail.pack(side="right")

    def _draw_dot(self) -> None:
        key = (self._dot_color, int(self.dot.winfo_width() or 0), int(self.dot.winfo_height() or 0))
        if getattr(self, "_dot_drawn", None) == key:
            return
        self._dot_drawn = key
        self.dot.delete("all")
        self.dot.create_oval(0, 0, 8, 8, fill=self._dot_color, outline=self._dot_color)

    def set(self, state: str, color: str, detail: str) -> None:
        if (
            getattr(self, "_state", None) == state
            and self._dot_color == color
            and getattr(self, "_detail", None) == detail
        ):
            return
        self._state = state
        self._detail = detail
        self._dot_color = color
        self._draw_dot()
        self.state.configure(text=state)
        self.detail.configure(text=detail)

    def pack(self, **kwargs):
        self.frame.pack(**kwargs)
        return self


__all__ = [
    "ActivityRow",
    "AreaChart",
    "CheckBox",
    "EmptyState",
    "FilterChip",
    "IconCanvas",
    "KpiCard",
    "LinkLabel",
    "PillButton",
    "RangePills",
    "ScrollableFrame",
    "SearchBox",
    "SeverityBars",
    "StateView",
    "StatusBar",
    "StatusDot",
    "StatusTile",
    "TopNav",
    "TrafficChart",
    "nice_peak",
    "round_rect",
    "series_points",
]
