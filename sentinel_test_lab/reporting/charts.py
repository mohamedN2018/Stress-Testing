"""Dependency-free SVG charts built from recorded data.

The same SVG is embedded in the HTML report and rasterized for the PDF report.
Chart text is kept to numbers and Latin technical labels so it renders the
same everywhere; Arabic titles live in the surrounding document.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from html import escape
from typing import Any, Sequence

BLUE, CYAN, RED, AMBER, GREEN, GREY = "#2563eb", "#0891b2", "#dc2626", "#d97706", "#16a34a", "#64748b"
INK, GRID, MUTED = "#0f172a", "#e2e8f0", "#64748b"
FONT = "font-family=\"Segoe UI, Tahoma, Arial, sans-serif\""


@dataclass(frozen=True)
class Line:
    name: str
    color: str
    points: Sequence[tuple[float, float]]
    dashed: bool = False


def nice_ticks(maximum: float, count: int = 4) -> list[float]:
    if maximum <= 0 or not math.isfinite(maximum):
        return [0.0, 1.0]
    raw = maximum / count
    magnitude = 10 ** math.floor(math.log10(raw))
    step = next(m * magnitude for m in (1, 2, 2.5, 5, 10) if m * magnitude >= raw)
    ticks = [round(i * step, 10) for i in range(int(math.ceil(maximum / step)) + 1)]
    return ticks


def _fmt(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:g}k"
    return f"{value:g}"


def line_chart(lines: Sequence[Line], y_unit: str = "", width: int = 760, height: int = 250) -> str:
    """Multi-series line chart over time (x = seconds). Returns '' when there is no data."""
    lines = [ln for ln in lines if len(ln.points) >= 1]
    if not lines:
        return ""
    left, right, top, bottom = 52, 16, 30, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    xs = [x for ln in lines for x, _ in ln.points]
    ys = [y for ln in lines for _, y in ln.points]
    x_min, x_max = min(xs), max(xs)
    if x_max <= x_min:
        x_max = x_min + 1
    ticks = nice_ticks(max(ys))
    y_max = ticks[-1] or 1.0

    def sx(x: float) -> float:
        return left + (x - x_min) / (x_max - x_min) * plot_w

    def sy(y: float) -> float:
        return top + plot_h - (y / y_max) * plot_h

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" role="img" direction="ltr">',
           f'<rect width="{width}" height="{height}" fill="#ffffff"/>']
    for tick in ticks:
        y = sy(tick)
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="{GRID}"/>')
        out.append(f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end" font-size="11" fill="{MUTED}" '
                   f'{FONT}>{_fmt(tick)}</text>')
    for tick in nice_ticks(x_max - x_min, 6):
        x_value = x_min + tick
        if x_value > x_max + 1e-9:
            continue
        out.append(f'<text x="{sx(x_value):.1f}" y="{height - 14}" text-anchor="middle" font-size="11" '
                   f'fill="{MUTED}" {FONT}>{_fmt(round(x_value, 1))}s</text>')
    if y_unit:
        out.append(f'<text x="{left}" y="{top - 12}" font-size="11" fill="{MUTED}" {FONT}>{escape(y_unit)}</text>')
    legend_x = width - right
    for ln in reversed(lines):
        label_w = 14 + 7 * len(ln.name) + 14
        legend_x -= label_w
        out.append(f'<rect x="{legend_x}" y="{top - 21}" width="10" height="10" rx="2" fill="{ln.color}"/>')
        out.append(f'<text x="{legend_x + 14}" y="{top - 12}" font-size="11" fill="{INK}" {FONT}>'
                   f'{escape(ln.name)}</text>')
    for ln in lines:
        dash = ' stroke-dasharray="5 4"' if ln.dashed else ""
        if len(ln.points) == 1:
            x, y = ln.points[0]
            out.append(f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="3" fill="{ln.color}"/>')
            continue
        path = " ".join(f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(y):.1f}" for i, (x, y) in enumerate(ln.points))
        out.append(f'<path d="{path}" fill="none" stroke="{ln.color}" stroke-width="2" '
                   f'stroke-linejoin="round"{dash}/>')
    out.append("</svg>")
    return "".join(out)


def bar_chart(items: Sequence[tuple[str, float, str]], y_unit: str = "", width: int = 760, height: int = 220) -> str:
    """Vertical bar chart: (label, value, color). Returns '' when every value is zero/missing."""
    items = [(label, float(value or 0), color) for label, value, color in items]
    if not items or not any(v > 0 for _, v, _ in items):
        return ""
    left, right, top, bottom = 52, 16, 26, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    ticks = nice_ticks(max(v for _, v, _ in items))
    y_max = ticks[-1] or 1.0
    slot = plot_w / len(items)
    bar_w = min(70.0, slot * 0.6)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" '
           f'height="{height}" role="img" direction="ltr">',
           f'<rect width="{width}" height="{height}" fill="#ffffff"/>']
    for tick in ticks:
        y = top + plot_h - tick / y_max * plot_h
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" stroke="{GRID}"/>')
        out.append(f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end" font-size="11" fill="{MUTED}" '
                   f'{FONT}>{_fmt(tick)}</text>')
    if y_unit:
        out.append(f'<text x="{left}" y="{top - 10}" font-size="11" fill="{MUTED}" {FONT}>{escape(y_unit)}</text>')
    for i, (label, value, color) in enumerate(items):
        x = left + slot * i + (slot - bar_w) / 2
        h = value / y_max * plot_h
        y = top + plot_h - h
        out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(h, 0):.1f}" rx="3" fill="{color}"/>')
        out.append(f'<text x="{x + bar_w / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle" font-size="11" '
                   f'fill="{INK}" {FONT}>{round(value, 1):,.6g}</text>')
        out.append(f'<text x="{x + bar_w / 2:.1f}" y="{height - 14}" text-anchor="middle" font-size="11" '
                   f'fill="{MUTED}" {FONT}>{escape(label)}</text>')
    out.append("</svg>")
    return "".join(out)


def run_charts(record: dict[str, Any]) -> list[tuple[str, str]]:
    """(Arabic title, SVG) pairs for a run. Charts without data are omitted, never faked."""
    series = [s for s in record.get("series") or [] if "t" in s]
    summary = record.get("summary") or {}
    charts: list[tuple[str, str]] = []
    if len(series) >= 2:
        charts.append(("الطلبات في الثانية وعدد المستخدمين", line_chart([
            Line("RPS", BLUE, [(s["t"], s.get("rps") or 0) for s in series]),
            Line("Users", GREY, [(s["t"], s.get("users") or 0) for s in series], dashed=True),
        ])))
        latency = [s for s in series if s.get("avg_ms") is not None]
        if latency:
            charts.append(("زمن الاستجابة عبر الوقت", line_chart([
                Line("avg ms", CYAN, [(s["t"], s["avg_ms"]) for s in latency]),
                Line("p95 ms", AMBER, [(s["t"], s.get("p95_ms") or s["avg_ms"]) for s in latency]),
            ], "ms")))
        if any(s.get("failed") for s in series):
            charts.append(("الطلبات الفاشلة في كل ثانية", line_chart([
                Line("failed/s", RED, [(s["t"], s.get("failed") or 0) for s in series]),
                Line("429/s", AMBER, [(s["t"], s.get("s429") or 0) for s in series], dashed=True),
            ])))
    status = bar_chart([
        ("2xx", summary.get("s2xx", 0), GREEN), ("3xx", summary.get("s3xx", 0), BLUE),
        ("4xx", summary.get("s4xx", 0), AMBER), ("5xx", summary.get("s5xx", 0), RED),
        ("no response", summary.get("transport_errors", 0), GREY),
    ], "requests")
    if status:
        charts.append(("توزيع أكواد الاستجابة", status))
    percentiles = bar_chart([
        (label, summary.get(key) or 0, CYAN)
        for label, key in (("p50", "p50_ms"), ("p90", "p90_ms"), ("p95", "p95_ms"), ("p99", "p99_ms"))
    ], "ms")
    if percentiles:
        charts.append(("النِّسب المئوية لزمن الاستجابة", percentiles))
    steps = (record.get("details") or {}).get("steps")
    if steps:
        chart = bar_chart([
            (f"{s['users']} VU", s.get("p95_ms") or 0, GREEN if s.get("passed") else RED) for s in steps
        ], "p95 ms")
        if chart:
            charts.append(("p95 لكل مرحلة إجهاد (أخضر = ضمن العتبات)", chart))
    return charts
