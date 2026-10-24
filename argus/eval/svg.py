"""Tiny standard-library SVG charts for `reproduce` (ADR-0013: no plotting dependency).

Output is deterministic text (fixed decimals, sorted input order), so figures can be
checked byte-for-byte in CI like the tables.
"""

from __future__ import annotations

from html import escape
from typing import Sequence

W, H = 560, 360
L, R, T, B = 56, 150, 36, 48            # margins (legend on the right)
COLORS = ("#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c")
INK, GRID = "#1f2937", "#d1d5db"


def _f(x: float) -> str:
    return f"{x:.1f}"


def _frame(title: str, xlabel: str, ylabel: str, xmax: float, ymax: float, xticks: Sequence[float],
           yticks: Sequence[float], xfmt: str = "{:.1f}", yfmt: str = "{:.1f}") -> list[str]:
    pw, ph = W - L - R, H - T - B
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
           f'font-family="Helvetica, Arial, sans-serif" font-size="12">',
           f'<rect width="{W}" height="{H}" fill="#ffffff"/>',
           f'<text x="{L}" y="20" font-size="14" font-weight="bold" fill="{INK}">{escape(title)}</text>']
    for v in xticks:
        x = L + pw * v / xmax
        out += [f'<line x1="{_f(x)}" y1="{T}" x2="{_f(x)}" y2="{T + ph}" stroke="{GRID}"/>',
                f'<text x="{_f(x)}" y="{T + ph + 16}" text-anchor="middle" fill="{INK}">{xfmt.format(v)}</text>']
    for v in yticks:
        y = T + ph - ph * v / ymax
        out += [f'<line x1="{L}" y1="{_f(y)}" x2="{L + pw}" y2="{_f(y)}" stroke="{GRID}"/>',
                f'<text x="{L - 6}" y="{_f(y + 4)}" text-anchor="end" fill="{INK}">{yfmt.format(v)}</text>']
    out += [f'<rect x="{L}" y="{T}" width="{pw}" height="{ph}" fill="none" stroke="{INK}"/>',
            f'<text x="{L + pw / 2:.1f}" y="{H - 10}" text-anchor="middle" fill="{INK}">{escape(xlabel)}</text>',
            f'<text x="14" y="{T + ph / 2:.1f}" text-anchor="middle" fill="{INK}" '
            f'transform="rotate(-90 14 {T + ph / 2:.1f})">{escape(ylabel)}</text>']
    return out


def _legend(names: Sequence[str]) -> list[str]:
    out = []
    for i, n in enumerate(names):
        y = T + 10 + 18 * i
        out += [f'<rect x="{W - R + 12}" y="{y - 9}" width="12" height="12" fill="{COLORS[i % len(COLORS)]}"/>',
                f'<text x="{W - R + 30}" y="{y + 1}" fill="{INK}">{escape(n)}</text>']
    return out


def line_chart(title: str, xlabel: str, ylabel: str, series: dict[str, Sequence[tuple[float, float]]],
               xmax: float = 1.0, ymax: float = 1.0, diagonal: bool = False, xfmt: str = "{:.1f}") -> str:
    pw, ph = W - L - R, H - T - B
    ticks = [round(xmax * i / 5, 4) for i in range(6)]
    out = _frame(title, xlabel, ylabel, xmax, ymax, ticks, [round(ymax * i / 5, 4) for i in range(6)], xfmt)
    if diagonal:
        out.append(f'<line x1="{L}" y1="{T + ph}" x2="{L + pw}" y2="{T}" stroke="{GRID}" stroke-dasharray="4 4"/>')
    for i, (name, pts) in enumerate(series.items()):
        d = " ".join(f"{_f(L + pw * min(x, xmax) / xmax)},{_f(T + ph - ph * min(y, ymax) / ymax)}" for x, y in pts)
        out.append(f'<polyline fill="none" stroke="{COLORS[i % len(COLORS)]}" stroke-width="2" points="{d}">'
                   f'<title>{escape(name)}</title></polyline>')
    out += _legend(list(series)) + ["</svg>"]
    return "\n".join(out) + "\n"


def histogram(title: str, xlabel: str, ylabel: str, values: Sequence[int], label: str) -> str:
    """Bar per integer value (e.g. steps before harm)."""
    pw, ph = W - L - R, H - T - B
    lo, hi = (min(values), max(values)) if values else (0, 1)
    bins = list(range(lo, hi + 1))
    counts = [sum(v == b for v in values) for b in bins]
    ymax = max(5, max(counts) if counts else 1)
    ymax = ((ymax + 4) // 5) * 5
    out = _frame(title, xlabel, ylabel, 1.0, ymax, [], [ymax * i / 5 for i in range(6)], yfmt="{:.0f}")
    bw = pw / len(bins)
    for b, c in zip(bins, counts):
        x = L + bw * (b - lo)
        h = ph * c / ymax
        out += [f'<rect x="{_f(x + 2)}" y="{_f(T + ph - h)}" width="{_f(bw - 4)}" height="{_f(h)}" '
                f'fill="{COLORS[0]}"><title>{b}: {c}</title></rect>',
                f'<text x="{_f(x + bw / 2)}" y="{T + ph + 16}" text-anchor="middle" fill="{INK}">{b}</text>']
    out += _legend([label]) + ["</svg>"]
    return "\n".join(out) + "\n"
