"""Cross-platform comparison of generated JSON/YAML artefacts (ADR-0013 correction).

Floating-point results differ in the last digits between Windows and Linux numeric
libraries, so a rerun on another OS is compared numerically (relative tolerance), not by
bytes. Keys whose values are hashes of platform-specific bytes are skipped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

REL_TOL = 1e-6
PLATFORM_SPECIFIC_KEYS = frozenset({"files", "ml_fingerprint"})


def load_any(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    return json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)


def walk(a: Any, b: Any, where: str, out: list[str]) -> float:
    """Mismatches appended to ``out``; returns the largest relative numeric difference seen."""
    num = (int, float)
    if isinstance(a, num) and isinstance(b, num) and not isinstance(a, bool) and not isinstance(b, bool):
        rel = abs(a - b) / max(1.0, abs(a), abs(b))
        if rel > REL_TOL:
            out.append(f"{where}: {a!r} != {b!r}")
        return rel
    if isinstance(a, dict) and isinstance(b, dict):
        worst = 0.0
        for k in sorted(set(a) | set(b)):
            if k in PLATFORM_SPECIFIC_KEYS:
                continue
            if k not in a or k not in b:
                out.append(f"{where}.{k}: missing")
                continue
            worst = max(worst, walk(a[k], b[k], f"{where}.{k}", out))
        return worst
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{where}: length {len(a)} != {len(b)}")
            return 0.0
        return max([walk(x, y, f"{where}[{i}]", out) for i, (x, y) in enumerate(zip(a, b))], default=0.0)
    if a != b:
        out.append(f"{where}: {a!r} != {b!r}")
    return 0.0


def file_diff(a: Path, b: Path) -> tuple[list[str], float]:
    out: list[str] = []
    return out, walk(load_any(a), load_any(b), a.name, out)


def dir_diff(a: Path, b: Path) -> tuple[list[str], float]:
    """Semantic differences between two directories of JSON/YAML files (numbers within REL_TOL)."""
    names = sorted({p.relative_to(a).as_posix() for p in a.rglob("*") if p.is_file()} |
                   {p.relative_to(b).as_posix() for p in b.rglob("*") if p.is_file()})
    out: list[str] = []
    worst = 0.0
    for n in names:
        if not ((a / n).is_file() and (b / n).is_file()):
            out.append(f"{n}: missing")
            continue
        worst = max(worst, walk(load_any(a / n), load_any(b / n), n, out))
    return out, worst
