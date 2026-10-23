"""requirements.txt / constraints.txt stay exact, consistent, and match this environment."""

import re
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)$")


def _pins(name: str) -> dict[str, str]:
    out = {}
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = PIN.match(line)
        assert m, f"{name}: not an exact pin: {line!r}"
        out[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    return out


def test_requirements_are_exact_and_locked():
    req, lock = _pins("requirements.txt"), _pins("constraints.txt")
    for name, ver in req.items():
        assert lock.get(name) == ver, f"{name}=={ver} differs from constraints.txt"


def test_environment_matches_lock():
    """Packages that decide results must be the locked versions (re-lock after upgrading)."""
    lock = _pins("constraints.txt")
    for name in ("numpy", "scipy", "scikit-learn", "joblib", "threadpoolctl", "pydantic", "pyyaml"):
        assert version(name) == lock[name], f"installed {name} {version(name)} != locked {lock[name]}"
