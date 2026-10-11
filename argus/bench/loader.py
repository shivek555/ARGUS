from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from argus.events.schema import Objective

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_scenario(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["_path"] = str(path)
    data["_sha256"] = file_sha256(path)
    return data


def load_all_scenarios(directory: Path = SCENARIO_DIR) -> list[dict[str, Any]]:
    paths = sorted(directory.glob("*.yaml"))
    return [load_scenario(p) for p in paths]


def objective_from_scenario(data: dict[str, Any]) -> Objective:
    obj = data["objective"]
    return Objective(
        task_id=data["id"],
        text=obj["text"],
        allowed_scopes=tuple(obj["allowed_scopes"]),
    )
