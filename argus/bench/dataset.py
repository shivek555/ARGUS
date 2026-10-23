"""Load and replay AgentEscapeBench v1 trajectories through the real gateway."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from argus.agents.runtime import run_scripted
from argus.bench.steps import Trajectory
from argus.events.schema import Event, Objective
from argus.gateway.core import Gateway
from argus.policy.engine import PolicyEngine
from argus.sandbox.tools import FakeWorld, make_tools, normalize_path, world_v2
from argus.telemetry.log import MemoryLogger

V1_DIR = Path(__file__).resolve().parent / "v1"
POLICY_V2 = Path(__file__).resolve().parents[2] / "configs" / "policies" / "v2.yaml"


class IntegrityError(RuntimeError):
    pass


def load_split(split: Literal["dev", "test"], directory: Path = V1_DIR) -> list[Trajectory]:
    """Load a split, refusing files whose hash differs from the manifest."""
    path = directory / f"{split}.jsonl"
    blob = path.read_bytes()
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    want = manifest["splits"][split]["sha256"]
    if hashlib.sha256(blob).hexdigest() != want:
        raise IntegrityError(f"{path} does not match manifest sha256 {want[:12]}…")
    return [Trajectory.model_validate(json.loads(line)) for line in blob.decode("utf-8").splitlines() if line]


def objective_of(t: Trajectory) -> Objective:
    return Objective(task_id=t.id, text=t.objective_text, allowed_scopes=t.allowed_scopes)


def build_world(t: Trajectory) -> FakeWorld:
    world = world_v2()
    world.files.update(t.extra_files)
    return world


def replay(
    t: Trajectory, policy: PolicyEngine, mode: Literal["record", "enforce"] = "record"
) -> tuple[list[Event], FakeWorld]:
    world = build_world(t)
    objective = objective_of(t)
    logger = MemoryLogger()
    gateway = Gateway(tools=make_tools(world), policy=policy, logger=logger,
                      objective=objective, agent_id=f"bench-{t.split}", mode=mode)
    run_scripted(gateway, objective, [c.model_dump() for c in t.calls])
    return logger.events, world


def harm_step(t: Trajectory, events: list[Event]) -> int | None:
    """Step at which the harm call executed, or None if it never executed."""
    if t.harm is None:
        return None
    for e in events:
        target = normalize_path(e.target) if e.tool in {"fs_read", "fs_write", "fs_list"} else e.target
        executed = e.result_redacted is not None and not e.result_redacted.startswith("tool_error:")
        if e.tool == t.harm.tool and target == t.harm.target and executed:
            return e.step
    return None
