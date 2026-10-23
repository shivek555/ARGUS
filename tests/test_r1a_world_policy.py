"""R1-a: world v2, fs_list, workspace confinement (policy v2), v0 freeze."""

import socket
from pathlib import Path

import pytest

from argus.agents.runtime import run_scripted
from argus.bench.loader import load_all_scenarios, objective_from_scenario
from argus.events.builders import build_pre_event, redact_result, sensitivity_for
from argus.events.schema import Objective
from argus.gateway.core import Gateway
from argus.policy.engine import PolicyEngine
from argus.sandbox import tools as sandbox
from argus.sandbox.tools import default_world, make_tools, normalize_path, world_v2
from argus.telemetry.log import MemoryLogger

ROOT = Path(__file__).resolve().parents[1]
POC = PolicyEngine.from_yaml(ROOT / "configs" / "policies" / "poc.yaml")
V2 = PolicyEngine.from_yaml(ROOT / "configs" / "policies" / "v2.yaml")
READ_ONLY = Objective(task_id="t", text="Summarize README", allowed_scopes=("workspace_read",))

# Copied from docs/EXPERIMENTS.md. Benchmark v0 must stay byte-identical.
V0_HASHES = {
    "A-creds-s1": "59f9da3507029a88c5db72e8042311fac7e6f6317bc837ce1d3c5b16757675cf",
    "A-creds-s2": "3d1b4a56d8f14da3667ab2fbea51ef6392fd846aad3131cf103ac4f13274d888",
    "A-hijack-s1": "402d124ca66815ab7f6298a17d472e9ddd829c5f9ed7670fb49fcd11a8c7c26b",
    "A-hijack-s2": "e32fb7fb91a7d1cda2d02661c6e6ecc7af8307965c7a85595c346b87b93abc94",
    "A-slow-s1": "8f8243da195d4f4f4330dfd02e3a98d09c5ae45e63396a172b6f8d30d1838914",
    "A-slow-s2": "34f2771cb573dfc24c108879cfe8e90b0a03d9bac087f558b0ce8d0cb998e289",
    "B-analytics-s1": "a85c37898e81d0877b89830f710adcddc904eddf3763bbfbeaff1dc3e7dfff54",
    "B-analytics-s2": "2fbb1ccf972b31ac83074fa11be38dc1f258e46faccfa2a384ce9e69d3df6985",
    "B-audit-s1": "b0d5b99c4aa73546f1292653e2f17f8ab872e13cbb850d662639ed8fd9418df3",
    "B-audit-s2": "880e1a28b35ea36bf5b212ed6db98db045d220edb2035246fcfb3682bde6bbaf",
}


def _event(tool, args, objective=READ_ONLY):
    return build_pre_event(objective=objective, agent_id="a", step=1, tool=tool, args=args, prev_tool=None)


def _replay(data, policy):
    objective = objective_from_scenario(data)
    logger = MemoryLogger()
    gw = Gateway(tools=make_tools(default_world()), policy=policy, logger=logger,
                 objective=objective, agent_id="t", mode="record")
    run_scripted(gw, objective, data["calls"])
    return [e.decision for e in logger.events]


# ----------------------------------------------------------------- v0 freeze

def test_v0_scenarios_unchanged():
    assert {s["id"]: s["_sha256"] for s in load_all_scenarios()} == V0_HASHES


def test_v0_decisions_identical_under_policy_v2():
    """Confinement must not change any v0 decision (all v0 paths are in /workspace)."""
    for data in load_all_scenarios():
        assert _replay(data, POC) == _replay(data, V2), data["id"]


def test_default_world_unchanged_by_v2():
    assert "/workspace/.env" not in default_world().files
    assert set(default_world().files) < set(world_v2().files)


# --------------------------------------------------------------- confinement

@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/home/agent/.ssh/id_rsa",
        "/workspace/../etc/passwd",
        "/workspace/./../home/agent/.aws/credentials",
        "/workspacex/file",
        "//etc//passwd",
        "",
        "relative/../../etc/passwd",
    ],
)
@pytest.mark.parametrize("tool", ["fs_read", "fs_list", "fs_write"])
def test_confinement_blocks_outside_workspace(tool, path):
    args = {"path": path, "content": "x"} if tool == "fs_write" else {"path": path}
    verdict = V2.evaluate(_event(tool, args), READ_ONLY)
    assert verdict.decision == "BLOCK"
    assert verdict.rule == "workspace.confinement"


@pytest.mark.parametrize(
    "path", ["/workspace", "/workspace/", "/workspace/.env", "/workspace/a/../secrets/deploy_key"]
)
def test_confinement_allows_inside_workspace(path):
    assert V2.evaluate(_event("fs_read", {"path": path}), READ_ONLY).decision == "ALLOW"


def test_in_scope_secret_read_is_policy_compliant():
    """The gap R1 targets: reading .env under workspace_read passes every rule."""
    assert V2.decide(_event("fs_read", {"path": "/workspace/.env"}), READ_ONLY) == "ALLOW"


def test_poc_policy_has_no_confinement():
    assert POC.workspace_root is None
    assert POC.decide(_event("fs_read", {"path": "/etc/passwd"}), READ_ONLY) == "ALLOW"


def test_gateway_enforces_confinement_without_executing():
    world = world_v2()
    logger = MemoryLogger()
    gw = Gateway(tools=make_tools(world), policy=V2, logger=logger,
                 objective=READ_ONLY, agent_id="t", mode="enforce")
    result = gw.invoke("fs_read", {"path": "/workspace/../home/agent/.ssh/id_rsa"})
    assert result.decision == "BLOCK" and result.result is None
    result = gw.invoke("fs_write", {"path": "/etc/cron.d/persist", "content": "x"})
    assert result.decision == "BLOCK"
    assert "/etc/cron.d/persist" not in world.files


# ------------------------------------------------------------------- fs_list

def test_fs_list_children():
    tools = make_tools(world_v2())
    assert tools["fs_list"]("/workspace/configs") == ["app.yaml", "database.yaml", "logging.yaml"]
    root = tools["fs_list"]("/workspace")
    assert ".env" in root and "secrets/" in root and "src/" in root
    assert tools["fs_list"]("/") == ["etc/", "home/", "workspace/"]


def test_fs_list_errors():
    tools = make_tools(world_v2())
    with pytest.raises(FileNotFoundError):
        tools["fs_list"]("/workspace/nope")
    with pytest.raises(NotADirectoryError):
        tools["fs_list"]("/workspace/README.md")


def test_fs_list_event_shape():
    e = _event("fs_list", {"path": "/workspace/secrets"})
    assert e.action == "list" and e.target == "/workspace/secrets"
    assert e.data_sensitivity == "high"


def test_normalize_path():
    assert normalize_path("/workspace/a/../b//c/.") == "/workspace/b/c"
    assert normalize_path("workspace/x") == "/workspace/x"
    assert normalize_path("") == ""


def test_v2_tools_open_no_sockets(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("socket connect must not be used")

    monkeypatch.setattr(socket.socket, "connect", boom)
    tools = make_tools(world_v2())
    tools["fs_list"]("/workspace")
    tools["fs_read"]("/workspace/.env")
    tools["http_post"]("https://fake.local/api", "x")


# ---------------------------------------------------------- canaries / labels

def test_every_v2_secret_is_a_canary_and_redacted():
    world = world_v2()
    canaries = [v for k, v in vars(sandbox).items() if k.startswith("CANARY_")]
    for path in ["/workspace/.env", "/workspace/secrets/deploy_key", "/workspace/configs/database.yaml",
                 "/home/agent/.ssh/id_rsa", "/home/agent/.aws/credentials"]:
        content = world.files[path]
        assert any(c in content for c in canaries), path
        assert redact_result(content) == "[CANARY_PRESENT]"
    assert all(c.endswith("_NOT_REAL") for c in canaries)


@pytest.mark.parametrize(
    ("target", "level"),
    [
        ("/workspace/.env", "high"),
        ("/workspace/secrets/deploy_key", "high"),
        ("/home/agent/.ssh/id_rsa", "high"),
        ("/home/agent/.aws/credentials", "high"),
        ("/workspace/configs/database.yaml", "medium"),  # path-only heuristic limit
        ("/workspace/README.md", "low"),
    ],
)
def test_sensitivity_v2(target, level):
    assert sensitivity_for("fs_read", target) == level
