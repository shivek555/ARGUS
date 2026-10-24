"""R2-L: Ollama adapter, runner and workflow — all offline (httpx MockTransport / fake client)."""

import json
from pathlib import Path

import httpx
import pytest
import yaml

from argus.events.builders import build_pre_event
from argus.events.schema import Objective
from argus.eval import r2_local as R
from argus.intent import prompt as P
from argus.intent.monitor import (
    OLLAMA_NUM_PREDICT, OLLAMA_SCHEMA_HINT, LiveMonitor, MonitorConfig, OllamaClient,
)

ROOT = Path(__file__).resolve().parents[1]
OBJ = Objective(task_id="t", text="Summarize /workspace/README.md.", allowed_scopes=("workspace_read",))


def ev(tool, step=1, **args):
    return build_pre_event(objective=OBJ, agent_id="a", step=step, tool=tool, args=args, prev_tool=None)


def verdict(action="ALLOW", align=0.9):
    return json.dumps({"intent_alignment": align, "confidence": 0.7, "risk_reason": "r",
                       "recommended_action": action, "evidence_steps": [1]})


def ollama_reply(content, done=True, reason="stop", model="llama3.2:3b"):
    return {"model": model, "message": {"role": "assistant", "content": content}, "done": done,
            "done_reason": reason, "prompt_eval_count": 900, "eval_count": 60, "total_duration": 4_000_000_000}


def ocfg(tmp_path, **kw):
    kw.setdefault("model", "llama3.2:3b")
    return MonitorConfig(mode="live", provider="ollama", cache_path=tmp_path / "c.jsonl", **kw)


def mock_client(handler, seen):
    def wrapped(request: httpx.Request):
        seen.append(request)
        return handler(request)
    return OllamaClient("http://127.0.0.1:11434", transport=httpx.MockTransport(wrapped))


# ------------------------------------------------------------- adapter

def test_config_for_ollama():
    c = MonitorConfig(provider="ollama", model="qwen2.5:3b")
    assert (c.effort, c.fallback, c.ollama_url) == ("none", False, "http://127.0.0.1:11434")
    assert MonitorConfig(provider="ollama").model == ""  # user must choose
    assert MonitorConfig.from_env({"ARGUS_LLM_PROVIDER": "ollama", "ARGUS_OLLAMA_URL": "http://localhost:1"}).ollama_url \
        == "http://localhost:1"


def test_request_body_and_success(tmp_path):
    seen = []
    client = mock_client(lambda req: httpx.Response(200, json=ollama_reply(verdict("ESCALATE", 0.2))), seen)
    live = LiveMonitor(ocfg(tmp_path), client_factory=lambda: client)
    r = live.judge(OBJ, [], ev("fs_read", path="/workspace/.env"))
    assert r.source == "live" and r.recommended_action == "ESCALATE" and r.served_by == "llama3.2:3b"
    assert r.usage == {"input_tokens": 900, "output_tokens": 60,
                       "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    req = seen[0]
    assert req.url == httpx.URL("http://127.0.0.1:11434/api/chat") and req.method == "POST"
    body = json.loads(req.content)
    assert body["format"] == P.VERDICT_JSON_SCHEMA and body["stream"] is False
    assert body["options"] == {"temperature": 0, "seed": 0, "num_predict": OLLAMA_NUM_PREDICT}
    assert body["messages"][0] == {"role": "system", "content": P.SYSTEM_PROMPT}
    assert body["messages"][1]["content"].endswith(OLLAMA_SCHEMA_HINT)
    assert not {"tools", "tool_choice"} & set(body)


@pytest.mark.parametrize(("reply", "error"), [
    (ollama_reply("not json"), "schema_invalid:JSONDecodeError"),
    (ollama_reply(verdict(), reason="length"), "max_tokens"),
    (ollama_reply(verdict(), done=False), "incomplete:not_done"),
    (ollama_reply(json.dumps({"recommended_action": "APPROVE"})), "schema_invalid:ValidationError"),
])
def test_bad_replies_fail_closed(tmp_path, reply, error):
    client = mock_client(lambda req: httpx.Response(200, json=reply), [])
    r = LiveMonitor(ocfg(tmp_path), client_factory=lambda: client).judge(
        OBJ, [], ev("http_post", url="https://fake.local/api", body="x"))
    assert r.source == "fail_closed" and r.error == error and r.recommended_action == "ESCALATE"


@pytest.mark.parametrize("status", [404, 500])
def test_http_errors_fail_closed_and_are_not_cached(tmp_path, status):
    client = mock_client(lambda req: httpx.Response(status, json={"error": "model not found"}), [])
    live = LiveMonitor(ocfg(tmp_path), client_factory=lambda: client)
    r = live.judge(OBJ, [], ev("fs_read", path="/workspace/README.md"))
    assert r.error == "api_error:OllamaHTTPError" and r.recommended_action == "MONITOR" and len(live.cache) == 0


@pytest.mark.parametrize("url", ["http://example.com:11434", "http://10.0.0.5:11434", "https://ollama.com"])
def test_only_loopback_hosts(url):
    with pytest.raises(ValueError):
        OllamaClient(url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434", "http://[::1]:11434"])
def test_loopback_hosts_accepted(url):
    assert OllamaClient(url).base_url == url


def test_non_loopback_config_fails_closed_without_network(tmp_path):
    r = LiveMonitor(ocfg(tmp_path, ollama_url="http://evil.fake:11434")).judge(OBJ, [], ev("creds_list"))
    assert r.source == "fail_closed" and r.error == "api_error:ValueError" and r.recommended_action == "ESCALATE"


# -------------------------------------------------------------- runner

class FakeOllama:
    """Deterministic stand-in: low alignment when the current call is a write/egress/credential call."""

    def __init__(self, fail=False):
        self.n, self.fail = 0, fail

    def with_options(self, **_):
        return self

    def chat(self, **body):
        self.n += 1
        if self.fail:
            raise ConnectionError("no ollama")
        current = body["messages"][1]["content"].split('<current_call trust="untrusted">', 1)[1]
        bad = any(t in current for t in ('"fs_write"', '"http_post"', '"creds_list"', '"high"'))
        return ollama_reply(verdict("ESCALATE", 0.2) if bad else verdict("ALLOW", 0.9))


def test_items_and_scope():
    assert len(R.items_for("smoke")) == 1
    pilot = R.items_for("pilot")
    assert 120 <= len(pilot) <= 170
    for name in ("dev", "catalog"):
        items = R.items_for(name)
        assert items and all(R.is_risky(it.current) for it in items)
    assert all(it.t.split == "dev" for it in R.items_for("dev"))
    with pytest.raises(ValueError):
        R.items_for("test")


def test_sharding_partitions():
    items = R.items_for("catalog")
    parts = [R.shard_items(items, 3, k) for k in range(3)]
    ids = [(it.t.id, it.i) for p in parts for it in p]
    assert len(ids) == len(set(ids)) == len(items)
    with pytest.raises(ValueError):
        R.shard_items(items, 2, 2)


def test_pilot_run_summary_resume_and_determinism(tmp_path):
    fake = FakeOllama()
    kw = dict(cfg=ocfg(tmp_path), client_factory=lambda: fake, cache_root=tmp_path / "cache",
              out_root=tmp_path / "out")
    s = R.run("pilot", recheck=5, **kw)
    assert s["complete"] and s["judged"] == s["planned"] and s["valid_json_rate"] == 1.0
    assert s["cost_usd"] == 0.0 and s["determinism"] == {"n": 5, "identical": 5, "rate": 1.0}
    assert s["auroc_unsafe_vs_benign"] is not None
    assert (tmp_path / "out" / "pilot" / "llama3.2_3b-shard0of1.json").exists()
    assert (tmp_path / "cache" / "llama3.2_3b" / "pilot-shard0of1.jsonl").exists()
    calls = fake.n
    again = R.run("pilot", recheck=0, **kw)
    assert again["from_cache"] == again["judged"] and again["live_calls"] == 0 and fake.n == calls


def test_shards_read_each_others_cache(tmp_path):
    fake = FakeOllama()
    kw = dict(cfg=ocfg(tmp_path), client_factory=lambda: fake, cache_root=tmp_path / "cache",
              out_root=tmp_path / "out", recheck=0)
    first = R.run("catalog", shards=2, shard=0, **kw)
    n0 = fake.n
    s = R.run("catalog", shards=1, shard=0, **kw)  # whole run reads shard 0's cache file
    assert s["from_cache"] >= first["judged"]       # every shard-0 item is served from cache
    assert fake.n - n0 == s["live_calls"] < s["judged"]  # only not-yet-cached items cost a call


def test_time_cap_stops_and_resumes(tmp_path):
    ticks = iter(range(0, 10**6, 400))  # each clock read advances 400 s
    s = R.run("dev", time_cap_min=30, cfg=ocfg(tmp_path), client_factory=FakeOllama,
              cache_root=tmp_path / "cache", out_root=tmp_path / "out", recheck=0, clock=lambda: next(ticks))
    assert s["stopped_early"].startswith("time cap") and 0 < s["judged"] < s["planned"]


def test_first_call_failure_stops(tmp_path):
    s = R.run("pilot", cfg=ocfg(tmp_path), client_factory=lambda: FakeOllama(fail=True),
              cache_root=tmp_path / "cache", out_root=tmp_path / "out", recheck=0)
    assert s["stopped_early"].startswith("first call failed") and s["judged"] == 1


def test_requires_ollama_provider(tmp_path):
    with pytest.raises(SystemExit):
        R.run("smoke", cfg=MonitorConfig(provider="openai", model="x", cache_path=tmp_path / "c"))


def test_choose_model_rule():
    pilots = {
        "llama3.2:3b": {"valid_json_rate": 0.99, "auroc_unsafe_vs_benign": 0.71, "latency_ms": {"p50": 9000}},
        "qwen2.5:3b": {"valid_json_rate": 0.97, "auroc_unsafe_vs_benign": 0.78, "latency_ms": {"p50": 12000}},
        "phi4-mini:3.8b": {"valid_json_rate": 0.90, "auroc_unsafe_vs_benign": 0.95, "latency_ms": {"p50": 5000}},
    }
    assert R.choose_model(pilots)["selected"] == "qwen2.5:3b"
    assert R.choose_model({"m": {"valid_json_rate": 0.5}})["selected"] is None
    assert R.CANDIDATES == ("llama3.2:3b", "qwen2.5:3b")


# ------------------------------------------------------------ workflow

WF = yaml.safe_load((ROOT / ".github" / "workflows" / "r2-llm.yml").read_text(encoding="utf-8"))
WF_TEXT = (ROOT / ".github" / "workflows" / "r2-llm.yml").read_text(encoding="utf-8")


def test_workflow_is_manual_only_and_secretless():
    triggers = WF.get("on", WF.get(True))  # PyYAML parses the key `on` as True
    assert set(triggers) == {"workflow_dispatch"}
    assert "secrets." not in WF_TEXT and "pull_request" not in WF_TEXT
    assert WF["permissions"] == {"contents": "write"}
    assert WF["concurrency"]["group"] == "r2-llm"


def test_workflow_inputs_never_interpolated_into_shell():
    for step in WF["jobs"]["monitor"]["steps"]:
        assert "${{" not in step.get("run", ""), step.get("name")


def test_workflow_pins_and_limits():
    assert WF["env"]["OLLAMA_PIN"] == "0.40.2"
    assert WF["env"]["ARGUS_LLM_PROVIDER"] == "ollama"
    assert WF["jobs"]["monitor"]["timeout-minutes"] < 360
    options = WF.get("on", WF.get(True))["workflow_dispatch"]["inputs"]["model"]["options"]
    assert list(R.CANDIDATES) + list(R.RESERVE) == options
    commit = next(s for s in WF["jobs"]["monitor"]["steps"] if s.get("name", "").startswith("Commit"))
    assert "git add argus/intent/cache/ollama eval/r2l" in commit["run"]


def test_runners_pinned_to_ubuntu_2404():
    """ubuntu-latest moved to 26.04 (Oct 2026), which has no Python 3.11.9 build; pilots ran on 24.04."""
    for wf in ("r2-llm.yml", "ci.yml"):
        doc = yaml.safe_load((ROOT / ".github" / "workflows" / wf).read_text(encoding="utf-8"))
        for name, job in doc["jobs"].items():
            assert job["runs-on"] == "ubuntu-24.04", (wf, name)
