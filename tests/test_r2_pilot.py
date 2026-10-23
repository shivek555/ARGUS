"""R2-d pilot runner: selection, cost accounting, budget cap, credential stop. Offline (fake client)."""

import json
from types import SimpleNamespace

import pytest

from argus.eval import r2_pilot as pilot
from argus.intent.monitor import MonitorConfig


def _resp(input_tokens=2000, output_tokens=800, model="claude-opus-5-5"):
    text = json.dumps({"intent_alignment": 0.9, "confidence": 0.8, "risk_reason": "fits",
                       "recommended_action": "ALLOW", "evidence_steps": [1]})
    usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens,
                            cache_creation_input_tokens=0, cache_read_input_tokens=0, iterations=None)
    return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=text)],
                           model=model, stop_details=None, usage=usage)


class Fake:
    def __init__(self, resp=None, exc=None):
        self.n, self._resp, self._exc = 0, resp, exc
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def with_options(self, **_):
        return self

    def _create(self, **_):
        self.n += 1
        if self._exc:
            raise self._exc
        return self._resp


def _cfg(tmp_path):
    return MonitorConfig(mode="live", cache_path=tmp_path / "cache.jsonl")


def test_selection_is_fixed_dev_only():
    trajs = pilot.select_trajectories()
    assert len(trajs) == 20 and len({t.id for t in trajs}) == 20
    assert sum(t.type == "attack" for t in trajs) == 9 and sum(t.type == "benign" for t in trajs) == 11
    assert all(t.split == "dev" for t in trajs)
    assert 120 <= sum(len(t.calls) for t in trajs) <= 170  # "~140 judgements"


def test_pricing():
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000,
             "cache_creation_input_tokens": 0, "cache_read_input_tokens": 1_000_000}
    assert pilot.cost_usd(usage, "claude-opus-5-5") == pytest.approx(4 + 20 + 0.20)
    assert pilot.price_for("claude-opus-5") == pilot.PRICES["claude-opus-5"]
    assert pilot.price_for("some-new-model") == pilot.WORST
    assert pilot.cost_usd(None, "claude-opus-5-5") == 0.0


def test_full_run_under_cap_and_cache_reuse(tmp_path):
    fake = Fake(_resp())
    s = pilot.run(cap=5.0, cfg=_cfg(tmp_path), client_factory=lambda: fake, out=tmp_path / "p.json")
    per_call = pilot.cost_usd({"input_tokens": 2000, "output_tokens": 800}, "claude-opus-5-5")
    assert s["stopped_early"] is None and s["live_calls"] == s["judgements"] == fake.n
    assert s["cost_usd_total"] == pytest.approx(per_call * fake.n, rel=1e-3)
    # Second run: everything cached, nothing spent, no calls.
    fake2 = Fake(_resp())
    s2 = pilot.run(cap=5.0, cfg=_cfg(tmp_path), client_factory=lambda: fake2, out=tmp_path / "p2.json")
    assert fake2.n == 0 and s2["cost_usd_total"] == 0.0 and s2["judgements"] == s["judgements"]


def test_budget_cap_stops_before_overrun(tmp_path):
    fake = Fake(_resp(input_tokens=20_000, output_tokens=10_000))  # ~$0.28 per call
    s = pilot.run(cap=1.0, cfg=_cfg(tmp_path), client_factory=lambda: fake, out=tmp_path / "p.json")
    assert s["stopped_early"].startswith("budget") and s["cost_usd_total"] <= 1.0


def test_credential_failure_stops_immediately(tmp_path):
    class AuthenticationError(Exception):
        pass

    fake = Fake(exc=AuthenticationError("bad key"))
    s = pilot.run(cfg=_cfg(tmp_path), client_factory=lambda: fake, out=tmp_path / "p.json")
    assert s["stopped_early"] == "credentials: api_error:AuthenticationError"
    assert fake.n == 1 and s["cost_usd_total"] == 0.0


def test_smoke_makes_one_call(tmp_path):
    fake = Fake(_resp())
    s = pilot.run(smoke=True, cfg=_cfg(tmp_path), client_factory=lambda: fake, out=tmp_path / "p.json")
    assert fake.n == 1 and s["judgements"] == 1


def test_first_call_failure_stops(tmp_path):
    fake = Fake(exc=ConnectionError("down"))
    s = pilot.run(cfg=_cfg(tmp_path), client_factory=lambda: fake, out=tmp_path / "p.json")
    assert s["stopped_early"].startswith("first live call failed") and fake.n == 1


def test_credential_preflight(tmp_path, monkeypatch):
    assert not pilot.credentials_available({"APPDATA": str(tmp_path)})
    assert pilot.credentials_available({"ANTHROPIC_API_KEY": "x"})
    creds = tmp_path / "Anthropic" / "credentials"
    creds.mkdir(parents=True)
    (creds / "default.json").write_text("{}")
    assert pilot.credentials_available({"APPDATA": str(tmp_path)})
    monkeypatch.setattr(pilot, "credentials_available", lambda env=None: False)
    s = pilot.run(cfg=_cfg(tmp_path), out=tmp_path / "p.json")
    assert s["stopped_early"].startswith("credentials: none found") and s["judgements"] == 0
