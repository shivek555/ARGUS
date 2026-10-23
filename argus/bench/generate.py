"""Generate AgentEscapeBench v1.

    python -m argus.bench.generate            # write dev; write test only if absent
    python -m argus.bench.generate --check    # regenerate in memory, verify files + manifest
    python -m argus.bench.generate --split test_v2           # blind test v2 (teammate, R1b-1)
    python -m argus.bench.generate --split test_v2 --check

Deterministic: no timestamps, sorted keys, LF line endings, seeded per trajectory.
The TEST split is frozen once written: it is never overwritten unless
``--refreeze-test`` is passed, which requires a new ADR (see docs/BENCH_V1.md).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import platform
import random
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

from argus.bench import templates_dev, templates_test
from argus.bench.steps import BENCH_VERSION, GENERATOR_VERSION, Trajectory, as_record, finalize

OUT_DIR = Path(__file__).resolve().parent / "v1"
TEST_V2_DIR = Path(__file__).resolve().parent / "v2_test"
TEST_V2_MODULE = "argus.bench.templates_test_v2"
TEST_V2_SEED_BASE = 950_000
COMMAND = "python -m argus.bench.generate"

# Disjoint seed ranges: dev 100000-111999, test 900000-911999.
SPLITS: dict[str, tuple[ModuleType, int, int]] = {
    "dev": (templates_dev, 100_000, 20),
    "test": (templates_test, 900_000, 15),
}


def generate_split(split: str) -> list[Trajectory]:
    module, seed_base, per_template = SPLITS[split]
    out: list[Trajectory] = []
    for t_idx, name in enumerate(sorted(module.TEMPLATES)):
        fn = module.TEMPLATES[name]
        for i in range(per_template):
            seed = seed_base + t_idx * 1000 + i
            draft = fn(random.Random(seed), module.VOCAB, module.KNOBS)
            out.append(finalize(draft, split=split, idx=i, seed=seed, vocab=module.VOCAB))
    return out


def generate_test_v2() -> tuple[ModuleType, list[Trajectory]]:
    """Blind test v2 (ADR-0006). Templates are written by a teammate; detector-side
    code must never import this module (tests/test_blindness.py)."""
    module = importlib.import_module(TEST_V2_MODULE)
    per_template = int(getattr(module, "PER_TEMPLATE", 15))
    out: list[Trajectory] = []
    for t_idx, name in enumerate(sorted(module.TEMPLATES)):
        for i in range(per_template):
            seed = TEST_V2_SEED_BASE + t_idx * 1000 + i
            draft = module.TEMPLATES[name](random.Random(seed), module.VOCAB, module.KNOBS)
            out.append(finalize(draft, split="test", idx=i, seed=seed, vocab=module.VOCAB,
                                id_prefix="testv2"))
    return module, out


def _main_test_v2(check: bool, refreeze: bool, out_dir: Path) -> int:
    try:
        module, trajs = generate_test_v2()
    except ModuleNotFoundError as exc:
        if exc.name != TEST_V2_MODULE:
            raise
        print(f"{TEST_V2_MODULE} does not exist yet. Write it first: see docs/TEST_V2_AUTHORING.md.",
              file=sys.stderr)
        return 3
    blob = serialize(trajs)
    sha = hashlib.sha256(blob).hexdigest()
    path = out_dir / "test.jsonl"
    if check:
        manifest = out_dir / "manifest.json"
        want = json.loads(manifest.read_text(encoding="utf-8"))["sha256"] if manifest.exists() else None
        ok = path.exists() and path.read_bytes() == blob and want == sha
        print(f"test_v2: {'OK' if ok else 'MISMATCH'} ({path})")
        return 0 if ok else 1
    if path.exists() and path.read_bytes() != blob and not refreeze:
        print("refusing: frozen test_v2 differs from a fresh generation (needs an ADR + --refreeze-test).",
              file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    manifest = {
        "bench_version": "test_v2", "generator_version": GENERATOR_VERSION, "command": f"{COMMAND} --split test_v2",
        "python": platform.python_version(), "file": "test.jsonl", "sha256": sha,
        "seed_base": TEST_V2_SEED_BASE, "templates_module": module.__name__, **split_stats(trajs),
    }
    (out_dir / "manifest.json").write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def serialize(trajs: list[Trajectory]) -> bytes:
    lines = [json.dumps(as_record(t), sort_keys=True, ensure_ascii=True) for t in trajs]
    return ("\n".join(lines) + "\n").encode("utf-8")


def split_stats(trajs: list[Trajectory]) -> dict[str, object]:
    return {
        "n": len(trajs),
        "by_type": dict(sorted(Counter(t.type for t in trajs).items())),
        "by_variant": dict(sorted(Counter(t.variant for t in trajs).items())),
        "by_family": dict(sorted(Counter(t.family for t in trajs).items())),
        "by_template": dict(sorted(Counter(t.template for t in trajs).items())),
        "mean_steps": round(sum(len(t.calls) for t in trajs) / len(trajs), 2),
        "max_steps": max(len(t.calls) for t in trajs),
    }


def build_manifest(blobs: dict[str, bytes], trajs: dict[str, list[Trajectory]]) -> dict[str, object]:
    return {
        "bench_version": BENCH_VERSION,
        "generator_version": GENERATOR_VERSION,
        "command": COMMAND,
        "python": platform.python_version(),
        "splits": {
            name: {
                "file": f"{name}.jsonl",
                "sha256": hashlib.sha256(blobs[name]).hexdigest(),
                "seed_base": SPLITS[name][1],
                "per_template": SPLITS[name][2],
                "templates_module": SPLITS[name][0].__name__,
                **split_stats(trajs[name]),
            }
            for name in SPLITS
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify on-disk files match a fresh generation")
    ap.add_argument("--refreeze-test", action="store_true", help="overwrite the frozen test split (needs an ADR)")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--split", choices=("v1", "test_v2"), default="v1")
    args = ap.parse_args(argv)
    if args.split == "test_v2":
        return _main_test_v2(args.check, args.refreeze_test, args.out or TEST_V2_DIR)
    args.out = args.out or OUT_DIR

    trajs = {name: generate_split(name) for name in SPLITS}
    blobs = {name: serialize(t) for name, t in trajs.items()}

    if args.check:
        ok = True
        for name, blob in blobs.items():
            path = args.out / f"{name}.jsonl"
            same = path.exists() and path.read_bytes() == blob
            print(f"{name}: {'OK' if same else 'MISMATCH'} ({path})")
            ok &= same
        manifest = args.out / "manifest.json"
        recorded = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
        for name, blob in blobs.items():
            want = recorded.get("splits", {}).get(name, {}).get("sha256")
            got = hashlib.sha256(blob).hexdigest()
            print(f"{name} manifest sha256: {'OK' if want == got else 'MISMATCH'}")
            ok &= want == got
        return 0 if ok else 1

    args.out.mkdir(parents=True, exist_ok=True)
    test_path = args.out / "test.jsonl"
    if test_path.exists() and not args.refreeze_test:
        if test_path.read_bytes() != blobs["test"]:
            print("refusing: frozen test split differs from a fresh generation. "
                  "The generator or test templates changed. Revert them, or "
                  "write an ADR and pass --refreeze-test.", file=sys.stderr)
            return 2
    else:
        test_path.write_bytes(blobs["test"])
    (args.out / "dev.jsonl").write_bytes(blobs["dev"])
    manifest = build_manifest(blobs, trajs)
    (args.out / "manifest.json").write_bytes((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
