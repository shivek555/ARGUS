"""ADR-0006: detector-side code must stay blind to the teammate-written test v2.

Only the final R1b-4 runner may load it, and it is added only after the R1b
protocol commit. Until then no module outside the generator may mention it.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "argus"
MARKERS = ("v2_test", "templates_test_v2", "test_v2")
ALLOWED = {
    ROOT / "bench" / "generate.py",        # builds the split for the teammate
    ROOT / "eval" / "r1b_final.py",        # R1b-4 only, written after the protocol commit
}


def test_no_detector_side_module_references_test_v2():
    offenders = []
    for path in ROOT.rglob("*.py"):
        if path in ALLOWED or path.name == "templates_test_v2.py":
            continue
        text = path.read_text(encoding="utf-8")
        if any(m in text for m in MARKERS):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_generator_reports_missing_module_cleanly(capsys):
    from argus.bench import generate

    if (ROOT / "bench" / "templates_test_v2.py").exists():
        return  # teammate has delivered; the freeze tests take over
    assert generate.main(["--split", "test_v2"]) == 3
    assert "TEST_V2_AUTHORING" in capsys.readouterr().err
