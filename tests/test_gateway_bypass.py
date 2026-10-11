import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "argus" / "agents"


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_agent_runtime_does_not_import_sandbox_tools():
    for path in AGENTS.rglob("*.py"):
        imported = _imports(path)
        assert "argus.sandbox.tools" not in imported
        assert "argus.sandbox" not in imported
