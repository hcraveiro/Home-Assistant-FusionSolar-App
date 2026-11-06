"""Load the identity helper without importing HA or the integration entry point."""
import ast
from pathlib import Path
from types import SimpleNamespace


def identity_module():
    path = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/identity.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    tree.body = [node for node in tree.body
                 if not (isinstance(node, ast.ImportFrom) and node.level)]
    namespace = {"DOMAIN": "fusion_solar_app"}
    exec(compile(tree, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)
