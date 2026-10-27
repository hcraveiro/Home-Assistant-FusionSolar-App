"""Regression tests for device parent registration compatibility."""

import ast
import inspect
from types import SimpleNamespace
from pathlib import Path
import unittest


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/sensor.py"
)


class ViaDeviceMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_children_resolve_version_compatible_parent_link(self):
        calls = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "DeviceInfo"
        ]
        children = [
            call for call in calls
            if any(isinstance(keyword.value, ast.Call)
                   and isinstance(keyword.value.func, ast.Name)
                   and keyword.value.func.id == "_parent_device_link"
                   for keyword in call.keywords)
        ]
        self.assertEqual(len(children), 3)

    def test_parent_link_on_legacy_home_assistant(self):
        helper = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_parent_device_link"
        )
        namespace = {
            "inspect": inspect,
            "dr": SimpleNamespace(DeviceRegistry=SimpleNamespace(
                async_get_or_create=lambda self, *, via_device=None: None
            )),
        }
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(SOURCE), "exec"), namespace)
        identifier = ("fusion_solar_app", "plant")
        self.assertEqual(
            namespace["_parent_device_link"]("registry-id", identifier),
            {"via_device": identifier},
        )
        self.assertEqual(namespace["_parent_device_link"](None, identifier), {})

    def test_parent_link_on_modern_home_assistant(self):
        helper = next(
            node for node in self.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_parent_device_link"
        )
        namespace = {
            "inspect": inspect,
            "dr": SimpleNamespace(DeviceRegistry=SimpleNamespace(
                async_get_or_create=lambda self, *, via_device_id=None: None
            )),
        }
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(SOURCE), "exec"), namespace)
        self.assertEqual(
            namespace["_parent_device_link"]("registry-id", ("domain", "plant")),
            {"via_device_id": "registry-id"},
        )

    def test_parent_registered_before_entities(self):
        setup = next(
            node for node in self.tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "async_setup_entry"
        )
        src = ast.get_source_segment(self.source, setup)
        self.assertLess(src.index("async_get_or_create("), src.index("add_discovered_sensors()"))
        self.assertLess(src.index("_plant_device_registry_id = plant.id"), src.index("add_discovered_sensors()"))


if __name__ == "__main__":
    unittest.main()
