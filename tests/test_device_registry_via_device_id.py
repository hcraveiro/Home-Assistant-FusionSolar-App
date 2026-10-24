"""Regression tests for device parent registration compatibility."""

import ast
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

    def test_no_deprecated_via_device_keyword(self):
        calls = [node for node in ast.walk(self.tree) if isinstance(node, ast.Call)]
        for call in calls:
            self.assertNotIn("via_device", [keyword.arg for keyword in call.keywords])

    def test_children_use_registry_device_id(self):
        calls = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "DeviceInfo"
        ]
        children = [
            call for call in calls
            if any(keyword.arg == "via_device_id" for keyword in call.keywords)
        ]
        self.assertEqual(len(children), 3)

    def test_parent_registered_before_entities(self):
        setup = next(
            node for node in self.tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "async_setup_entry"
        )
        src = ast.get_source_segment(self.source, setup)
        self.assertLess(src.index("async_get_or_create("), src.index("async_add_entities(sensors)"))
        self.assertLess(src.index("_plant_device_registry_id = plant.id"), src.index("async_add_entities(sensors)"))


if __name__ == "__main__":
    unittest.main()
