"""Regression checks for disconnected optimizer live telemetry."""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"


class OptimizerOfflineTests(unittest.TestCase):
    def test_disconnected_sampling_invalidates_live_readings(self):
        source = (ROOT / "api/optimizer.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertIn('"disconnected", "offline"', source)
        self.assertIn("is_disconnected and key in", source)
        for signal in (
            "outputPower", "inputVoltage", "outputVoltage",
            "inputCurrent", "powerPercent",
        ):
            self.assertIn(f'"{signal}"', source)
        self.assertIn("value = None", source)
        self.assertIn('"dailyEnergy"', source)
        self.assertIn('"connectStatus"', source)

    def test_disconnected_live_sensors_report_unavailable(self):
        source = (ROOT / "sensor.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        sensor = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "FusionSolarSensor"
        )
        available = next(
            node for node in sensor.body
            if isinstance(node, ast.FunctionDef) and node.name == "available"
        )
        method_source = ast.get_source_segment(source, available)
        self.assertIn("Optimizer Output Power", method_source)
        self.assertIn("Optimizer Input Voltage", method_source)
        self.assertIn("Optimizer Output Voltage", method_source)
        self.assertIn("Optimizer Input Current", method_source)
        self.assertIn("Optimizer Power Percent", method_source)
        self.assertIn("self.device.state is None", method_source)
        self.assertIn("return False", method_source)


if __name__ == "__main__":
    unittest.main()
