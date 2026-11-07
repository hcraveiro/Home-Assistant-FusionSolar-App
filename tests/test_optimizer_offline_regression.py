"""Regression checks for disconnected optimizer live telemetry."""

import ast
from pathlib import Path
import unittest

import pytest

from test_optimizer_behavior import FakeOptimizerAPI, optimizer_module

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

    def test_sensors_require_current_snapshot_reading_for_availability(self):
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
        self.assertIn("super().available", method_source)
        self.assertIn("self.native_value is not None", method_source)


@pytest.mark.parametrize("status", ["offline", "disconnected", "unavailable", " OFFLINE "])
@pytest.mark.parametrize("include_details", [True, False])
def test_offline_measurements_keep_identity_without_stale_live_values(
    optimizer_module, status, include_details
):
    record = {
        "mocId": 20814, "dn": "NE=OPT_2", "connectStatus": "connected",
        "dailyEnergy": "0.4", "powerPercent": "50",
        "optInfo": {"outputPower": "200", "inputVoltage": "30",
                    "outputVoltage": "29", "inputCurrent": "6"},
    }
    info = {"dn": "NE=OPT_2", "optName": "Module A", "temperature": "28.5"}
    api = FakeOptimizerAPI(optimizer_module, [record], optimizer_info=[info])
    live = {d.device_id: d for d in api.get_optimizer_devices() if d.dn == "NE=OPT_2"}
    assert live["Optimizer Temperature"].state == 28.5
    record["connectStatus"] = status
    if not include_details:
        api.optimizer_info = []
    offline = {d.device_id: d for d in api.get_optimizer_devices() if d.dn == "NE=OPT_2"}
    for name in (
        "Optimizer Output Power", "Optimizer Input Voltage", "Optimizer Output Voltage",
        "Optimizer Input Current", "Optimizer Power Percent", "Optimizer Temperature",
    ):
        assert offline[name].state is None
        assert offline[name].device_unique_id == live[name].device_unique_id
    assert offline["Optimizer Energy Today"].state == 0.4
    assert offline["Optimizer Connection"].state == status
    assert offline["Optimizer Position"].state == "1.1.2"
    record["connectStatus"] = "connected"
    api.optimizer_info = [info]
    restored = {d.device_id: d for d in api.get_optimizer_devices() if d.dn == "NE=OPT_2"}
    assert restored["Optimizer Temperature"].state == 28.5
    assert restored["Optimizer Temperature"].device_unique_id == live["Optimizer Temperature"].device_unique_id
    assert restored["Optimizer Output Power"].state == pytest.approx(0.2)


@pytest.mark.parametrize("temperature", ["--", "unavailable", "unknown", "null", "", None, "NaN", "inf", True])
def test_invalid_temperature_clears_previous_reading(optimizer_module, temperature):
    info = {"dn": "NE=OPT_2", "temperature": "25.5"}
    api = FakeOptimizerAPI(optimizer_module, [
        {"mocId": 20814, "dn": "NE=OPT_2", "connectStatus": "connected"},
    ], optimizer_info=[info])
    before = next(d for d in api.get_optimizer_devices() if d.device_id == "Optimizer Temperature")
    assert before.state == 25.5
    info["temperature"] = temperature
    after = next(d for d in api.get_optimizer_devices() if d.device_id == "Optimizer Temperature")
    assert after.state is None
    assert after.device_unique_id == before.device_unique_id


def test_valid_zero_temperature_is_not_treated_as_missing(optimizer_module):
    api = FakeOptimizerAPI(optimizer_module, [
        {"mocId": 20814, "dn": "NE=OPT_2", "connectStatus": "connected"},
    ], optimizer_info=[{"dn": "NE=OPT_2", "temperature": "0"}])
    temperature = next(d for d in api.get_optimizer_devices() if d.device_id == "Optimizer Temperature")
    assert temperature.state == 0


if __name__ == "__main__":
    unittest.main()
