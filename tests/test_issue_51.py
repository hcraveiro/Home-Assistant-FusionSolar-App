"""Regression tests for issue #51 without a Home Assistant installation."""

import ast
import asyncio
import logging
import types
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "fusion_solar_app"


def load_function(path: Path, name: str, namespace: dict):
    """Compile a function directly from its production source module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(functions) != 1:
        raise AssertionError(f"Expected one definition of {name}, got {len(functions)}")
    function = functions[0]
    function.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(module, str(path), "exec"), namespace)
    return namespace[name]


def make_pv_signals(active_inputs: int, total_inputs: int = 20, timestamp: int = 1):
    """Build metadata with live PV inputs followed by zero-value placeholders."""
    signals = {}
    for index in range(1, total_inputs + 1):
        voltage_id = 11001 + 3 * (index - 1)
        voltage = 340 if index <= active_inputs else 0
        current = 5 if index <= active_inputs else 0
        signals[voltage_id] = {"value": voltage, "latestTime": timestamp}
        signals[voltage_id + 1] = {"value": current, "latestTime": timestamp}
    return signals


class PVDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def extract_numeric(value):
            try:
                return float(str(value).split()[0])
            except (ValueError, TypeError, IndexError, AttributeError):
                return 0.0

        cls.detect = staticmethod(load_function(
            COMPONENT / "api" / "inverter.py",
            "_get_visible_pv_indexes_from_signal_meta",
            {"Any": Any, "_LOGGER": logging.getLogger(__name__), "extract_numeric": extract_numeric},
        ))

    def setUp(self):
        self.inverter = types.SimpleNamespace()

    def check(self, signals):
        return self.detect(self.inverter, signals)

    def test_daylight_excludes_placeholder_inputs(self):
        self.assertEqual(self.check(make_pv_signals(2)), {1, 2})

    def test_night_start_does_not_create_fictitious_inputs(self):
        self.assertEqual(self.check(make_pv_signals(0)), set())

    def test_daylight_after_night_start_discovers_real_inputs(self):
        self.check(make_pv_signals(0))
        self.assertEqual(self.check(make_pv_signals(2)), {1, 2})

    def test_night_after_daylight_preserves_known_inputs(self):
        self.check(make_pv_signals(2))
        self.assertEqual(self.check(make_pv_signals(0)), {1, 2})

    def test_one_string_inverter(self):
        self.assertEqual(self.check(make_pv_signals(1)), {1})
        self.assertEqual(self.check(make_pv_signals(0)), {1})


class DynamicSensorTests(unittest.TestCase):
    def setUp(self):
        self.devices = []
        self.listeners = []
        self.added_batches = []
        self.unload_callbacks = []

        class DeviceType:
            SENSOR_KW = "power"

        self.device_type = DeviceType
        coordinator = types.SimpleNamespace(
            data=types.SimpleNamespace(devices=self.devices, controller_name="test_controller"),
            api=types.SimpleNamespace(station="test_station", station_name="Test Plant", controller_name="test_controller"),
            async_add_listener=self.register_listener,
        )
        hass = types.SimpleNamespace(
            data={"fusion_solar_app": {"entry": types.SimpleNamespace(coordinator=coordinator)}}
        )
        config_entry = types.SimpleNamespace(
            entry_id="entry",
            async_on_unload=self.unload_callbacks.append,
        )
        namespace = {
            "HomeAssistant": object,
            "ConfigEntry": object,
            "AddEntitiesCallback": object,
            "FusionSolarCoordinator": object,
            "DOMAIN": "fusion_solar_app",
            "SUPPORTED_SENSOR_DEVICE_TYPES": {DeviceType.SENSOR_KW},
            "SensorEntity": object,
            "DeviceType": DeviceType,
            "FusionSolarSensor": lambda coordinator, device: device,
            "FusionSolarForecastedTodaySensor": lambda coordinator: "forecast",
            "FusionSolarRemainingTodaySensor": lambda coordinator: "remaining",
            "callback": lambda function: function,
            "dr": types.SimpleNamespace(async_get=lambda hass: types.SimpleNamespace(
                async_get_or_create=lambda **kwargs: types.SimpleNamespace(id="test_parent_id")
            )),
        }
        self.setup = load_function(COMPONENT / "sensor.py", "async_setup_entry", namespace)
        asyncio.run(self.setup(hass, config_entry, self.added_batches.append))

    def register_listener(self, listener):
        self.listeners.append(listener)
        return lambda: self.listeners.remove(listener)

    def notify(self):
        for listener in list(self.listeners):
            listener()

    def test_late_discovery_adds_sensor_only_once(self):
        self.assertEqual(len(self.listeners), 1)
        self.assertEqual(self.added_batches, [["forecast", "remaining"]])
        self.devices.append(types.SimpleNamespace(device_type="power", device_id="Inverter PV1 Voltage", device_unique_id="plant_inv_1_pv1_voltage"))
        self.notify()
        self.notify()
        self.assertEqual(len(self.added_batches), 2)
        self.assertEqual(len(self.added_batches[1]), 1)
        self.assertEqual(self.added_batches[1][0].device_id, "Inverter PV1 Voltage")

    def test_existing_sensor_is_not_created_twice(self):
        self.devices.extend([
            types.SimpleNamespace(device_type="power", device_id="Inverter PV1 Power", device_unique_id="plant_inv_1_pv1_power"),
            types.SimpleNamespace(device_type="power", device_id="Inverter PV2 Power", device_unique_id="plant_inv_1_pv2_power"),
        ])
        self.notify()
        self.notify()
        self.assertEqual(len(self.added_batches), 2)
        self.assertEqual(len(self.added_batches[1]), 2)
        self.assertEqual(len(self.unload_callbacks), 1)
        self.unload_callbacks[0]()
        self.assertEqual(self.listeners, [])


if __name__ == "__main__":
    unittest.main()
