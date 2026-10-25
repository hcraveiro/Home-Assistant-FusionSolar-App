"""Behavioral regression tests for inverter, battery, and meter discovery."""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_device_behavior"


@pytest.fixture(scope="module")
def modules():
    for name, directory in ((PREFIX, ROOT), (f"{PREFIX}.api", ROOT / "api")):
        module = types.ModuleType(name)
        module.__path__ = [str(directory)]
        sys.modules[name] = module
    for name, path in (
        ("const", ROOT / "const.py"),
        ("utils", ROOT / "utils.py"),
        ("api.exceptions", ROOT / "api/exceptions.py"),
        ("api.models", ROOT / "api/models.py"),
        ("api.signal_maps", ROOT / "api/signal_maps.py"),
        ("api.power_sensor", ROOT / "api/power_sensor.py"),
        ("api.battery", ROOT / "api/battery.py"),
        ("api.inverter", ROOT / "api/inverter.py"),
    ):
        fullname = f"{PREFIX}.{name}"
        spec = importlib.util.spec_from_file_location(fullname, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = module
        spec.loader.exec_module(module)
    yield [sys.modules[f"{PREFIX}.api.{name}"] for name in ("power_sensor", "battery", "inverter")]
    for name in list(sys.modules):
        if name == PREFIX or name.startswith(PREFIX + "."):
            del sys.modules[name]


@pytest.mark.parametrize(("raw", "expected"), [
    ("1", "Export+import meter"), ("2", "Production meter"),
    ("3", "Consumption meter"), ("unknown", "unknown"),
    (" -- ", "--"), ("--", None), (None, None),
])
def test_meter_usage(modules, raw, expected):
    api = modules[0].FusionSolarPowerSensorMixin()
    assert api._normalize_power_sensor_usage(raw) == expected


@pytest.mark.parametrize(("power", "expected"), [
    ("2500 W", "exporting"), ("-500 W", "importing"),
    ("0", "idle"), ("--", "idle"),
])
def test_meter_direction(modules, power, expected):
    api = modules[0].FusionSolarPowerSensorMixin()
    assert api._get_power_sensor_direction(power) == expected


def test_meter_dn_discovery_preserves_existing(modules):
    api = modules[0].FusionSolarPowerSensorMixin()
    api.power_sensor_dn = None
    api._discover_power_sensor_dn_from_flow_nodes([
        {"name": "unknown", "devIds": ["ignored"]},
        {"name": "neteco.pvms.devTypeLangKey.powerMeter", "devIds": ["meter-1"]},
    ])
    assert api.power_sensor_dn == "meter-1"
    api._discover_power_sensor_dn_from_flow_nodes([{"name": "smartmeter", "devDn": "meter-2"}])
    assert api.power_sensor_dn == "meter-1"


@pytest.mark.parametrize(("signal", "value", "expected"), [
    (999999, "1500 W", "1500 W"),
    (10004, "--", None),
    (10004, None, None),
])
def test_meter_signal_normalization(modules, signal, value, expected):
    api = modules[0].FusionSolarPowerSensorMixin()
    assert api._normalize_power_sensor_signal_value(signal, value) == expected


@pytest.mark.parametrize(("battery_types", "expected"), [
    ({"module1DevType": "LUNA", "module2DevType": "LUNA"}, [1, 2]),
    ({"module1DevType": "ESS", "module3DevType": "LUNA"}, [3]),
    ({"module1DevType": "--", "module2DevType": "LUNA"}, [2]),
])
def test_battery_module_ids_from_metadata(modules, battery_types, expected):
    api = modules[1].FusionSolarBatteryMixin()
    api.get_battery_module_data = Mock(side_effect=AssertionError("Unexpected probe"))
    assert api._get_available_battery_module_ids(battery_types) == expected


def test_battery_module_probe_and_fallback(modules):
    api = modules[1].FusionSolarBatteryMixin()
    api.get_battery_module_data = Mock(side_effect=lambda n: [
        {"name": "[Module 2] SN", "realValue": "test"}] if n == 2 else [])
    assert api._get_available_battery_module_ids({}) == [2]
    api.get_battery_module_data = Mock(side_effect=RuntimeError("offline"))
    assert api._get_available_battery_module_ids({}) == [1]


def test_battery_name_map_fallback_and_metadata(modules):
    api = modules[1].FusionSolarBatteryMixin()
    result = api._extract_battery_module_name_map([
        {"name": "module-value", "realValue": None, "value": "22"},
        {"name": "other", "realValue": "3"},
        {"value": "ignored"},
    ])
    assert result == {"module-value": "22", "other": "3"}
    api.battery_serial_number = None
    api.battery_software_version = None
    api.battery_model = None
    api._update_battery_metadata_from_module_name_map({
        "[Module 1] [DC/DC] SN": "redacted",
        "[Module 1] [DC/DC] Software version": "1.2",
    })
    assert api.battery_serial_number == "redacted"
    assert api.battery_software_version == "1.2"


@pytest.mark.parametrize(("nodes", "expected"), [
    ([{"name": "neteco.pvms.devTypeLangKey.inverter", "devIds": ["inverter-1"]}], "inverter-1"),
    ([{"name": "neteco.pvms.devTypeLangKey.inverter", "devDn": "inverter-2"}], "inverter-2"),
    ([{"name": "neteco.pvms.devTypeLangKey.inverter", "devIds": []}], None),
    ([{"name": "other", "devDn": "ignored"}], None),
])
def test_inverter_dn_discovery(modules, nodes, expected):
    api = modules[2].FusionSolarInverterMixin()
    api.inverter_dn = None
    api._discover_inverter_dn_from_flow_nodes(nodes)
    assert api.inverter_dn == expected


def test_inverter_pv_placeholders_trimmed(modules):
    api = modules[2].FusionSolarInverterMixin()
    pairs = {
        11001: {"value": "460 V", "latestTime": 100},
        11002: {"value": "4 A", "latestTime": 100},
        11004: {"value": "0", "latestTime": 50},
        11005: {"value": "0", "latestTime": 50},
        11007: {"value": "0", "latestTime": 50},
        11008: {"value": "0", "latestTime": 50},
    }
    assert api._get_visible_pv_indexes_from_signal_meta(pairs, 3) == {1}
    assert api._get_visible_pv_indexes_from_signal_meta({}, 3) == set()


def test_inverter_known_pv_kept_after_nightfall(modules):
    api = modules[2].FusionSolarInverterMixin()
    api._known_visible_pv_indexes = {1}
    pairs = {11001: {"value": 0, "latestTime": 50}, 11002: {"value": 0, "latestTime": 50}}
    assert api._get_visible_pv_indexes_from_signal_meta(pairs, 1) == {1}
