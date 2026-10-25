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


def make_api_for_fetch(module, dn_attribute, dn):
    api = (module.FusionSolarBatteryMixin() if dn_attribute == "battery_dn" else
           module.FusionSolarPowerSensorMixin() if dn_attribute == "power_sensor_dn" else
           module.FusionSolarInverterMixin())
    setattr(api, dn_attribute, dn)
    api.data_host = "eu5.fusionsolar.huawei.com"
    api.csrf = "dummy"
    api.refresh_csrf = Mock()
    api._request_json = Mock()
    return api


@pytest.mark.parametrize(("module_index", "attribute", "method"), [
    (0, "power_sensor_dn", "get_power_sensor_realtime_data"),
    (1, "battery_dn", "get_battery_realtime_data"),
    (2, "inverter_dn", "get_inverter_config_info"),
    (1, "battery_dn", "get_battery_type"),
])
def test_device_endpoints_skip_missing_dn(modules, module_index, attribute, method):
    api = make_api_for_fetch(modules[module_index], attribute, None)
    assert getattr(api, method)() == {}
    api.refresh_csrf.assert_not_called()


@pytest.mark.parametrize("payload,expected", [
    ({"success": False, "data": []}, {}),
    ({"success": True, "data": []}, {}),
    ({"success": True, "data": [
        {"signals": [{"id": 10001, "value": "online"}, {"id": 10004, "value": "2000 W"}]},
        {"signals": [{"id": 9999999, "value": "ignore"}]},
        {"invalid": 1},
    ]}, {10001: "online", 10004: 2.0}),
])
def test_meter_realtime_parses_known_signals(modules, payload, expected):
    api = make_api_for_fetch(modules[0], "power_sensor_dn", "meter-1")
    api._request_json.return_value = (None, payload)
    assert api.get_power_sensor_realtime_data() == expected


def test_battery_type_model_discovery(modules):
    api = make_api_for_fetch(modules[1], "battery_dn", "battery-1")
    api.battery_model = None
    api._request_json.return_value = (None, {"data": {"module1DevType": "ESS", "module2DevType": "LUNA2000"}})
    api.get_battery_type()
    assert api.battery_model == "LUNA2000"


def test_battery_realtime_and_optional_kpi(modules):
    api = make_api_for_fetch(modules[1], "battery_dn", "battery-1")
    api._request_json.side_effect = [
        (None, {"success": True, "data": [{"signals": [
            {"id": 10001, "value": "42"}, {"id": None, "value": "ignore"}
        ]}]}),
        (None, {"data": {"signals": {"10007": {"value": "95"}}}}),
    ]
    result = api.get_battery_realtime_data()
    assert result[10001] == "42"
    assert result[10007] == "95"


def test_battery_optional_kpi_failure_does_not_discard_data(modules):
    api = make_api_for_fetch(modules[1], "battery_dn", "battery-1")
    api._request_json.side_effect = [
        (None, {"success": True, "data": [{"signals": [{"id": 10001, "value": "50"}]}]}),
        RuntimeError("kpi unavailable"),
    ]
    assert api.get_battery_realtime_data() == {10001: "50"}


def test_inverter_config_uses_real_metadata_parser(modules):
    api = make_api_for_fetch(modules[2], "inverter_dn", "inverter-1")
    api.inverter_name = None
    api.inverter_model = None
    api.inverter_software_version = None
    api.inverter_serial_number = None
    api._request_json.return_value = (None, {"data": {
        "signals": [
            {"signal": 33595393, "value": "Inverter"},
            {"signal": 50009, "value": "SUN2000"},
            {"signal": 50010, "realValue": "1.2"},
            {"signal": 50012, "value": "redacted"},
        ]
    }})
    api.get_inverter_config_info()
    assert api.inverter_model == "SUN2000"
    assert api.inverter_name == "Inverter"
    assert api.inverter_serial_number == "redacted"


def test_meter_config_metadata_parser(modules):
    api = make_api_for_fetch(modules[0], "power_sensor_dn", "meter-1")
    for attribute in ("power_sensor_name", "power_sensor_model", "power_sensor_software_version",
                      "power_sensor_serial_number", "power_sensor_usage"):
        setattr(api, attribute, None)
    api._request_json.return_value = (None, {"data": {
        "33595393": "Meter", "50009": "DTSU666", "50010": "1.2",
        "50012": "redacted", "20004": "1"
    }})
    api.get_power_sensor_config_info()
    assert api.power_sensor_name == "Meter"
    assert api.power_sensor_usage == "Export+import meter"


def test_inverter_realtime_pv_kpi_and_power(modules):
    api = make_api_for_fetch(modules[2], "inverter_dn", "inverter-1")
    api._request_json.side_effect = [
        (None, {"success": True, "data": [{"signals": [{"id": 10001, "value": "running"}]}]}),
        (None, {"success": True, "data": {"signals": {
            "11001": {"value": "400 V", "latestTime": 100},
            "11002": {"value": "5 A", "latestTime": 100},
            "11004": {"value": "0", "latestTime": 50},
            "11005": {"value": "0", "latestTime": 50},
            "11007": {"value": "0", "latestTime": 50},
            "11008": {"value": "0", "latestTime": 50},
        }}}),
    ]
    result = api.get_inverter_realtime_data()
    assert 11001 in result
    assert 11002 in result


def test_inverter_realtime_kpi_failure_keeps_initial_values(modules):
    api = make_api_for_fetch(modules[2], "inverter_dn", "inverter-1")
    api._request_json.side_effect = [
        (None, {"success": True, "data": [{"signals": [{"id": 11001, "value": "400 V"}]}]}),
        RuntimeError("KPI offline"),
    ]
    assert isinstance(api.get_inverter_realtime_data(), dict)


def test_meter_type_name_and_entities(modules):
    api = make_api_for_fetch(modules[0], "power_sensor_dn", "meter-1")
    api.power_sensor_model = None
    api._request_json.return_value = (None, {"data": "Smart meter"})
    assert api.get_power_sensor_type_name() == "Smart meter"
    api.get_power_sensor_config_info = Mock(side_effect=RuntimeError("config offline"))
    api.get_power_sensor_type_name = Mock(side_effect=RuntimeError("type offline"))
    api.get_power_sensor_realtime_data = Mock(return_value={10004: "-1 kW", 10001: "online"})
    api.power_sensor_usage = "Consumption meter"
    api._create_dynamic_device = lambda identifier, kind, value, icon: (
        type("FakeDevice", (), {"device_id": identifier})() if value not in (None, "", "--") else None
    )
    names = [device.device_id for device in api.get_power_sensor_devices()]
    assert "Power Sensor Direction" in names
    assert "Power Sensor Usage" in names


def test_battery_device_assembly_with_partial_module_failure(modules):
    api = make_api_for_fetch(modules[1], "battery_dn", "battery-1")
    api.get_battery_type = Mock(return_value={"data": {"module1DevType": "LUNA", "module2DevType": "LUNA"}})
    api.get_battery_realtime_data = Mock(return_value={10003: "running", 10007: "95"})
    api.get_battery_module_data = Mock(side_effect=lambda n: [
        {"name": "[Module 1] [DC/DC] Bus current", "realValue": "2 A"}] if n == 1 else [])
    api.battery_serial_number = None
    api.battery_software_version = None
    api.battery_model = "LUNA"
    api._create_dynamic_device = lambda identifier, kind, value, icon: (
        type("FakeDevice", (), {"device_id": identifier})() if value is not None else None
    )
    devices = api.get_battery_devices()
    names = [device.device_id for device in devices]
    assert "Battery SOH" in names
    assert "Battery Operating Status" in names
    assert "Battery Module 1 Bus Current" in names


def test_battery_device_assembly_handles_fetch_errors(modules):
    api = make_api_for_fetch(modules[1], "battery_dn", "battery-1")
    api.get_battery_type = Mock(side_effect=RuntimeError("offline"))
    api.get_battery_realtime_data = Mock(side_effect=RuntimeError("offline"))
    api.get_battery_module_data = Mock(side_effect=RuntimeError("offline"))
    api._create_dynamic_device = Mock(return_value=None)
    assert api.get_battery_devices() == []
