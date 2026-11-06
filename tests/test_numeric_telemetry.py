"""Synthetic malformed telemetry through the real parser, readers and assembled API.

No Huawei requests, HA instance mutations or replacement production-method ASTs.
"""
from unittest.mock import Mock

import pytest

from test_api_lifecycle_behavior import api, api_module
from test_utils_behavior import utils


INVALID = [None, "", " \t ", "--", " -- ", "null", "None", "garbage",
           "12 garbage", True, False, "True", "NaN", "inf", "-Infinity",
           float("nan"), float("inf"), -float("inf"), "1e999", 10**400,
           [], {}, object()]
KINDS = {
    "SENSOR_KW": ("kW", "600W", 0.6),
    "SENSOR_KWH": ("kWh", "600 Wh", 0.6),
    "SENSOR_PERCENTAGE": ("%", "76.8%", 77),
    "SENSOR_RATIO": ("%", "98.125 %", 98.125),
    "SENSOR_VOLTAGE": ("V", "230.125V", 230.125),
    "SENSOR_CURRENT": ("A", "-2.125 A", -2.125),
    "SENSOR_FREQUENCY": ("Hz", "50 Hz", 50),
    "SENSOR_TEMPERATURE": ("°C", "-5.125 °C", -5.125),
    "SENSOR_RESISTANCE": ("MΩ", "2.125 MΩ", 2.125),
    "SENSOR_POWER_FACTOR": ("", "-0.985", -0.985),
    "SENSOR_VAR": ("var", "-20.125 var", -20.125),
    "SENSOR_KG": ("kg", "12.5 kg", 12.5),
    "SENSOR_COUNT": ("", "2.6", 2.6),
    "SENSOR_MINUTES": ("min", "1440 min", 1440),
}


@pytest.mark.parametrize("raw", INVALID)
def test_strict_parser_invalid(raw):
    assert utils.extract_numeric(raw) is None


@pytest.mark.parametrize("raw,unit,expected", [
    (0, "", 0), (-2.123456, "", -2.123456),
    ("600 W", "kW", 0.6), ("600W", "kW", 0.6),
    ("-600 W", "kW", -0.6), ("0.6 kW", "kW", 0.6),
    ("0.6kW", "kW", 0.6), ("600 Wh", "kWh", 0.6),
    ("600Wh", "kWh", 0.6), ("0.6kWh", "kWh", 0.6),
    ("0 %", "%", 0), ("-5 °C", "°C", -5), ("24.5 C", "°C", 24.5),
    ("230V", "V", 230), ("2.5 A", "A", 2.5),
    ("2 MΩ", "MΩ", 2), ("3", "", 3), ("1.25e2", "V", 125),
])
def test_parser_units_and_precision(raw, unit, expected):
    assert utils.extract_numeric(raw, unit) == expected


@pytest.mark.parametrize("raw,unit", [
    ("600 W", "%"), ("50%", "kW"), ("2 kWh", "kW"),
    ("2 kW", "kWh"), ("2 A", "V"), ("2 V", "A"),
    ("2 V", ""), ("2 widgets", ""), ("2 kg more", "kg"),
    ("2 Ω", "MΩ"), ("2 °F", "°C"), ("2 kHz", "Hz"),
])
def test_parser_rejects_wrong_dimension(raw, unit):
    assert utils.extract_numeric(raw, unit) is None


def test_meter_bare_unit_is_only_a_default():
    assert utils.extract_numeric(600, "kW", default_unit="W") == 0.6
    assert utils.extract_numeric("600 W", "kW", default_unit="W") == 0.6
    assert utils.extract_numeric("0.6 kW", "kW", default_unit="W") == 0.6


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("raw", INVALID)
def test_assembled_factory_and_getter_reject_invalid(api, api_module, kind, raw):
    dtype = getattr(api_module.DeviceType, kind)
    assert api._create_dynamic_device("Test", dtype, raw, "mdi:test") is None
    assert api.get_device_value("Test", dtype, {"test": raw}) is None


@pytest.mark.parametrize("kind", KINDS)
def test_factory_valid_units_rounding_and_mismatch(api, api_module, kind):
    unit, raw, expected = KINDS[kind]
    dtype = getattr(api_module.DeviceType, kind)
    device = api._create_dynamic_device("Test", dtype, raw, "mdi:test")
    assert device.state == expected
    wrong = "2 V" if unit != "V" else "2 A"
    assert api._create_dynamic_device("Test", dtype, wrong, "mdi:test") is None
    assert api.get_device_value("Test", dtype, {"test": wrong}) is None
    for raw, expected in [(0, 0), ("0", 0), (-2, -2)]:
        assert api._create_dynamic_device("Test", dtype, raw, "mdi:test").state == expected
        assert api.get_device_value("Test", dtype, {"test": raw}) == expected


def test_established_distinct_percentage_and_count_rounding(api, api_module):
    percent = api_module.DeviceType.SENSOR_PERCENTAGE
    count = api_module.DeviceType.SENSOR_COUNT
    assert api._create_dynamic_device("Test", percent, "76.8%", "mdi:test").state == 77
    assert api.get_device_value("Test", percent, {"test": "76.8%"}) == 76
    assert api.get_device_value("Test", count, {"test": "2.6"}) == 3


@pytest.mark.parametrize("raw", INVALID + ["2 %", "2 kWh"])
def test_flow_invalid_is_not_power_or_soc(api, raw):
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.string", "description": {"value": raw}},
        {"name": "neteco.pvms.KPI.kpiView.electricalLoad", "description": {"value": "600W"}},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "description": {"value": "1 kW"},
         "deviceTips": {"SOC": raw, "BATTERY_POWER": raw}},
    ], output)
    assert output["panel_production_power"] is None
    assert output["house_load_power"] == 0.6
    assert output["battery_injection_power"] is None
    if raw != "2 %":
        assert output["battery_percentage"] is None


def test_flow_power_and_soc_dimensions_and_direction(api):
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.string", "description": {"value": "600 W"}},
        {"name": "neteco.pvms.KPI.kpiView.electricalLoad", "description": {"value": "0kW"}},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "description": {"value": "0.2 kW"},
         "deviceTips": {"SOC": "70.8 %", "BATTERY_POWER": "-200W"}},
    ], output)
    api._parse_installation_flow_links([
        {"description": {"label": "neteco.pvms.energy.flow.buy.power", "value": "800 W"}},
    ], output)
    assert output["panel_production_power"] == 0.6
    assert output["battery_percentage"] == 70.8
    assert output["grid_injection_power"] == 0.8
    assert output["grid_consumption_power"] == 0
    output = api._build_base_output()
    api._parse_installation_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "description": {"value": "1kW"},
         "deviceTips": {"SOC": "70 W", "BATTERY_POWER": "1kW"}},
    ], output)
    assert output["battery_percentage"] is None
    assert output["battery_injection_power"] == 1


@pytest.mark.parametrize("raw", INVALID + ["2 %", "2 kWh"])
def test_meter_malformed_is_not_idle_and_other_readings_survive(api, api_module, raw):
    api.power_sensor_dn = "meter"
    api.get_power_sensor_config_info = Mock(return_value={})
    api.get_power_sensor_type_name = Mock(return_value="Synthetic meter")
    normalized = api._normalize_power_sensor_signal_value(10004, raw)
    assert normalized is None
    assert api._get_power_sensor_direction(raw) is None
    api.get_power_sensor_realtime_data = Mock(return_value={10004: normalized, 10002: "230 V"})
    devices = api.get_power_sensor_devices([])
    assert not any(d.device_id in ("Power Sensor Direction", "Power Sensor Active Power") for d in devices)
    assert any(d.state == 230 for d in devices)


@pytest.mark.parametrize("signal", [10004, 10019, 10020, 10021])
@pytest.mark.parametrize("raw", [600, "600", "600 W", "600W", "0.6 kW", "0.6kW"])
def test_meter_watt_default_no_double_conversion(api, signal, raw):
    normalized = api._normalize_power_sensor_signal_value(signal, raw)
    assert normalized == 0.6
    assert api._get_power_sensor_direction(normalized) == "exporting"


def pv_read(api, api_module, voltage, current, *, measured_power=None):
    api.inverters = {"inv": api_module.InverterInfo(dn="inv")}
    api.data_host = "example.invalid"
    api.csrf = "synthetic"
    api.refresh_csrf = Mock()
    api._known_visible_pv_indexes = {1, 2}
    signals = {"11001": {"value": "400 V"}, "11002": {"value": "5 A"},
               "11004": {"value": voltage}, "11005": {"value": current}}
    measured = [{"id": 11006, "value": measured_power}] if measured_power is not None else []
    api._request_json = Mock(side_effect=[
        (Mock(), {"success": True, "data": [{"signals": measured}]}),
        (Mock(), {"success": True, "data": {"signals": signals}}),
    ])
    return api.get_inverter_realtime_data("inv")


@pytest.mark.parametrize("raw", INVALID + ["2 A"])
def test_derived_pv_requires_both_inputs_and_no_partial_total(api, api_module, raw):
    result = pv_read(api, api_module, raw, "5 A")
    assert result[11003] == 2
    assert 11006 not in result
    assert 30017 not in result
    result = pv_read(api, api_module, "400 V", raw if raw != "2 A" else "2 V", measured_power="3.25 kW")
    assert result[11006] == "3.25 kW"
    assert 30017 not in result


@pytest.mark.parametrize("voltage,current", [("1e308 V", "1e308 A"), ("1e308 V", "2 A")])
def test_derived_pv_nonfinite_arithmetic_does_not_replace_measurement(api, api_module, voltage, current):
    result = pv_read(api, api_module, voltage, current, measured_power="3.25 kW")
    assert result[11006] == "3.25 kW"
    assert 30017 not in result


def test_derived_pv_real_zero_negatives_and_total(api, api_module):
    assert pv_read(api, api_module, "0 V", "5 A")[30017] == 2
    assert pv_read(api, api_module, "400 V", "-5 A")[30017] == 0


@pytest.mark.parametrize("raw", INVALID)
def test_invalid_pv_is_not_zero_tail(api, raw):
    signals = {11001: {"value": "400 V"}, 11002: {"value": "5 A"},
               11004: {"value": raw}, 11005: {"value": 0},
               11007: {"value": 0}, 11008: {"value": 0}}
    assert api._get_visible_pv_indexes_from_signal_meta(signals, 3) == {1, 2, 3}


@pytest.mark.parametrize("raw", INVALID + ["2 kW", 0, -1])
def test_battery_soh_policy_and_pack_topology_fallback(api, raw):
    api.battery_dn = "battery"
    api.get_battery_type = Mock(return_value={"module1DevType": "LUNA"})
    api.get_battery_realtime_data = Mock(return_value={10007: raw, 10005: "400V"})
    api.get_battery_config_devices = Mock(return_value=[])
    api.get_battery_module_data = Mock(return_value=[
        {"name": "[Module 1] Battery pack quantity", "value": raw},
        {"name": "[Module 1] [Battery pack 1] Operating status", "value": "Running"},
        {"name": "[Module 1] [Battery pack 1] Voltage", "value": "48 V"},
    ])
    devices = api.get_battery_devices()
    assert not any(d.device_id == "Battery SOH" for d in devices)
    assert any(d.device_id == "Battery Bus Voltage" and d.state == 400 for d in devices)
    assert any(d.device_id.endswith("Pack 1 Voltage") and d.state == 48 for d in devices)


@pytest.mark.parametrize("raw", INVALID + ["2 kW"])
def test_social_metrics_are_independently_optional(api, raw):
    api.call_social_contribution = Mock(return_value={"data": {
        "standardCoalSavings": raw, "co2Reduction": "12.5kg",
        "equivalentTreePlanting": raw, "equivalentTreePlantingByYear": "4.6",
    }})
    output = {}
    api.update_output_with_social_contribution(output)
    assert output == {"standard_coal_saved": None, "standard_coal_saved_this_year": None,
                      "co2_avoided": 12.5, "co2_avoided_this_year": None,
                      "equivalent_trees_planted": None, "equivalent_trees_planted_this_year": 5}


@pytest.mark.parametrize("raw", INVALID)
def test_battery_config_rejects_before_numeric_conversion(api, raw):
    api.battery_dn = "battery"
    api.refresh_csrf = Mock()
    api._request_json = Mock(return_value=(None, {"code": 0, "data": [{
        "configSignalDisplayList": [{"id": 230320258, "value": raw},
                                    {"id": 230320281, "value": "1440"}],
    }]}))
    devices = api.get_battery_config_devices()
    assert not any(d.device_id == "Battery Forced Charge Power" for d in devices)
    assert any(d.device_id == "Battery Forced Charge Discharge Period" for d in devices)


@pytest.mark.parametrize("raw", ["600 W", "600W", "0.6 kW", "0.6kW", 600])
def test_battery_config_watt_default_and_explicit_units(api, raw):
    api.battery_dn = "battery"
    api.refresh_csrf = Mock()
    api._request_json = Mock(return_value=(None, {"code": 0, "data": [{
        "configSignalDisplayList": [{"id": 10011, "value": raw}],
    }]}))
    devices = api.get_battery_config_devices()
    assert next(d.state for d in devices if d.device_id == "Battery Maximum Charge Power") == 0.6
