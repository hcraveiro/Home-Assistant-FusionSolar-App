"""Explicit b17 periodic '--' policy, through real parsers/readers/assembled API."""
from copy import deepcopy
from datetime import datetime
import importlib
from unittest.mock import Mock

import pytest

from test_api_lifecycle_behavior import api, api_module, PREFIX
from test_energy_balance_full_behavior import complete_data


PERIODS = ("today", "week", "month", "year")
CATEGORIES = ("panel_production", "panel_production_consumption", "house_load",
              "grid_consumption", "grid_injection")
BATTERY = ("battery_injection", "battery_consumption")
COUNTERS = [f"{metric} {period}" for metric in (
    "Panel Production", "Panel Production Consumption", "House Load",
    "Grid Consumption", "Grid Injection", "Battery Injection", "Battery Consumption",
) for period in ("Today", "Week", "Month", "Year")] + [
    "Battery Energy Charged Today", "Battery Energy Discharged Today", "Optimizer Energy Today",
]
INVALID = [None, "", " -- ", "-- ", "null", "garbage", True, False,
           "NaN", "inf", float("nan"), float("inf"), "1e999"]


@pytest.fixture
def frozen(api, api_module, monkeypatch):
    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 5, 12)  # Thu: 4 elapsed weekly days, 5 monthly, 11 yearly
    monkeypatch.setattr(importlib.import_module(f"{PREFIX}.api.energy_balance"), "datetime", FrozenDatetime)
    api.refresh_csrf = Mock()
    return api


@pytest.mark.parametrize("counter", COUNTERS)
def test_only_classified_energy_counters_get_literal_zero(api, api_module, counter):
    kind = api_module.DeviceType.SENSOR_KWH
    assert api._create_dynamic_device(counter, kind, "--", "mdi:test").state == 0
    key = counter.lower().replace(" ", "_")
    assert api.get_device_value(counter, kind, {key: "--"}) == 0
    assert api._optional_grid_energy({"v": "--"}, "v") is None


@pytest.mark.parametrize("raw", INVALID)
def test_periodic_factory_and_getter_never_default_other_invalid_values(api, api_module, raw):
    for counter in ("Panel Production Month", "Battery Energy Charged Today", "Optimizer Energy Today"):
        kind = api_module.DeviceType.SENSOR_KWH
        assert api._create_dynamic_device(counter, kind, raw, "mdi:test") is None
        assert api.get_device_value(counter, kind, {counter.lower().replace(" ", "_"): raw}) is None


@pytest.mark.parametrize("counter,kind", [
    ("Panel Production Lifetime", "SENSOR_KWH"), ("Battery Capacity", "SENSOR_KWH"),
    ("Battery Rated Capacity", "SENSOR_KWH"), ("Battery Charged Energy", "SENSOR_KWH"),
    ("Battery Module 1 Total Charge Energy", "SENSOR_KWH"),
    ("Power Sensor Grid Consumption Total", "SENSOR_KWH"),
    ("Unknown Energy Today", "SENSOR_KWH"), ("House Load Today", "SENSOR_KW"),
    ("Self Consumption Ratio Today", "SENSOR_RATIO"),
    ("Standard Coal Saved This Year", "SENSOR_KG"),
])
def test_no_broad_suffix_or_nonenergy_placeholder_exception(api, api_module, counter, kind):
    dtype = getattr(api_module.DeviceType, kind)
    assert api._create_dynamic_device(counter, dtype, "--", "mdi:test") is None
    assert api.get_device_value(counter, dtype, {counter.lower().replace(" ", "_"): "--"}) is None


@pytest.mark.parametrize("period", PERIODS)
@pytest.mark.parametrize("readings,expected", [
    (["--"], 0), (["--", "--"], 0), (["--", 2, "--", -1], 1),
    ([], None), (None, None), (["--", None], None), (["--", "broken"], None),
    (["--", " -- "], None), (["--", True], None), (["--", float("inf")], None),
])
def test_period_aware_sum_and_unchanged_lifetime_default(api, period, readings, expected):
    assert api._energy_sum(readings, period=period) == expected
    if readings in (["--"], ["--", "--"]):
        assert api._energy_sum(readings) is None
        assert api._energy_sum(readings, period="lifetime") is None


@pytest.mark.parametrize("isitepower", [False, True])
def test_all_literal_placeholders_in_supported_periodic_readers(frozen, isitepower):
    api = frozen
    api._is_isitepower_m = isitepower
    data = complete_data()
    for key, value in data["data"].items():
        data["data"][key] = ["--"] * 31 if isinstance(value, list) else "--"
    api.call_energy_balance = Mock(return_value=data)
    api.get_week_data = Mock(return_value=[deepcopy(data) for _ in range(4)])
    output = {}
    api.update_output_with_energy_balance(output)
    for category in CATEGORIES:
        for period in PERIODS:
            assert output[f"{category}_{period}"] == 0, (category, period)
        assert output[f"{category}_lifetime"] is None
    for category in BATTERY:
        for period in ("month", "year") + (() if isitepower else ("today", "week")):
            assert output[f"{category}_{period}"] == 0, (category, period)
        assert output[f"{category}_lifetime"] is None
    assert all(value is None for key, value in output.items() if "ratio" in key)
    assert api._optional_grid_energy({"batteryCapacity": "--"}, "batteryCapacity") is None
    assert api._period_energy_sum(["--"] * 4, "month") is None
    assert api._period_energy_sum(["--"] * 10, "year") is None
    assert api.calculate_week_energy(data, [2, 3, 4, 5], "productPower") == 0


@pytest.mark.parametrize("isitepower", [False, True])
@pytest.mark.parametrize("raw", INVALID)
def test_periodic_readers_reject_every_other_invalid_value(frozen, isitepower, raw):
    api = frozen
    api._is_isitepower_m = isitepower
    data = complete_data()
    for key, value in data["data"].items():
        data["data"][key] = [raw] * 31 if isinstance(value, list) else raw
    api.call_energy_balance = Mock(return_value=data)
    api.get_week_data = Mock(return_value=[deepcopy(data) for _ in range(4)])
    output = {}
    api.update_output_with_energy_balance(output)
    assert all(value is None for value in output.values())


@pytest.mark.parametrize("isitepower", [False, True])
@pytest.mark.parametrize("response", [{}, {"data": {}}, {"success": False, "data": {
    "totalBuyPower": "--", "chargePower": ["--"] * 31,
}}])
def test_absent_or_unsuccessful_response_is_not_periodic_zero(frozen, isitepower, response):
    api = frozen
    api._is_isitepower_m = isitepower
    api.call_energy_balance = Mock(return_value=response)
    api.get_week_data = Mock(return_value=[response] * 4)
    output = {}
    api.update_output_with_energy_balance(output)
    assert all(value is None for value in output.values())


@pytest.mark.parametrize("isitepower", [False, True])
def test_http_failure_or_short_elapsed_data_cannot_turn_into_zero(frozen, api_module, isitepower):
    api = frozen
    api._is_isitepower_m = isitepower
    api.call_energy_balance = Mock(side_effect=api_module.APIConnectionError("synthetic"))
    api.get_week_data = Mock(return_value=[None] * 4)
    output = {}
    api.update_output_with_energy_balance(output)
    assert all(value is None for value in output.values())
    api.call_energy_balance = Mock(return_value={"data": {"productPower": ["--"],
        "chargePower": ["--"], "dischargePower": ["--"]}})
    api.get_week_data = Mock(return_value=[{"data": {"totalBuyPower": "--"}}] * 3)
    api.update_output_with_energy_balance(output)
    assert output["panel_production_today"] is None
    assert output["panel_production_week"] is None
    assert output["battery_injection_month"] is None
    assert output["battery_injection_year"] is None
    assert output["grid_consumption_week"] is None
    assert output["grid_consumption_today"] is None  # Short daily list cannot alias yesterday as today.


@pytest.mark.parametrize("raw,expected", [("--", 0), (" -- ", None), (None, None), (True, None), ("broken", None), (0, 0), (-1, -1)])
def test_battery_today_real_assembly(api, raw, expected):
    api.battery_dn = "battery"
    api.get_battery_type = Mock(return_value={"module1DevType": "LUNA"})
    api.get_battery_realtime_data = Mock(return_value={10001: raw, 10002: raw})
    api.get_battery_config_devices = Mock(return_value=[])
    api.get_battery_module_data = Mock(return_value=[])
    devices = api.get_battery_devices()
    for name in ("Battery Energy Charged Today", "Battery Energy Discharged Today"):
        found = [d for d in devices if d.device_id == name]
        assert ([d.state for d in found] == [expected]) if expected is not None else not found


@pytest.mark.parametrize("raw,expected", [("--", 0), (" -- ", None), (None, None), (True, None), ("broken", None), (0, 0), (-1, -1)])
def test_optimizer_today_real_reader(api, raw, expected):
    api.station = "synthetic-station"
    api._optimizers = {"opt": {"parent_dn": "inv"}}
    records = [{"dn": "opt", "mocId": 20814, "dailyEnergy": raw,
                "optInfo": {"inputVoltage": 40}}]
    api._optimizer_request = Mock(side_effect=[records, []])
    devices = api.get_optimizer_devices()
    found = [d for d in devices if d.device_id == "Optimizer Energy Today"]
    assert ([d.state for d in found] == [expected]) if expected is not None else not found
    assert any(d.device_id == "Optimizer Input Voltage" and d.state == 40 for d in devices)
