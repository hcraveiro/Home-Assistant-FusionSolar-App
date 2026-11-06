"""Optional per-battery configuration reads never affect normal telemetry."""

import ast
import logging
import math
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


BATTERY_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/api/battery.py"
)


def _configuration_reader():
    tree = ast.parse(BATTERY_PATH.read_text(encoding="utf-8"))
    battery = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "FusionSolarBatteryMixin"
    )
    method = next(
        node for node in battery.body
        if isinstance(node, ast.FunctionDef) and node.name == "get_battery_config_devices"
    )
    device_types = SimpleNamespace(
        SENSOR_KW="kw", SENSOR_KWH="kwh", SENSOR_PERCENTAGE="percentage",
        SENSOR_TEXT="text", SENSOR_MINUTES="minutes",
    )
    from test_utils_behavior import utils
    namespace = {
        "extract_numeric": utils.extract_numeric,
        "NUMERIC_DEVICE_UNITS": {"kw": "kW", "kwh": "kWh", "percentage": "%", "minutes": "min"},
        "Device": object,
        "DeviceType": device_types,
        "DATA_REFERER_URL": "/referer",
        "math": math,
        "time": SimpleNamespace(monotonic=lambda: 100.0),
        "_LOGGER": logging.getLogger(__name__),
    }
    module = ast.Module(body=[method], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(BATTERY_PATH), "exec"), namespace)
    return namespace["get_battery_config_devices"]


def _api(response):
    api = SimpleNamespace(
        battery_dn="BAT_A", _battery_entity_dn=None,
        data_host="example.invalid", csrf="csrf-token",
    )
    api.refresh_csrf = Mock()
    api._request_json = Mock(return_value=(None, response))
    api._create_dynamic_device = lambda name, kind, state, icon, dn=None: (
        name, kind, state, dn
    )
    return api


def test_code_zero_exposes_confirmed_configuration_with_one_hour_cache():
    read = _configuration_reader()
    api = _api({"code": 0, "data": [{"configSignalDisplayList": [
        {"id": "10011", "value": "5000"},
        {"id": 230320277, "value": "100"},
        {"id": 230320245, "value": "1"},
        {"id": 230320258, "value": "3.030"},
        {"id": 230320281, "value": "1440"},
        {"id": 230320279, "value": "1"},
        {"id": 230320278, "value": "NaN"},
    ]}]})

    devices = read(api)

    assert devices == [
        ("Battery Maximum Charge Power", "kw", 5.0, None),
        ("Battery End of Charge SOC", "percentage", 100.0, None),
        ("Battery Forced Charge Power", "kw", 3.03, None),
        ("Battery Forced Charge Discharge Period", "minutes", 1440.0, None),
        ("Battery Forced Charge Discharge", "text", "Charge", None),
        ("Battery Charge From AC", "text", "Enabled", None),
    ]
    assert read(api) == devices
    api._request_json.assert_called_once()
    assert api._request_json.call_args.args[0] == "GET"
    assert api._request_json.call_args.kwargs["params"] == {"dn": "BAT_A"}


def test_nonzero_code_is_ignored_and_cached_without_raising():
    read = _configuration_reader()
    api = _api({"code": 1020, "description": "not available"})

    assert read(api) == []
    assert read(api) == []
    api._request_json.assert_called_once()


def test_request_failure_does_not_block_existing_battery_telemetry():
    read = _configuration_reader()
    api = _api({})
    api._request_json.side_effect = RuntimeError("request failed")

    assert read(api) == []
