"""Exercise optional battery configuration reads through the real transport."""

import importlib.util
import json
import logging
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_battery_config_transport_regression"


@pytest.fixture(scope="module")
def battery_api_module():
    package = types.ModuleType(PREFIX)
    package.__path__ = [str(ROOT)]
    sys.modules[PREFIX] = package
    for short in ("const", "utils"):
        name = f"{PREFIX}.{short}"
        spec = importlib.util.spec_from_file_location(name, ROOT / f"{short}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    name = f"{PREFIX}.api"
    path = ROOT / "api/__init__.py"
    spec = importlib.util.spec_from_file_location(
        name, path, submodule_search_locations=[str(path.parent)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    yield module
    for name in list(sys.modules):
        if name == PREFIX or name.startswith(PREFIX + "."):
            sys.modules.pop(name, None)


@pytest.fixture
def api(battery_api_module):
    instance = battery_api_module.FusionSolarAPI("test", "test", "eu5", None)
    instance.connected = True
    instance.station = "PLANT"
    instance.battery_dn = "BAT_A"
    instance.data_host = "example.invalid"
    instance.csrf = "test-csrf"
    instance.refresh_csrf = Mock()
    yield instance
    instance.logout()


def response(status, payload):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = json.dumps(payload).encode()
    return result


@pytest.mark.parametrize("status", [403, 404, 418, 500])
def test_optional_http_rejections_leave_valid_session_untouched(api, status, caplog):
    api.session.request = Mock(return_value=response(status, {"message": "not available"}))

    with caplog.at_level(logging.DEBUG):
        assert api.get_battery_config_devices() == []
        assert api.get_battery_config_devices() == []

    assert api.connected is True
    assert api.session.request.call_count == 1
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_optional_non_json_failure_does_not_log_error_or_invalidate_session(api, caplog):
    invalid = response(200, {})
    invalid._content = b"gateway temporarily unavailable"
    api.session.request = Mock(return_value=invalid)

    with caplog.at_level(logging.DEBUG):
        assert api.get_battery_config_devices() == []

    assert api.connected is True
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_nonzero_json_code_cannot_create_sensors_even_if_it_contains_data(api):
    api.session.request = Mock(return_value=response(200, {
        "code": 1020,
        "data": [{"configSignalDisplayList": [{"id": 10011, "value": "5000"}]}],
    }))

    assert api.get_battery_config_devices() == []
    assert api.connected is True


def test_successful_config_is_scoped_per_battery_and_uses_only_get(api):
    api._battery_entity_dn = "BAT_B"
    api.battery_dn = "BAT_B"
    api.session.request = Mock(return_value=response(200, {
        "code": 0,
        "data": [{"configSignalDisplayList": [
            {"id": 10011, "value": "5000"},
            {"id": "230320245", "value": "1"},
        ]}],
    }))

    devices = api.get_battery_config_devices()

    assert [(device.device_id, device.state, device.dn) for device in devices] == [
        ("Battery Maximum Charge Power", 5.0, "BAT_B"),
        ("Battery Forced Charge Discharge", "Charge", "BAT_B"),
    ]
    assert all("_inv_bat_b_" in device.device_unique_id for device in devices)
    assert all(device.icon == "mdi:battery" for device in devices)
    assert api.session.request.call_args.args[0] == "GET"
    assert api.session.request.call_args.kwargs["params"] == {"dn": "BAT_B"}


def test_expired_successful_snapshot_is_not_reported_after_rejection(api):
    api.session.request = Mock(return_value=response(200, {
        "code": 0,
        "data": [{"configSignalDisplayList": [{"id": 10011, "value": "5000"}]}],
    }))
    assert len(api.get_battery_config_devices()) == 1
    _, records = api._battery_config_cache[api.battery_dn]
    api._battery_config_cache[api.battery_dn] = (0, records)
    api.session.request.return_value = response(200, {"code": 1020})

    assert api.get_battery_config_devices() == []
    assert api.get_battery_config_devices() == []
    assert api.session.request.call_count == 2


def test_configuration_caches_are_independent_per_battery(api):
    api.session.request = Mock(return_value=response(200, {
        "code": 0,
        "data": [{"configSignalDisplayList": [{"id": 10011, "value": "5000"}]}],
    }))
    first = api.get_battery_config_devices()
    api.battery_dn = "BAT_B"
    api._battery_entity_dn = "BAT_B"
    api.session.request.return_value = response(200, {"code": 1020})
    assert api.get_battery_config_devices() == []
    api.battery_dn = "BAT_A"
    api._battery_entity_dn = None

    assert api.get_battery_config_devices() == first
    assert api.session.request.call_count == 2
