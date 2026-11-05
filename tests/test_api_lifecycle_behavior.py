"""Behavioral tests of the real assembled FusionSolar API and session lifecycle."""
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock
from datetime import datetime, timezone

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_complete_api"

@pytest.fixture(scope="module")
def api_module():
    package=types.ModuleType(PREFIX)
    package.__path__=[str(ROOT)]
    sys.modules[PREFIX]=package
    for name,path in (("const",ROOT/"const.py"),("utils",ROOT/"utils.py")):
        full=f"{PREFIX}.{name}";spec=importlib.util.spec_from_file_location(full,path)
        module=importlib.util.module_from_spec(spec);sys.modules[full]=module;spec.loader.exec_module(module)
    fullname=f"{PREFIX}.api";path=ROOT/"api"/"__init__.py"
    spec=importlib.util.spec_from_file_location(fullname,path,submodule_search_locations=[str(path.parent)])
    module=importlib.util.module_from_spec(spec);sys.modules[fullname]=module;spec.loader.exec_module(module)
    yield module
    for key in list(sys.modules):
        if key==PREFIX or key.startswith(PREFIX+"."):del sys.modules[key]

@pytest.fixture
def api(api_module,monkeypatch):
    obj=api_module.FusionSolarAPI("test-user","test-password","uni004eu5.fusionsolar.huawei.com",None)
    yield obj
    obj.close()

def test_initialization(api):
    assert api.login_host=="eu5.fusionsolar.huawei.com"
    assert api.controller_name=="fusion_solar_app"
    assert not api.connected
    assert api.request_timeout==20
    assert api.session.cookies.get("locale")=="en-us"

@pytest.mark.parametrize(("kind","value","expected"),[
    ("SENSOR_TEXT","running","running"),
    ("SENSOR_PERCENTAGE","76.8 %",77),
    ("SENSOR_KW","2.123456 W",2.1235),
    ("SENSOR_KWH","12.34 kWh",12.34),
])
def test_dynamic_device(api,api_module,kind,value,expected):
    device=api._create_dynamic_device("Test Signal",getattr(api_module.DeviceType,kind),value,"mdi:test")
    assert device.state==expected
    assert device.device_unique_id=="fusion_solar_app_test_signal"

@pytest.mark.parametrize("missing",[None,"","--","null"])
def test_dynamic_device_skips_missing(api,api_module,missing):
    assert api._create_dynamic_device("Power",api_module.DeviceType.SENSOR_KW,missing,"mdi:test") is None

@pytest.mark.parametrize("raw", [None, "--", "null", "garbage", "NaN", float("inf"), True])
def test_dynamic_energy_rejects_invalid(api, api_module, raw):
    assert api._create_dynamic_device("Energy", api_module.DeviceType.SENSOR_KWH, raw, "mdi:test") is None


@pytest.mark.parametrize("raw", [0, "0", "0 kWh", "0 Wh"])
def test_dynamic_energy_retains_real_zero(api, api_module, raw):
    assert api._create_dynamic_device("Energy", api_module.DeviceType.SENSOR_KWH, raw, "mdi:test").state == 0


def test_station_scoped_unique_id(api,api_module):
    api.station="Plant/1: North"
    assert api.get_device_unique_id("Power Now",api_module.DeviceType.SENSOR_KW)=="fusion_solar_app_plant_1__north_power_now"

@pytest.mark.parametrize(("kind","value","expected"),[
    ("SENSOR_TEXT",56,"56"),
    ("SENSOR_PERCENTAGE","78.9",78),
    ("SENSOR_COUNT","2.6",3),
    ("SENSOR_KW","2.123456",2.1235),
    ("SENSOR_RATIO","12.3456",12.35),
    ("SENSOR_TEMPERATURE","23.45678",23.4568),
])
def test_value_conversion(api,api_module,kind,value,expected):
    assert api.get_device_value("Test Value",getattr(api_module.DeviceType,kind),{"test_value":value})==expected

def test_value_missing_default_and_time(api,api_module):
    assert api.get_device_value("Power",api_module.DeviceType.SENSOR_KW,{"power":None},default=9)==9
    with pytest.raises(KeyError):api.get_device_value("Missing",api_module.DeviceType.SENSOR_KW,{})
    api.last_session_time=datetime(2026,1,1,tzinfo=timezone.utc)
    assert api.get_device_value("time",api_module.DeviceType.SENSOR_TIME,{})==api.last_session_time

def test_logout_closes_local_session_once(api):
    api.connected = True
    api.session.close = Mock(wraps=api.session.close)
    assert api.logout() is True
    assert api.logout() is True
    api.close()
    assert not api.connected
    assert api._closed
    api.session.close.assert_called_once_with()

def test_restore_session_does_not_start_background_thread(api, api_module, monkeypatch):
    thread = Mock(side_effect=AssertionError("No session monitor is needed"))
    monkeypatch.setattr(api_module.threading, "Thread", thread)
    api.restore_session("transferred-token", "example.invalid")
    assert api.connected
    assert api.session.cookies.get("dp-session") == "transferred-token"
    thread.assert_not_called()


@pytest.mark.parametrize("operation", ["login", "reset_session", "restore_session", "request"])
def test_closed_api_cannot_be_revived(api, api_module, operation):
    api.close()
    calls = {
        "login": api.login,
        "reset_session": api.reset_session,
        "restore_session": lambda: api.restore_session("token", "example.invalid"),
        "request": lambda: api._request_json("GET", "https://example.invalid", context="test"),
    }
    with pytest.raises(api_module.APIConnectionError, match="closed"):
        calls[operation]()
    assert not api.connected


@pytest.mark.parametrize("operation", ["close", "reset_session", "login"])
def test_lifecycle_waits_for_inflight_transport(api, operation):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import requests

    entered = threading.Event()
    release = threading.Event()
    lifecycle_started = threading.Event()
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"data": []}'

    def transport(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return response

    api.session.request = Mock(side_effect=transport)
    old_session = api.session
    old_session.close = Mock(wraps=old_session.close)
    api._login_eu5 = Mock(return_value=True)

    def lifecycle():
        lifecycle_started.set()
        getattr(api, operation)()

    with ThreadPoolExecutor(max_workers=2) as pool:
        request = pool.submit(api._request_json, "GET", "https://example.invalid", context="test")
        try:
            assert entered.wait(5)
            cleanup = pool.submit(lifecycle)
            assert lifecycle_started.wait(5)
            old_session.close.assert_not_called()
            api._login_eu5.assert_not_called()
        finally:
            release.set()
        assert request.result(timeout=5)[1] == {"data": []}
        cleanup.result(timeout=5)
    if operation == "login":
        api._login_eu5.assert_called_once()
    else:
        old_session.close.assert_called_once()
    if operation == "reset_session":
        assert api.session is not old_session


def test_close_waits_for_login_then_prevents_reconnection(api):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    entered = threading.Event()
    release = threading.Event()
    cleanup_started = threading.Event()

    def regional_login():
        entered.set()
        assert release.wait(5)
        api.connected = True
        return True

    def cleanup():
        cleanup_started.set()
        api.close()

    api._login_eu5 = Mock(side_effect=regional_login)
    api.session.close = Mock(wraps=api.session.close)
    with ThreadPoolExecutor(max_workers=2) as pool:
        login = pool.submit(api.login)
        try:
            assert entered.wait(5)
            close = pool.submit(cleanup)
            assert cleanup_started.wait(5)
            api.session.close.assert_not_called()
        finally:
            release.set()
        assert login.result(timeout=5)
        close.result(timeout=5)
    assert api._closed
    assert not api.connected
    api.session.close.assert_called_once_with()
