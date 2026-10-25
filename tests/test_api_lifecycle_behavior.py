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
    obj._stop_event.set()
    obj.session.close()

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

def test_logout_stops_monitor(api,monkeypatch):
    api.connected=True
    api._stop_session_monitor=Mock()
    assert api.logout() is True
    assert not api.connected
    api._stop_session_monitor.assert_called_once()

def test_renew_session_success(api):
    api.reset_session=Mock()
    api.login=Mock(return_value=True)
    api._renew_session()
    api.reset_session.assert_called_once()
    api.login.assert_called_once()

def test_renew_session_failure(api):
    api.reset_session=Mock()
    api.login=Mock(side_effect=RuntimeError("offline"))
    api.connected=True
    api._renew_session()
    assert not api.connected

def test_renew_session_captcha(api,api_module):
    api.reset_session=Mock()
    api.login=Mock(side_effect=api_module.APIAuthCaptchaError("captcha"))
    api.connected=True
    api._renew_session()
    assert not api.connected

def test_monitor_stops_when_renewal_fails(api):
    api.connected=False
    api._renew_session=Mock()
    api._session_monitor()
    assert api._stop_event.is_set()
    api._renew_session.assert_called_once()

def test_stop_session_monitor_without_running_thread(api):
    api._stop_session_monitor()
    assert api._stop_event.is_set()
