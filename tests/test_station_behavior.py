"""Exercise station metadata and API list retrieval with mocked responses."""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock
import pytest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/fusion_solar_app"
PREFIX="_fusion_solar_station_test"

@pytest.fixture(scope="module")
def modules():
    for name,path in ((PREFIX,ROOT),(f"{PREFIX}.api",ROOT/"api")):
        p=types.ModuleType(name);p.__path__=[str(path)];sys.modules[name]=p
    for sub,path in (("const",ROOT/"const.py"),("api.exceptions",ROOT/"api/exceptions.py"),("api.station",ROOT/"api/station.py")):
        full=f"{PREFIX}.{sub}";spec=importlib.util.spec_from_file_location(full,path)
        mod=importlib.util.module_from_spec(spec);sys.modules[full]=mod;spec.loader.exec_module(mod)
    yield sys.modules[f"{PREFIX}.api.station"],sys.modules[f"{PREFIX}.api.exceptions"]
    for key in list(sys.modules):
        if key==PREFIX or key.startswith(PREFIX+"."):del sys.modules[key]

def make_api(modules,station=None):
    api=modules[0].FusionSolarStationMixin()
    api.station=station;api.station_name=None;api.battery_capacity=None
    api.data_host="eu5.fusionsolar.huawei.com";api.csrf="example"
    api.refresh_csrf=Mock();api._request_json=Mock()
    return api

def test_station_auto_select_and_metadata(modules):
    api=make_api(modules)
    api._update_station_metadata_from_station_list({"data":{"list":[{"dn":"station-1","name":"Test plant","batteryCapacity":15}]}})
    assert (api.station,api.station_name,api.battery_capacity)==("station-1","Test plant",15)

def test_station_selected_by_id(modules):
    api=make_api(modules,"station-2")
    api._update_station_metadata_from_station_list({"data":{"list":[{"dn":"station-1"},{"dn":"station-2","name":"second","batteryCapacity":10}]}})
    assert api.station_name=="second"

@pytest.mark.parametrize("payload", [{},{"data":{"list":[]}},{"data":{"list":"not-a-list"}}])
def test_station_invalid_metadata(modules,payload):
    with pytest.raises(modules[1].APIDataStructureError):
        make_api(modules)._update_station_metadata_from_station_list(payload)

def test_station_missing_selected_raises(modules):
    with pytest.raises(modules[1].APIDataStructureError):
        make_api(modules,"unknown")._update_station_metadata_from_station_list({"data":{"list":[{"dn":"other"}]}})

@pytest.mark.parametrize("payload", [{"success":False},{"data":None},{"data":{"list":"invalid"}}])
def test_station_list_invalid_response(modules,payload):
    api=make_api(modules);api._request_json.return_value=(None,payload)
    with pytest.raises(modules[1].APIDataStructureError):api.get_station_list()

def test_station_list_success_and_post_payload(modules):
    api=make_api(modules);api._request_json.return_value=(None,{"success":True,"data":{"list":[{"dn":"a"}]}})
    assert api.get_station_id()=="a"
    assert api._request_json.call_args.args[0]=="POST"
    assert api._request_json.call_args.kwargs["json"]["pageSize"]==10
    api.refresh_csrf.assert_called_once()
