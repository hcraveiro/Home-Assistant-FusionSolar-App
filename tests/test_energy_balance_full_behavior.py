"""End-to-end energy-balance aggregation using deterministic mocked Huawei data."""
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock
from datetime import datetime
from urllib.parse import parse_qs, urlparse

import pytest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/fusion_solar_app"
PREFIX="_energy_comprehensive_tests"

@pytest.fixture(scope="module")
def module():
    for name,root in ((PREFIX,ROOT),(PREFIX+".api",ROOT/"api")):
        pkg=types.ModuleType(name);pkg.__path__=[str(root)];sys.modules[name]=pkg
    for sub,path in (("const",ROOT/"const.py"),("utils",ROOT/"utils.py"),("api.exceptions",ROOT/"api/exceptions.py"),("api.models",ROOT/"api/models.py"),("api.energy_balance",ROOT/"api/energy_balance.py")):
        name=PREFIX+"."+sub;spec=importlib.util.spec_from_file_location(name,path)
        mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    yield sys.modules[PREFIX+".api.energy_balance"],sys.modules[PREFIX+".api.exceptions"]
    for name in list(sys.modules):
        if name==PREFIX or name.startswith(PREFIX+"."):del sys.modules[name]

def make_api(module):
    api=module[0].FusionSolarEnergyBalanceMixin()
    api.station="fake-station";api.data_host="example.invalid";api.csrf="placeholder"
    api.refresh_csrf=Mock()
    api._request_json=Mock(return_value=(None,{"data":{}}))
    return api

@pytest.mark.parametrize(("kind","date_str","dimension"),[
    ("MONTH",None,"4"),("PREVIOUS_MONTH",None,"4"),("YEAR",None,"5"),
    ("LIFETIME",None,"6"),("DAY",datetime(2026,1,3),"2"),
])
def test_energy_endpoint_periods(module,kind,date_str,dimension):
    api=make_api(module)
    result=api.call_energy_balance(getattr(module[0].ENERGY_BALANCE_CALL_TYPE,kind),specific_date=date_str)
    assert result=={"data":{}}
    url=api._request_json.call_args.args[1]
    params=parse_qs(urlparse(url).query)
    assert params["timeDim"]==[dimension]
    assert params["stationDn"]==["fake-station"]
    if date_str is not None:assert params["dateStr"][0].startswith("2026-01-03")
    api.refresh_csrf.assert_called_once()

def test_energy_endpoint_missing_data(module):
    api=make_api(module)
    api._request_json.return_value=(None,{"success":True})
    with pytest.raises(module[1].APIDataStructureError):
        api.call_energy_balance(module[0].ENERGY_BALANCE_CALL_TYPE.DAY)

def complete_data(days=31,months=12):
    return {"data":{
        "totalProductPower":"120 kWh",
        "totalSelfUsePower":"40 kWh",
        "totalOnGridPower":"30 kWh",
        "totalBuyPower":"20 kWh",
        "totalUsePower":"50 kWh",
        "chargePower":["1 kWh"]*days,
        "dischargePower":["2 kWh"]*days,
        "selfUsePower":["3 kWh"]*days,
        "usePower":["4 kWh"]*max(days,months),
        "productPower":["5 kWh"]*days,
    }}

def test_full_energy_output_aggregation(module,monkeypatch):
    api=make_api(module)
    data=complete_data()
    api.call_energy_balance=Mock(return_value=data)
    api.get_week_data=Mock(return_value=[data])
    output={}
    api.update_output_with_energy_balance(output)
    assert output["panel_production_month"]==120
    assert output["panel_production_lifetime"]==120
    assert output["battery_injection_month"]==31
    assert output["battery_consumption_month"]==62
    assert output["grid_consumption_today"]==20
    assert output["grid_injection_today"]==30
    assert output["panel_production_year"]==120
    assert output["grid_consumption_lifetime"]==20
    assert output["battery_injection_lifetime"]==31
    assert api.call_energy_balance.call_count>=4
