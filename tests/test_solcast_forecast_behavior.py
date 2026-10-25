"""Behavioral tests of the production Solcast forecast builder."""
import importlib.util
from pathlib import Path
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/fusion_solar_app"
PREFIX="_solcast_forecast_tests"
NOW=datetime(2026,10,25,12,0,tzinfo=timezone.utc)

@pytest.fixture(scope="module")
def solcast():
    owned=[]
    def add(name, **attrs):
        mod=types.ModuleType(name)
        for key,val in attrs.items():setattr(mod,key,val)
        sys.modules[name]=mod;owned.append(name);return mod
    h=add("homeassistant");h.__path__=[]
    add("homeassistant.core",HomeAssistant=object)
    util=add("homeassistant.util");util.__path__=[]
    add("homeassistant.util.dt",now=lambda:NOW,parse_datetime=lambda s:None if s=="invalid" else datetime.fromisoformat(s.replace("Z","+00:00")),as_local=lambda dt:dt)
    parent=add(PREFIX);parent.__path__=[str(ROOT)]
    api=add(PREFIX+".api",Device=object);api.__path__=[str(ROOT/"api")]
    for sub,path in (("const",ROOT/"const.py"),("forecast.models",ROOT/"forecast"/"models.py"),("forecast.solcast",ROOT/"forecast"/"solcast.py")):
        if sub.startswith("forecast.") and PREFIX+".forecast" not in sys.modules:
            p=add(PREFIX+".forecast");p.__path__=[str(ROOT/"forecast")]
        full=PREFIX+"."+sub;spec=importlib.util.spec_from_file_location(full,path)
        mod=importlib.util.module_from_spec(spec);sys.modules[full]=mod;owned.append(full);spec.loader.exec_module(mod)
    yield sys.modules[PREFIX+".forecast.solcast"]
    for name in reversed(owned):sys.modules.pop(name,None)

def make_builder(solcast,state=None,entity_id="sensor.solcast",actual=1.0,power=0.7):
    hass=types.SimpleNamespace(states=types.SimpleNamespace(get=lambda key:state))
    return solcast.SolcastForecastBuilder(hass,lambda:entity_id,lambda devices:actual,lambda devices:power)

@pytest.mark.asyncio
async def test_no_entity_configured(solcast):
    assert await make_builder(solcast,entity_id=None).build([]) is None

@pytest.mark.asyncio
async def test_missing_state(solcast):
    assert await make_builder(solcast).build([]) is None

@pytest.mark.asyncio
async def test_missing_hourly(solcast):
    state=types.SimpleNamespace(state="5",attributes={"detailedHourly":[]})
    assert await make_builder(solcast,state).build([]) is None

@pytest.mark.asyncio
async def test_invalid_hourly_entries(solcast):
    state=types.SimpleNamespace(state="5",attributes={"detailedHourly":[{"period_start":"invalid","pv_estimate":1}]})
    assert await make_builder(solcast,state).build([]) is None

@pytest.mark.asyncio
async def test_build_full_solcast_forecast(solcast):
    entries=[
        {"period_start":(NOW+timedelta(hours=n)).isoformat(),"pv_estimate":float(n+1)}
        for n in (0,1,2,3)
    ]
    state=types.SimpleNamespace(state="10.0",attributes={
        "detailedHourly":entries,"estimate":10.0,"estimate10":"8.0","estimate90":"12.0",
        "analysis":{"confidence":"0.85"}})
    result=await make_builder(solcast,state).build([])
    assert result is not None
    assert result.forecasted_today==10.0
    assert result.remaining_today==9.0
    assert result.estimate10_kwh==8
    assert result.confidence==0.85
    assert len(result.curve)>4
    assert result.debug["generated_step_count"]>0

@pytest.mark.asyncio
async def test_out_of_day_intervals_filtered(solcast):
    entries=[
        {"period_start":(NOW-timedelta(days=2)).isoformat(),"pv_estimate":2},
        {"period_start":(NOW+timedelta(hours=1)).isoformat(),"pv_estimate":3},
        {"period_start":None,"pv_estimate":3},
    ]
    state=types.SimpleNamespace(state="4",attributes={"detailedHourly":entries})
    result=await make_builder(solcast,state).build([])
    assert result is not None
    assert result.debug["valid_interval_count"]==1
    assert result.debug["skipped_invalid_period_count"]==1

def test_solcast_helpers(solcast):
    b=make_builder(solcast)
    assert b._get_optional_float_attribute({"good":"1.25"},"good")==1.25
    assert b._get_optional_float_attribute({"bad":"bad"},"bad") is None
    assert b._get_optional_float_attribute({},"missing") is None
    assert b._smoothstep(-1)==0
    assert b._smoothstep(2)==1
    assert b._smoothstep(0.5)==0.5
    assert b._parse_period_start(None,NOW) is None
    assert b._parse_period_start("2026-10-25T13:00:00+00:00",NOW).hour==13
    raw=[{"time":NOW+timedelta(minutes=5*n),"power_kw":n,"duration_hours":1/12} for n in range(4)]
    result=b._build_smoothed_steps(raw)
    assert len(result)==4
    assert result[0]["power_kw"]==pytest.approx(1.0)
