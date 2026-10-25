"""Exercise native forecast builder with a lightweight Home Assistant test boundary."""
import asyncio
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock

import pytest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/fusion_solar_app"
PREFIX="_native_forecast_behavior"


@pytest.fixture(scope="module")
def native(monkeypatch_module=None):
    owned=[]
    def add(name, **attrs):
        module=types.ModuleType(name)
        for key,value in attrs.items():setattr(module,key,value)
        sys.modules[name]=module
        owned.append(name)
        return module
    ha=add("homeassistant")
    ha.__path__=[]
    components=add("homeassistant.components");components.__path__=[]
    recorder=add("homeassistant.components.recorder",get_instance=lambda hass: hass)
    recorder.__path__=[]
    add("homeassistant.components.recorder.history",get_significant_states=lambda *args,**kwargs:{})
    add("homeassistant.core",HomeAssistant=object)
    helpers=add("homeassistant.helpers");helpers.__path__=[]
    add("homeassistant.helpers.entity_registry",async_get=lambda hass: hass.registry)
    add("homeassistant.helpers.storage",Store=lambda *args,**kwargs: Mock())
    util=add("homeassistant.util");util.__path__=[]
    now=datetime(2026,10,25,12,0,tzinfo=timezone.utc)
    add("homeassistant.util.dt",now=lambda:now)
    package=add(PREFIX);package.__path__=[str(ROOT)]
    api=add(PREFIX+".api");api.__path__=[str(ROOT/"api")]
    for name,path in (("const",ROOT/"const.py"),("api.models",ROOT/"api/models.py")):
        fullname=PREFIX+"."+name
        spec=importlib.util.spec_from_file_location(fullname,path)
        mod=importlib.util.module_from_spec(spec);sys.modules[fullname]=mod;owned.append(fullname)
        spec.loader.exec_module(mod)
    models=sys.modules[PREFIX+".api.models"]
    api.Device=models.Device;api.DeviceType=models.DeviceType
    forecast=add(PREFIX+".forecast");forecast.__path__=[str(ROOT/"forecast")]
    for name,path in (("forecast.models",ROOT/"forecast"/"models.py"),("forecast.native",ROOT/"forecast"/"native.py")):
        fullname=PREFIX+"."+name
        spec=importlib.util.spec_from_file_location(fullname,path)
        mod=importlib.util.module_from_spec(spec);sys.modules[fullname]=mod;owned.append(fullname)
        spec.loader.exec_module(mod)
    yield sys.modules[PREFIX+".forecast.native"],models
    for name in reversed(owned):sys.modules.pop(name,None)


def builder(native):
    mod,_=native
    hass=types.SimpleNamespace(registry=types.SimpleNamespace(async_get_entity_id=lambda *args:"sensor.production"))
    return mod.NativeForecastBuilder(hass,"test",step_minutes=60,days=2)


def source_device(native,state=4.5):
    _,model=native
    return model.Device("Panel Production Today","test-id",model.DeviceType.SENSOR_KWH,"Today",state,"mdi:solar")


@pytest.mark.asyncio
async def test_no_source_returns_none(native):
    assert await builder(native).build([]) is None


@pytest.mark.asyncio
async def test_no_history_keeps_actual_value(native):
    obj=builder(native)
    async def no_history(*args):return []
    obj._get_history_states=no_history
    result=await obj.build([source_device(native)])
    assert result.forecasted_today==4.5
    assert result.remaining_today==0
    assert result.curve


@pytest.mark.asyncio
async def test_forecast_future_curve(native):
    obj=builder(native)
    now=datetime(2026,10,25,12,0,tzinfo=timezone.utc)
    async def get_history(*args):
        return [types.SimpleNamespace(state="1.0",last_changed=now-timedelta(hours=2)),
                types.SimpleNamespace(state="2.0",last_changed=now)]
    obj._get_history_states=get_history
    async def cache(**kwargs):
        return {"date":"2026-10-25","delta_curve":[{"delta_kwh":0.1,"power_w":100.0} for _ in range(25)]}
    obj._async_ensure_forecast_cache=cache
    result=await obj.build([source_device(native,2.0)])
    assert result.forecasted_today>2
    assert result.remaining_today>0
    assert any(point["source"]=="forecast" for point in result.curve)


@pytest.mark.parametrize(("states","expected"),[
    ([("unavailable",0),("3.0",1),("unknown",2)], [3.0]),
    ([("bad",0),("4.2",1)], [4.2]),
])
def test_history_filters_non_numeric(native,states,expected):
    obj=builder(native)
    now=datetime(2026,10,25,tzinfo=timezone.utc)
    samples=[types.SimpleNamespace(state=v,last_changed=now+timedelta(minutes=i)) for v,i in states]
    _,values=obj._build_history_index(samples)
    assert values==expected


def test_sample_lookback(native):
    obj=builder(native)
    t=datetime(2026,10,25,tzinfo=timezone.utc)
    assert obj._get_numeric_sample_at([t],[2.0],t+timedelta(minutes=2),timedelta(minutes=3))==(t,2.0)
    assert obj._get_numeric_sample_at([t],[2.0],t+timedelta(minutes=6),timedelta(minutes=3)) is None


def test_smoothing_preserves_total(native):
    obj=builder(native)
    values=[0,0,4,0,0]
    smoothed=obj._smooth_delta_values(values)
    assert sum(smoothed)==pytest.approx(4)
    assert all(x>=0 for x in smoothed)


def test_weighted_statistics(native):
    obj=builder(native)
    assert obj._calculate_weighted_average_delta([(2,1),(4,3)])==pytest.approx(3.5)
    assert obj._calculate_weighted_average_delta([])==0
    assert obj._calculate_median_delta([1,3,2])==2
    assert obj._calculate_median_delta([1,3])==2
    assert obj._calculate_median_delta([])==0
    assert obj._calculate_robust_weighted_delta([(2,1),(3,1)])==pytest.approx(2.5)
