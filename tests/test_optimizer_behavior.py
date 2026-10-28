"""Regression tests for Huawei optimizer layout and bulk telemetry (#47)."""

import html
import json
from pathlib import Path
import importlib.util
import sys
import types
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"


@pytest.fixture
def optimizer_module():
    prefix = "_optimizer_47"
    pkg = types.ModuleType(prefix)
    pkg.__path__ = [str(ROOT / "api")]
    models_name = f"{prefix}.models"
    model_spec = importlib.util.spec_from_file_location(models_name, ROOT / "api/models.py")
    models = importlib.util.module_from_spec(model_spec)
    sys.modules[prefix] = pkg
    sys.modules[models_name] = models
    model_spec.loader.exec_module(models)
    name = f"{prefix}.optimizer"
    spec = importlib.util.spec_from_file_location(name, ROOT / "api/optimizer.py")
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    yield result
    for key in (name, models_name, prefix):
        sys.modules.pop(key, None)


@pytest.fixture
def layout():
    schema = {"datas": [
        {"c": {"nodetype": "inverter", "devId": "NE=INV_1", "devTypeId": 20822}},
        {"c": {"nodetype": "assembly", "devTypeId": 20814, "devId": "NE=OPT_2",
               "parentDevId": "NE=INV_1", "assemblyText1": "1.1.2",
               "modelVersion": "MERC-600W-PA0", "bindNode": "OPT_SN_2"}},
        {"c": {"nodetype": "assembly", "devTypeId": 20814, "devId": "NE=OPT_8",
               "parentDevId": "NE=INV_1", "assemblyText1": "1.1.8"}},
        {"c": {"nodetype": "assembly", "devTypeId": 20814, "devId": "NE=OPT_8",
               "parentDevId": "NE=INV_1", "assemblyText1": "1.1.8"}},
        {"c": {"nodetype": "assembly", "devTypeId": 20814, "devId": "",
               "parentDevId": "NE=INV_1"}},
    ]}
    return {"data": {"schemaData": html.escape(json.dumps(schema), quote=True)}}


@pytest.mark.parametrize("invalid", [{}, {"data": {}},
                                      {"data": {"schemaData": "<broken"}},
                                      {"data": {"schemaData": "{}"}},
                                      {"data": {"schemaData": "[]"}}])
def test_layout_invalid_payloads_do_not_create_devices(optimizer_module, invalid):
    assert optimizer_module._parse_optimizer_layout(invalid) == {}


def test_layout_discovers_only_distinct_valid_optimizer_dns(optimizer_module, layout):
    found = optimizer_module._parse_optimizer_layout(layout)
    assert set(found) == {"NE=OPT_2", "NE=OPT_8"}
    assert found["NE=OPT_2"]["parent_dn"] == "NE=INV_1"
    assert found["NE=OPT_2"]["position"] == "1.1.2"


@pytest.mark.parametrize(("value", "expected"), [
    ("109.6", 109.6), ("0", 0), (0, 0), ("--", None),
    ("null", None), ("", None), (None, None), (True, None),
    ("NaN", None), ("inf", None), ("unknown", None),
])
def test_optional_numeric_readings(optimizer_module, value, expected):
    assert optimizer_module._safe_number(value) == expected


class FakeOptimizerAPI:
    def __init__(self, mixin, records, count=2):
        self._mixin = mixin
        self.station = "NE=STATION_1"
        self.records = records
        self.count = count
        self._calls = []
        self._optimizers = None

    def _optimizer_request(self, method, endpoint, **kwargs):
        self._calls.append((method, endpoint, kwargs))
        if endpoint.endswith("station-simple-devicedata"):
            return {"optimizerNum": self.count}
        if endpoint.endswith("layout"):
            schema = {"datas": [
                {"c": {"nodetype": "assembly", "devTypeId": 20814,
                       "devId": "NE=OPT_2", "parentDevId": "NE=INV_1",
                       "assemblyText1": "1.1.2", "modelVersion": "MERC-600W-PA0"}},
                {"c": {"nodetype": "assembly", "devTypeId": 20814,
                       "devId": "NE=OPT_8", "parentDevId": "NE=INV_1"}},
            ]}
            return {"schemaData": html.escape(json.dumps(schema))}
        return self.records

    def get_device_unique_id(self, name, dtype, dn=None):
        return f"station_opt_{dn}_{name}"

    def get_optimizer_devices(self):
        return self._mixin.FusionSolarOptimizerMixin.get_optimizer_devices(self)


@pytest.fixture
def api(optimizer_module):
    return FakeOptimizerAPI(optimizer_module, [
        {"mocId": 20822, "dn": "NE=INV_1"},
        {"mocId": 20814, "dn": "NE=OPT_2", "dailyEnergy": "0.11",
         "powerPercent": "18.267", "connectStatus": "connected",
         "optInfo": {"outputPower": "109.6", "inputVoltage": "32.0",
                     "outputVoltage": "31.1", "inputCurrent": "3.41",
                     "runningStatusVal": 1}},
        {"mocId": 20814, "dn": "NE=OPT_8", "dailyEnergy": "0.10",
         "optInfo": {"outputPower": "--", "runningStatusVal": 0}},
        {"mocId": 20814, "dn": "NE=OTHER", "optInfo": {"outputPower": "9999"}},
    ])


def test_optimizer_values_and_scoped_unique_ids(api):
    devices = api.get_optimizer_devices()
    values = {(device.dn, device.device_id): device.state for device in devices}
    assert values[("NE=OPT_2", "Optimizer Output Power")] == pytest.approx(0.1096)
    assert values[("NE=OPT_2", "Optimizer Input Voltage")] == 32.0
    assert values[("NE=OPT_2", "Optimizer Output Voltage")] == 31.1
    assert values[("NE=OPT_2", "Optimizer Input Current")] == 3.41
    assert values[("NE=OPT_2", "Optimizer Energy Today")] == 0.11
    assert values[("NE=OPT_2", "Optimizer Running Status")] == 1
    assert ("NE=OPT_8", "Optimizer Output Power") not in values
    assert ("NE=OTHER", "Optimizer Output Power") not in values
    assert len({d.device_unique_id for d in devices}) == len(devices)
    assert len([c for c in api._calls if c[0] == "POST"]) == 1


def test_optimizer_topology_is_cached_but_telemetry_refreshes(api):
    api.get_optimizer_devices()
    api.get_optimizer_devices()
    assert sum(c[1].endswith("layout") for c in api._calls) == 1
    assert len([c for c in api._calls if c[0] == "POST"]) == 2


def test_no_optimizer_count_skips_layout_and_polling(optimizer_module):
    api = FakeOptimizerAPI(optimizer_module, [], count=0)
    assert api.get_optimizer_devices() == []
    assert len(api._calls) == 1
    assert api.get_optimizer_devices() == []
    assert len(api._calls) == 1


def test_sampling_request_uses_json_array_and_csrf(optimizer_module):
    class Dummy(optimizer_module.FusionSolarOptimizerMixin):
        data_host = "example.invalid"
        csrf = "csrf"
        def refresh_csrf(self):
            self.csrf = "renewed"
        def _request_json(self, method, url, **kwargs):
            self.call = (method, url, kwargs)
            return None, {"success": True, "data": []}
    api = Dummy()
    assert api._optimizer_request("POST", optimizer_module._SAMPLING, json_body=["NE=OPT_2"]) == []
    assert api.call[2]["json"] == ["NE=OPT_2"]
    assert api.call[2]["headers"]["Roarand"] == "renewed"
    assert api.call[2]["headers"]["Content-Type"] == "application/json"


def test_failed_response_rejected(optimizer_module):
    class Dummy(optimizer_module.FusionSolarOptimizerMixin):
        data_host = "example.invalid"
        csrf = "csrf"
        def refresh_csrf(self):
            pass
        def _request_json(self, method, url, **kwargs):
            return None, {"success": False}
    with pytest.raises(ValueError):
        Dummy()._optimizer_request("GET", optimizer_module._COUNTS)
