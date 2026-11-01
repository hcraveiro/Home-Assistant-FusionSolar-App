"""Regression tests for Huawei optimizer layout and bulk telemetry (#47)."""

import html
import json
from unittest.mock import patch
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


@pytest.fixture
def logical_tree():
    """Minimal, synthetic form of the verified master/slave logical layout."""
    return {"list": [
        {"mocId": 20822, "dn": "NE=INV_A", "children": [
            {"mocId": 20812, "dn": "NE=PV_A"},
            *[{"mocId": 20814, "dn": f"NE=OPT_A_{i}",
               "parentDn": "NE=STATION", "bindInverterDn": "NE=INV_A",
               "pvNum": f"A.{i}", "meType": "MERC-600W-PA0"}
              for i in range(4)],
        ]},
        {"mocId": 20822, "dn": "NE=INV_B", "children": [
            {"mocId": 20812, "dn": "NE=PV_B"},
            *[{"mocId": 20814, "dn": f"NE=OPT_B_{i}",
               "parentDn": "NE=STATION", "bindInverterDn": "NE=INV_B",
               "pvNum": f"B.{i}", "meType": "MERC-600W-PA0"}
              for i in range(8)],
        ]},
    ]}


def test_logical_tree_discovers_twelve_correctly_associated_optimizers(
    optimizer_module, logical_tree
):
    result = optimizer_module._parse_optimizer_logical_tree(logical_tree)
    assert len(result) == 12
    assert sum(x["parent_dn"] == "NE=INV_A" for x in result.values()) == 4
    assert sum(x["parent_dn"] == "NE=INV_B" for x in result.values()) == 8
    assert result["NE=OPT_B_7"]["position"] == "B.7"


@pytest.mark.parametrize("payload", [{}, None, [], {"list": {}}, {"list": "bad"}])
def test_logical_tree_rejects_malformed_responses(optimizer_module, payload):
    assert optimizer_module._parse_optimizer_logical_tree(payload) == {}


def test_logical_tree_rejects_unbound_or_conflicting_optimizer_dns(optimizer_module):
    payload = {"list": [
        {"mocId": 20822, "dn": "INV_A", "children": [
            {"mocId": 20814, "dn": "GOOD", "bindInverterDn": "INV_A"},
            {"mocId": 20814, "dn": "BAD", "bindInverterDn": "UNKNOWN"},
            {"mocId": 20814, "dn": "", "bindInverterDn": "INV_A"},
            {"mocId": 20814, "dn": "DUP", "bindInverterDn": "INV_A"},
        ]},
        {"mocId": 20822, "dn": "INV_B", "children": [
            {"mocId": 20814, "dn": "DUP", "bindInverterDn": "INV_B"},
        ]},
    ]}
    found = optimizer_module._parse_optimizer_logical_tree(payload)
    assert set(found) == {"GOOD"}


def test_logical_layout_fallback_preserves_scoped_optimizer_ids(optimizer_module, logical_tree):
    class LogicalAPI(FakeOptimizerAPI):
        def _optimizer_request(self, method, endpoint, **kwargs):
            self._calls.append((method, endpoint, kwargs))
            if endpoint.endswith("station-simple-devicedata"):
                return {"optimizerNum": 12}
            if endpoint.endswith("/layout"):
                return {"schemaData": json.dumps({"areas": [], "buildings": [], "version": "1"})}
            if endpoint.endswith("device-tree-page"):
                return logical_tree
            return [
                {"mocId": 20814, "dn": "NE=OPT_A_0",
                 "dailyEnergy": "0.2", "optInfo": {"outputPower": "150"}},
                {"mocId": 20814, "dn": "NE=OPT_B_0",
                 "dailyEnergy": "0.1", "optInfo": {"outputPower": "80"}},
            ]
    api = LogicalAPI(optimizer_module, [])
    first = api.get_optimizer_devices()
    second = api.get_optimizer_devices()
    assert len(api._optimizers) == 12
    assert {d.dn for d in first} == {"NE=OPT_A_0", "NE=OPT_B_0"}
    assert [d.device_unique_id for d in second] == [d.device_unique_id for d in first]
    assert next(d for d in first if d.dn == "NE=OPT_A_0").device_unique_id.startswith(
        "station_opt_NE=OPT_A_0_"
    )
    assert sum(endpoint.endswith("device-tree-page") for _, endpoint, _ in api._calls) == 1
    tree_call = next(x for x in api._calls if x[1].endswith("device-tree-page"))
    assert tree_call[0] == "POST"
    assert tree_call[2]["json_body"]["layoutType"] == 2
    assert tree_call[2]["json_body"]["invertDnlist"] == []


def test_zero_optimizer_count_is_rechecked_after_cooldown(optimizer_module):
    api = FakeOptimizerAPI(optimizer_module, [], count=0)
    with patch.object(optimizer_module.time, "monotonic", return_value=1000):
        assert api.get_optimizer_devices() == []
        assert api.get_optimizer_devices() == []
    assert len(api._calls) == 1
    api.count = 2
    with patch.object(optimizer_module.time, "monotonic", return_value=1901):
        api.get_optimizer_devices()
    assert len([call for call in api._calls if call[1].endswith("station-simple-devicedata")]) == 2
    assert len(api._optimizers) == 2


def test_empty_logical_topology_is_rate_limited_and_recovers(optimizer_module, logical_tree):
    class RecoveringAPI(FakeOptimizerAPI):
        available = False

        def _optimizer_request(self, method, endpoint, **kwargs):
            self._calls.append((method, endpoint, kwargs))
            if endpoint.endswith("station-simple-devicedata"):
                return {"optimizerNum": 12}
            if endpoint.endswith("/layout"):
                return {"schemaData": json.dumps({"areas": [], "buildings": []})}
            if endpoint.endswith("device-tree-page"):
                return logical_tree if self.available else {"list": []}
            return []
    api = RecoveringAPI(optimizer_module, [])
    with patch.object(optimizer_module.time, "monotonic", return_value=1000):
        api.get_optimizer_devices()
        api.get_optimizer_devices()
    assert sum(c[1].endswith("device-tree-page") for c in api._calls) == 1
    api.available = True
    with patch.object(optimizer_module.time, "monotonic", return_value=1901):
        api.get_optimizer_devices()
    assert len(api._optimizers) == 12


def test_physical_layout_never_calls_logical_fallback(api):
    api.get_optimizer_devices()
    assert not any(call[1].endswith("device-tree-page") for call in api._calls)


def test_offline_optimizer_keeps_status_but_not_stale_power(api):
    api.records[1]["connectStatus"] = "offline"
    api.records[1]["dailyEnergy"] = "0.21"
    results = api.get_optimizer_devices()
    values = {(d.dn, d.device_id): d.state for d in results}
    assert values[("NE=OPT_2", "Optimizer Output Power")] is None
    assert values[("NE=OPT_2", "Optimizer Input Voltage")] is None
    assert values[("NE=OPT_2", "Optimizer Energy Today")] == 0.21
    assert values[("NE=OPT_2", "Optimizer Connection")] == "offline"
    api.records[1]["connectStatus"] = "connected"
    fresh = {(d.dn, d.device_id): d.state for d in api.get_optimizer_devices()}
    assert fresh[("NE=OPT_2", "Optimizer Output Power")] == pytest.approx(0.1096)


def test_optimizer_inverter_lookup_is_scoped_to_config_entry():
    """Prevent deprecated, cross-entry-ambiguous device-registry lookups."""
    import ast

    source = (ROOT / "sensor.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    old_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "async_get_device"
    ]
    assert not old_calls

    scoped_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "async_get_device_by_identifier"
    ]
    assert scoped_calls
    assert any(
        len(call.args) >= 2
        and isinstance(call.args[1], ast.Attribute)
        and call.args[1].attr == "entry_id"
        for call in scoped_calls
    )
