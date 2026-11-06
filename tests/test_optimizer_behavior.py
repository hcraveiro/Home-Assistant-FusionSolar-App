"""Regression tests for Huawei optimizer layout and bulk telemetry (#47)."""

import html
import json
import time
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


@pytest.mark.parametrize("include_inverters", [True, False])
def test_layout_rejects_conflicting_parent_associations(optimizer_module, include_inverters):
    nodes = [
        {"c": {"nodetype": "assembly", "devTypeId": 20814,
               "devId": dn, "parentDevId": parent}}
        for dn, parent in [
            ("GOOD", "INV_A"), ("DUP", "INV_A"), ("DUP", "INV_B"),
            ("DUP", "INV_A"), ("UNKNOWN_PARENT", "UNKNOWN"),
        ]
    ]
    if include_inverters:
        nodes += [
            {"c": {"nodetype": "inverter", "devTypeId": 20822, "devId": dn}}
            for dn in ("INV_A", "INV_B")
        ]
    result = optimizer_module._parse_optimizer_layout({
        "data": {"schemaData": json.dumps({"datas": nodes})},
    })
    assert set(result) == ({"GOOD"} if include_inverters else {"GOOD", "UNKNOWN_PARENT"})
    assert result["GOOD"]["parent_dn"] == "INV_A"


@pytest.mark.parametrize(("value", "expected"), [
    ("109.6", 109.6), ("0", 0), (0, 0), ("--", None),
    ("null", None), ("", None), (None, None), (True, None),
    ("NaN", None), ("inf", None), ("unknown", None),
])
def test_optional_numeric_readings(optimizer_module, value, expected):
    assert optimizer_module._safe_number(value) == expected


class FakeOptimizerAPI:
    def __init__(self, mixin, records, count=2, optimizer_info=None):
        self._mixin = mixin
        self.station = "NE=STATION_1"
        self.records = records
        self.count = count
        self.optimizer_info = optimizer_info or []
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
        if endpoint.endswith("optimizer-info"):
            return self.optimizer_info
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
    ], optimizer_info=[
        {"dn": "NE=OPT_2", "optName": "Optimizer A", "optNumber": "1.1.2", "temperature": "15.1"},
        {"dn": "NE=OPT_8", "optName": "Optimizer B", "optNumber": "1.1.8", "temperature": "--"},
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
    assert values[("NE=OPT_2", "Optimizer Name")] == "Optimizer A"
    assert values[("NE=OPT_2", "Optimizer Position")] == "1.1.2"
    assert values[("NE=OPT_2", "Optimizer Temperature")] == 15.1
    assert values[("NE=OPT_8", "Optimizer Position")] == "1.1.8"
    assert values[("NE=OPT_8", "Optimizer Temperature")] is None
    assert ("NE=OPT_8", "Optimizer Output Power") not in values
    assert ("NE=OTHER", "Optimizer Output Power") not in values
    assert len({d.device_unique_id for d in devices}) == len(devices)
    assert len([c for c in api._calls if c[0] == "POST"]) == 1
    assert len([c for c in api._calls if c[1].endswith("optimizer-info")]) == 1
    info_call = next(c for c in api._calls if c[1].endswith("optimizer-info"))
    assert info_call[0] == "GET"
    assert info_call[2]["params"] == {"inverterDn": "NE=INV_1"}


def test_optimizer_info_failure_does_not_suppress_existing_telemetry(api):
    request = api._optimizer_request

    def fail_details(method, endpoint, **kwargs):
        if endpoint.endswith("optimizer-info"):
            raise RuntimeError("optional endpoint unavailable")
        return request(method, endpoint, **kwargs)

    api._optimizer_request = fail_details
    devices = api.get_optimizer_devices()
    values = {(device.dn, device.device_id): device.state for device in devices}
    assert values[("NE=OPT_2", "Optimizer Output Power")] == pytest.approx(0.1096)
    assert ("NE=OPT_2", "Optimizer Temperature") not in values


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


@pytest.mark.parametrize("count", [None, "--", "bad", True, False, "NaN", "inf", -1, 1.5, {}, []])
def test_malformed_optimizer_count_recovers_next_refresh(optimizer_module, count):
    api = FakeOptimizerAPI(optimizer_module, [
        {"mocId": 20814, "dn": "NE=OPT_2", "optInfo": {"outputPower": "10"}},
    ], count=count)
    assert api.get_optimizer_devices() == []
    assert api._optimizers is None
    assert len(api._calls) == 1
    api.count = 2
    assert any(d.device_id == "Optimizer Output Power" for d in api.get_optimizer_devices())
    assert sum(c[1].endswith("station-simple-devicedata") for c in api._calls) == 2


@pytest.mark.parametrize("counts", [None, [], {}, {"optimizerNum": "--"}])
def test_malformed_count_response_does_not_cache_empty_topology(optimizer_module, counts):
    api = FakeOptimizerAPI(optimizer_module, [])
    request = api._optimizer_request

    def malformed_counts(method, endpoint, **kwargs):
        if endpoint.endswith("station-simple-devicedata"):
            return counts
        return request(method, endpoint, **kwargs)

    api._optimizer_request = malformed_counts
    assert api.get_optimizer_devices() == []
    assert api._optimizers is None
    api._optimizer_request = request
    api.get_optimizer_devices()
    assert len(api._optimizers) == 2


@pytest.mark.parametrize("count", [0, "0", 0.0])
def test_confirmed_zero_optimizer_count_retries_at_deadline(optimizer_module, count, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    api = FakeOptimizerAPI(optimizer_module, [], count=count)
    assert api.get_optimizer_devices() == []
    assert api._optimizers == {}
    api.count = 2
    clock[0] = 899.999
    assert api.get_optimizer_devices() == []
    assert len(api._calls) == 1
    clock[0] = 900.0
    api.get_optimizer_devices()
    assert len(api._optimizers) == 2
    assert sum(c[1].endswith("station-simple-devicedata") for c in api._calls) == 2


@pytest.mark.parametrize("failed", [False, True])
def test_empty_topology_retries_at_deadline(optimizer_module, logical_tree, monkeypatch, failed):
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    api = FakeOptimizerAPI(optimizer_module, [], count=12)
    request = api._optimizer_request
    available = [False]

    def discovery(method, endpoint, **kwargs):
        if endpoint.endswith("/layout") or endpoint.endswith("device-tree-page"):
            api._calls.append((method, endpoint, kwargs))
            if failed and not available[0]:
                raise RuntimeError("optional layout unavailable")
            return logical_tree if available[0] and endpoint.endswith("device-tree-page") else {}
        return request(method, endpoint, **kwargs)

    api._optimizer_request = discovery
    assert api.get_optimizer_devices() == []
    assert sum(c[1].endswith("device-tree-page") for c in api._calls) == 1
    available[0] = True
    clock[0] = 999.999
    assert api.get_optimizer_devices() == []
    assert sum(c[1].endswith("device-tree-page") for c in api._calls) == 1
    clock[0] = 1000.0
    api.get_optimizer_devices()
    assert len(api._optimizers) == 12
    assert sum(c[1].endswith("device-tree-page") for c in api._calls) == 2
    clock[0] = 2000.0
    api.get_optimizer_devices()
    assert sum(c[1].endswith("device-tree-page") for c in api._calls) == 2


def test_expired_zero_then_malformed_count_recovers_next_refresh(optimizer_module, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    api = FakeOptimizerAPI(optimizer_module, [], count=0)
    api.get_optimizer_devices()
    clock[0] = 900.0
    api.count = "--"
    assert api.get_optimizer_devices() == []
    assert api._optimizers is None
    api.count = 2
    api.get_optimizer_devices()
    assert len(api._optimizers) == 2
    assert sum(c[1].endswith("station-simple-devicedata") for c in api._calls) == 3


def test_physical_layout_never_calls_logical_fallback(api):
    api.get_optimizer_devices()
    assert not any(c[1].endswith("device-tree-page") for c in api._calls)


def test_no_station_skips_optimizer_discovery(optimizer_module):
    api = FakeOptimizerAPI(optimizer_module, [], count=2)
    api.station = None
    assert api.get_optimizer_devices() == []
    assert api._calls == []


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


@pytest.mark.parametrize(("method", "endpoint_name", "request_kwargs"), [
    ("GET", "_COUNTS", {"params": {"stationDn": "NE=STATION_1"}}),
    ("GET", "_LAYOUT", {"params": {"stationDn": "NE=STATION_1", "sheetNO": 0}}),
    ("POST", "_LOGICAL_TREE", {"json_body": {"stationDn": "NE=STATION_1", "layoutType": 2}}),
    ("POST", "_SAMPLING", {"json_body": ["NE=OPT_2"]}),
    ("GET", "_OPTIMIZER_INFO", {"params": {"inverterDn": "NE=INV_1"}}),
])
def test_all_optimizer_endpoints_use_optional_transport(
    optimizer_module, method, endpoint_name, request_kwargs
):
    class Dummy(optimizer_module.FusionSolarOptimizerMixin):
        data_host = "example.invalid"
        csrf = "csrf"

        def refresh_csrf(self):
            pass

        def _request_json(self, method, url, **kwargs):
            self.call = (method, url, kwargs)
            return None, {"success": True, "data": []}

    api = Dummy()
    endpoint = getattr(optimizer_module, endpoint_name)
    assert api._optimizer_request(method, endpoint, **request_kwargs) == []
    assert api.call[:2] == (method, f"https://example.invalid{endpoint}")
    assert api.call[2]["optional"] is True
    assert api.call[2]["context"] == "FusionSolar optimizer telemetry"
    if "params" in request_kwargs:
        assert api.call[2]["params"] == request_kwargs["params"]
    if "json_body" in request_kwargs:
        assert api.call[2]["json"] == request_kwargs["json_body"]


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
            if endpoint.endswith("optimizer-info"):
                parent = kwargs["params"]["inverterDn"]
                suffix = "A" if parent == "NE=INV_A" else "B"
                other = "B" if suffix == "A" else "A"
                return [
                    {"dn": f"NE=OPT_{suffix}_0", "optName": f"Module {suffix}",
                     "optNumber": f"{suffix}.1", "temperature": "25" if suffix == "A" else "30"},
                    # Some upstream responses leak details for another inverter.
                    {"dn": f"NE=OPT_{other}_0", "optName": "Wrong parent", "temperature": "99"},
                ]
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
    values = {(d.dn, d.device_id): d.state for d in first}
    assert values[("NE=OPT_A_0", "Optimizer Name")] == "Module A"
    assert values[("NE=OPT_B_0", "Optimizer Name")] == "Module B"
    assert values[("NE=OPT_A_0", "Optimizer Temperature")] == 25
    assert values[("NE=OPT_B_0", "Optimizer Temperature")] == 30
    assert values[("NE=OPT_A_0", "Optimizer Output Power")] == pytest.approx(0.15)
    assert values[("NE=OPT_B_0", "Optimizer Output Power")] == pytest.approx(0.08)
    info_calls = [c for c in api._calls if c[1].endswith("optimizer-info")]
    assert [(method, kwargs["params"]) for method, _, kwargs in info_calls] == [
        ("GET", {"inverterDn": parent})
        for parent in ("NE=INV_A", "NE=INV_B", "NE=INV_A", "NE=INV_B")
    ]
    sampling_calls = [c for c in api._calls if c[1].endswith("device-sampling-data")]
    assert len(sampling_calls) == 2
    assert all(method == "POST" and kwargs["json_body"] == list(api._optimizers)
               for method, _, kwargs in sampling_calls)


@pytest.mark.parametrize("conflicting", [True, False])
def test_optimizer_info_rejects_conflicting_duplicates(api, conflicting):
    original = dict(api.optimizer_info[0])
    duplicate = dict(original, temperature="99") if conflicting else dict(original)
    api.optimizer_info = [original, duplicate, dict(original)]
    values = {(d.dn, d.device_id): d.state for d in api.get_optimizer_devices()}
    assert values[("NE=OPT_2", "Optimizer Output Power")] == pytest.approx(0.1096)
    assert values[("NE=OPT_2", "Optimizer Position")] == "1.1.2"
    if conflicting:
        assert ("NE=OPT_2", "Optimizer Name") not in values
        assert ("NE=OPT_2", "Optimizer Temperature") not in values
    else:
        assert values[("NE=OPT_2", "Optimizer Name")] == "Optimizer A"
        assert values[("NE=OPT_2", "Optimizer Temperature")] == 15.1


@pytest.mark.parametrize("parent_key", ["inverterDn", "bindInverterDn"])
def test_optimizer_info_ignores_explicit_wrong_parent(api, parent_key):
    api.optimizer_info[0][parent_key] = "NE=WRONG_PARENT"
    values = {(d.dn, d.device_id): d.state for d in api.get_optimizer_devices()}
    assert ("NE=OPT_2", "Optimizer Name") not in values
    assert ("NE=OPT_2", "Optimizer Temperature") not in values
    assert values[("NE=OPT_2", "Optimizer Output Power")] == pytest.approx(0.1096)
