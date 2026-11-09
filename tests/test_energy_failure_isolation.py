"""Historical failures must not make a healthy production API poll retry setup.

Only HTTP transport is replayed: the assembled FusionSolarAPI, request error
classification, get_devices(), energy requests and device conversion are real.
"""
from datetime import datetime
import importlib
import json
from pathlib import Path
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from test_api_lifecycle_behavior import api_module, PREFIX
from test_energy_balance_full_behavior import complete_data


@pytest.fixture
def history_api(api_module, monkeypatch):
    energy = importlib.import_module(f"{PREFIX}.api.energy_balance")

    class Thursday(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 5, 12)

    monkeypatch.setattr(energy, "datetime", Thursday)
    auth = importlib.import_module(f"{PREFIX}.api.auth")
    clock = [0.0]
    sleep = Mock(side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    from types import SimpleNamespace
    monkeypatch.setattr(auth, "time", SimpleNamespace(
        monotonic=lambda: clock[0], sleep=sleep))
    profile = json.loads((Path(__file__).parent / "fixtures/runtime_profiles/single-battery-config-denied.json").read_text())
    api = api_module.FusionSolarAPI("unused", "unused", "eu5", None)
    api.station = profile["station"]["dn"]
    api.data_host = "example.invalid"
    api.csrf = "fictional-csrf"
    api.csrf_time = datetime.now()
    api.connected = True
    control = {"failure": None, "kind": "418", "value": 35, "calls": []}

    def request(method, url, **kwargs):
        parsed = urlsplit(url)
        assert parsed.hostname == "example.invalid", "No external HTTP allowed"
        query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
        query.update(kwargs.get("params") or {})
        path = parsed.path
        is_energy = path.endswith("energy-balance")
        dimension = str(query.get("timeDim"))
        label = dimension if is_energy else path.rsplit("/", 1)[-1]
        control["calls"].append((label, query.get("dateStr")))
        fail = control["failure"] == label
        # A single requested daily failure, rather than failing every day.
        if fail and label == "2":
            fail = str(query.get("dateStr", "")).startswith(control.get("day", "2026-11-05"))
        if fail and control["kind"] == "timeout":
            raise requests.Timeout("synthetic history timeout")
        candidates = [route for route in profile["routes"]
                      if route["method"] == method and route["path"] == path]
        candidates = [route for route in candidates if all(
            str(query.get(key)) == str(value)
            for key, value in route.get("params", {}).items()
            if key in ("timeDim", "deviceDn", "dn")
        )]
        assert candidates, (method, path, query)
        route = candidates[0]
        body = complete_data() if is_energy else route["body"]
        if is_energy:
            body["data"]["totalProductPower"] = control["value"]
        status = route["status"]
        if fail:
            if control["kind"] == "schema":
                body = {"success": True}
            else:
                status = int(control["kind"])
                body = {}
        response = requests.Response()
        response.status_code = status
        response.url = url
        response._content = json.dumps(body).encode()
        response.headers["Content-Type"] = "application/json"
        return response

    api.session.request = Mock(side_effect=request)
    yield api, control, energy, sleep
    api.close()


def states(api):
    return {device.device_id: device.state for device in api.get_devices()
            if device.dn is None}


@pytest.mark.parametrize("period,unavailable,retained", [
    ("4", ("Panel Production Month", "Panel Production Today", "Panel Production Week"), "Panel Production Year"),
    ("2", ("Grid Consumption Today", "Grid Consumption Week"), "Panel Production Today"),
    ("5", ("Panel Production Year", "House Load Month"), "Panel Production Month"),
    ("6", ("Panel Production Lifetime",), "Panel Production Year"),
])
@pytest.mark.parametrize("kind", ["418", "timeout"])
def test_real_get_devices_survives_history_and_recovers_next_poll(history_api, period, unavailable, retained, kind):
    api, control, _, sleep = history_api
    baseline = states(api)
    assert all(baseline.get(key) is not None for key in unavailable)
    control.update(failure=period, kind=kind, calls=[])
    failed = states(api)
    assert failed["Panel Production Power"] == 3.5
    assert failed["Battery Percentage"] == 81
    for key in unavailable:
        assert failed.get(key) is None
    assert failed[retained] == baseline[retained]
    assert sum(label == "energy-flow" for label, _ in control["calls"]) == 1
    assert sum(label == period for label, _ in control["calls"]) == (4 if period == "2" else 1)
    assert sleep.call_args.args == (2.0,)
    control.update(failure=None, calls=[])
    recovered = states(api)
    for key in unavailable:
        assert recovered[key] == baseline[key]
    assert sum(label == "energy-flow" for label, _ in control["calls"]) == 1


def test_failed_earlier_day_preserves_today_but_week_is_unknown(history_api):
    api, control, _, _ = history_api
    control.update(failure="2", day="2026-11-03")
    result = states(api)
    assert result["Grid Consumption Today"] == 20
    assert result.get("Grid Consumption Week") is None
    assert result["Panel Production Week"] == 20


def test_day_response_slots_preserve_date_association(history_api):
    api, control, _, sleep = history_api
    control.update(failure="2")
    days = api.get_week_data()
    assert len(days) == 4
    assert all(day["data"]["totalBuyPower"] == "20 kWh" for day in days[:3])
    assert days[3] is None
    assert sleep.call_count == 3


@pytest.mark.parametrize("period", ["4", "2", "5", "6"])
@pytest.mark.parametrize("kind,error", [("401", "APIAuthError"), ("schema", "APIDataStructureError")])
def test_history_auth_and_schema_failures_propagate(history_api, api_module, period, kind, error):
    api, control, _, _ = history_api
    control.update(failure=period, kind=kind)
    with pytest.raises(getattr(api_module, error)):
        api.get_devices()


def test_required_flow_failure_still_propagates(history_api, api_module):
    api, control, _, _ = history_api
    control.update(failure="energy-flow")
    with pytest.raises(api_module.APIConnectionError):
        api.get_devices()
    assert control["calls"] == [("energy-flow", None)]


def test_live_values_and_true_zero_downward_correction_unchanged(history_api):
    api, control, _, _ = history_api
    for value in (35, 34, 0, 34):
        control["value"] = value
        result = states(api)
        for period in ("Month", "Year", "Lifetime"):
            assert result[f"Panel Production {period}"] == value
        assert result["Panel Production Power"] == 3.5


@pytest.mark.parametrize("cross_month", [False, True])
def test_request_order_and_universal_energy_spacing(history_api, monkeypatch, cross_month):
    api, control, energy, sleep = history_api
    if cross_month:
        class Sunday(datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 11, 1, 12)
        monkeypatch.setattr(energy, "datetime", Sunday)
    events = []
    original = api.session.request.side_effect

    def request(method, url, **kwargs):
        if urlsplit(url).path.endswith("energy-balance"):
            events.append(parse_qs(urlsplit(url).query)["timeDim"][0])
        return original(method, url, **kwargs)

    api.session.request.side_effect = request
    advance = sleep.side_effect
    def spaced(seconds):
        events.append(("sleep", seconds))
        advance(seconds)
    sleep.side_effect = spaced
    api.get_devices()
    count = 7 if cross_month else 4
    periods = ["4"] + ["2"] * count
    if cross_month:
        periods.append("4")  # Previous month stays in the weekly stage.
    periods += ["5", "6"]
    expected = [periods[0]]
    for period in periods[1:]:
        expected.extend([("sleep", 2.0), period])
    assert events == expected


def test_previous_month_failure_only_invalidates_dependent_week(history_api, monkeypatch):
    api, control, energy, _ = history_api

    class Sunday(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 1, 12)

    monkeypatch.setattr(energy, "datetime", Sunday)
    original = api.session.request.side_effect

    def request(method, url, **kwargs):
        if "energy-balance" in url and "2026-10-01" in url:
            control["failure"] = "4"
        else:
            control["failure"] = None
        return original(method, url, **kwargs)

    api.session.request.side_effect = request
    result = states(api)
    assert result.get("Panel Production Week") is None
    assert result["Panel Production Today"] == 5
    assert result["Panel Production Month"] == 35
    assert result["Grid Consumption Week"] == 140
