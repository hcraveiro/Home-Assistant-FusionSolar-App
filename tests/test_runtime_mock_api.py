"""Runtime profiles run the assembled production readers, not mocked Device outputs."""
from datetime import datetime
import importlib
import json
from pathlib import Path

import pytest
import requests

from test_api_lifecycle_behavior import api_module, PREFIX

PROFILES = Path(__file__).parent / "fixtures/runtime_profiles"


@pytest.fixture
def runtime(api_module, monkeypatch):
    monkeypatch.setenv("FUSIONSOLAR_DEV_PROFILE_DIR", str(PROFILES))
    return (importlib.import_module(f"{PREFIX}.mock_profile"),
            importlib.import_module(f"{PREFIX}.mock_api"))


@pytest.mark.parametrize("profile_id,count", [
    ("single-battery-config-denied", 1),
    ("two-inverters-two-batteries", 2),
])
def test_full_production_poll_twice_and_reopen(runtime, profile_id, count):
    loader, backend = runtime
    profile = loader.load_profile(profile_id)
    api = backend.MockFusionSolarAPI(profile)
    assert api.station == profile["station"]["dn"]
    assert api.login() == (True, api.station)
    for _ in range(2):
        devices = api.get_devices()
        assert len(api.inverters) == count
        assert len(api.battery_dns) == count
        assert api.battery_dn == "MOCK_RUNTIME_BAT_A"
        assert api._battery_entity_dn is None
        assert api.connected
        assert not api.unexpected_requests
        assert len({d.device_unique_id for d in devices}) == len(devices)
        assert next(d.state for d in devices if d.device_id == "Panel Production Power") == 3.5
        assert api._battery_parent_dns["MOCK_RUNTIME_BAT_A"] == "MOCK_RUNTIME_INV_A"
        if count == 2:
            assert api._battery_parent_dns["MOCK_RUNTIME_BAT_B"] == "MOCK_RUNTIME_INV_B"
            assert any(d.device_id == "Optimizer Temperature" and d.state == 15.1 for d in devices)
            assert any(d.device_id == "Optimizer Output Power" and d.state == .35 for d in devices)
            assert any("mock_runtime_bat_b" in d.device_unique_id for d in devices)
            forced_power = [d for d in devices if d.device_id == "Battery Forced Charge Power"]
            assert len(forced_power) == 2
            assert {d.state for d in forced_power} == {3.03}
            assert {d.dn for d in forced_power} == {None, "MOCK_RUNTIME_BAT_B"}
            assert any(d.device_id == "Battery Forced Charge Discharge Period" and d.state == 1440 for d in devices)
            assert any(d.device_id == "Battery Maximum Charge Power" and d.state == 5.0 for d in devices)
        else:
            assert not any(d.device_id.startswith("Optimizer ") for d in devices)
            assert not any(d.device_id == "Battery Forced Charge Power" for d in devices)
            assert any(d.device_id == "Battery Charge/Discharge Power" and d.state == 2.125 for d in devices)
    api.reset_session()
    assert isinstance(api.session, backend.OfflineSession)
    api.login()
    assert api.get_devices()
    api.close()
    for operation in (api.login, api.reset_session, api.get_devices):
        with pytest.raises(Exception):
            operation()
    # A new API, as created on integration reload, rediscovers the complete topology.
    api = backend.MockFusionSolarAPI(profile)
    api.login()
    assert api.get_devices()
    api.logout()


def test_transport_fail_closed_and_instance_local(runtime, api_module):
    loader, backend = runtime
    original_request = requests.Session.request
    original_send = requests.Session.send
    for method, url, kwargs in [
        ("GET", "https://huawei.com/rest/read", {}),
        ("GET", "http://example.invalid/rest/read", {}),
        ("GET", "https://example.invalid:443/rest/read", {}),
        ("GET", "https://example.invalid/rest/not-in-profile", {}),
        ("POST", "https://example.invalid/rest/control", {"json": {}}),
        ("DELETE", "https://example.invalid/rest/read", {}),
        ("GET", "https://example.invalid/rest/pvms/web/station/v2/overview/energy-flow", {"params":{"stationDn":"REAL_STATION"}}),
    ]:
        api = backend.MockFusionSolarAPI(loader.load_profile("single-battery-config-denied"))
        with pytest.raises(backend.UnexpectedMockRequest):
            api.session.request(method, url, **kwargs)
        assert api.unexpected_requests
        api.reset_session()
        with pytest.raises(backend.UnexpectedMockRequest):
            api.get_devices()
        api.close()
    session = backend.OfflineSession(loader.load_profile("single-battery-config-denied"))
    with pytest.raises(backend.UnexpectedMockRequest):
        session.send(requests.Request("GET", "https://real.example/").prepare())
    normal = api_module.FusionSolarAPI("unmarked-source", "unused", "eu5", None)
    assert type(normal.session) is requests.Session
    assert requests.Session.request is original_request
    assert requests.Session.send is original_send
    normal.close()


def test_profile_optin_and_path_containment(runtime, monkeypatch, tmp_path):
    loader, _ = runtime
    assert len(loader.list_profiles()) == 7
    monkeypatch.delenv(loader.PROFILE_DIR_ENV)
    assert loader.list_profiles() == {}
    with pytest.raises(ValueError):
        loader.load_profile("single-battery-config-denied")
    monkeypatch.setenv(loader.PROFILE_DIR_ENV, str(tmp_path))
    for bad in ("../outside", "/absolute", "Name", "foo/bar", "foo.json"):
        with pytest.raises(ValueError):
            loader.load_profile(bad)
    (tmp_path / "escape.json").symlink_to(PROFILES / "single-battery-config-denied.json")
    with pytest.raises(ValueError):
        loader.load_profile("escape")
    profile = json.loads((PROFILES / "single-battery-config-denied.json").read_text())
    profile["id"] = "bad"
    profile["routes"][0].pop("body")
    profile["routes"][0]["body_file"] = "../outside.json"
    (tmp_path / "bad.json").write_text(json.dumps(profile))
    with pytest.raises((ValueError, OSError)):
        loader.load_profile("bad")
    assert loader.list_profiles() == {}


def test_identity_and_write_validation(runtime):
    loader, backend = runtime
    profile = loader.load_profile("two-inverters-two-batteries")
    profile["station"]["dn"] = "NOT_FICTIONAL"
    with pytest.raises(ValueError):
        backend.MockFusionSolarAPI(profile)
    profile = loader.load_profile("single-battery-config-denied")
    profile["routes"][0]["method"] = "POST"
    with pytest.raises(ValueError):
        backend.MockFusionSolarAPI(profile)


def test_bad_optional_route_is_not_swallowed(runtime):
    loader, backend = runtime
    profile = loader.load_profile("two-inverters-two-batteries")
    profile["routes"] = [r for r in profile["routes"] if not r["path"].endswith("optimizer-info")]
    api = backend.MockFusionSolarAPI(profile)
    api.login()
    with pytest.raises(backend.UnexpectedMockRequest, match="optimizer-info"):
        api.get_devices()
    api.close()


def test_strict_bodies_dates_and_session_refresh(runtime):
    loader, backend = runtime
    profile = loader.load_profile("single-battery-config-denied")
    api = backend.MockFusionSolarAPI(profile)
    api.login()
    api.csrf_time = None
    api.refresh_csrf()
    assert api.csrf == "MOCK_RUNTIME_CSRF"
    assert sum(path.endswith("keep-alive") for _, path, _, _ in api.session.calls) == 2
    with pytest.raises(ValueError, match="real sessions"):
        api.restore_session("source-token", "production.example")
    api.reset_session()
    api.restore_session("MOCK_RUNTIME_SESSION", "example.invalid")
    assert isinstance(api.session, backend.OfflineSession)
    api.close()
    for route in profile["routes"]:
        if "data" not in route:
            continue
        session = backend.OfflineSession(profile)
        with pytest.raises(backend.UnexpectedMockRequest):
            session.post("https://example.invalid" + route["path"])
        assert session.unexpected
    now = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    expected = next(r["params"] for r in profile["routes"]
                    if r["path"].endswith("energy-balance") and r["params"]["timeDim"] == "2")
    actual = {key: [str(value)] for key, value in expected.items()}
    actual.update(queryTime=[str(int(now.timestamp()*1000))],
                  dateStr=[now.strftime("%Y-%m-%d %H:%M:%S")],
                  _=[str(int(datetime.now().timestamp()*1000))])
    assert backend.OfflineSession._query_matches(actual, expected)
    for key, value in [("stationDn", "REAL_STATION"), ("queryTime", "0"),
                       ("dateStr", "not-a-date"), ("_", "0"),
                       ("timeDim", "6"), ("timeZoneStr", "Europe/Lisbon")]:
        bad = {**actual, key: [value]}
        assert not backend.OfflineSession._query_matches(bad, expected)
