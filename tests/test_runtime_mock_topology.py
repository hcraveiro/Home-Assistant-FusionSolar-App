"""Full production HTTP readers for storage-free and changing topology profiles."""
import json
from pathlib import Path

import pytest

from test_runtime_mock_transitions import fast_poll, value
from test_runtime_mock_api import runtime
from test_api_lifecycle_behavior import api_module


@pytest.mark.parametrize("profile_id", ["transitions-pv-meter", "transitions-topology"])
def test_full_http_topology(fast_poll, profile_id):
    loader, backend = fast_poll
    profile = loader.load_profile(profile_id)
    api = backend.MockFusionSolarAPI(profile)
    api.login()
    seen = set()
    for index, frame in enumerate(profile["frames"]):
        if index:
            api.queue_frame("advance")
        devices = api.get_devices()
        assert not api.unexpected_requests
        ids = [d.device_unique_id for d in devices]
        assert len(ids) == len(set(ids))
        if profile_id == "transitions-pv-meter":
            assert api.battery_dn is None
            assert not api.battery_dns
            assert api.battery_capacity == 0
            assert value(devices, "Panel Production Power") == [0, .4, 0][index]
            assert value(devices, "Power Sensor Active Power") == [-.6, -.2, -.6][index]
        else:
            assert api.battery_dn == "MOCK_RUNTIME_TOPO_BAT_A"
            assert api._battery_parent_dns["MOCK_RUNTIME_TOPO_BAT_B"] == "MOCK_RUNTIME_TOPO_INV_A"
            if index >= 3:
                assert "MOCK_RUNTIME_TOPO_BAT_C" in api.battery_dns
                if index == 3:
                    added = set(ids) - seen
                    assert added and all("mock_runtime_topo_bat_c" in key for key in added)
                else:
                    assert not set(ids) - seen
            soc = [d for d in devices if d.device_id == "Battery SOC" and d.dn == "MOCK_RUNTIME_TOPO_BAT_B"]
            if index == 1:
                assert not soc or soc[0].state is None
            else:
                assert len(soc) == 1 and soc[0].state == 39
            assert next(d.state for d in devices if d.device_id == "Battery SOC" and d.dn is None) == 81
            if index == 1:
                assert not any(d.dn == "MOCK_RUNTIME_TOPO_OPT_2" for d in devices)
                # Configuration remains valid while secondary realtime is absent.
                assert any(d.dn == "MOCK_RUNTIME_TOPO_BAT_B" and d.device_id == "Battery Forced Charge Power" and d.state == 3.03 for d in devices)
        seen.update(ids)
    api.queue_frame("reset")
    api.get_devices()
    assert not api.unexpected_requests
    api.close()


def test_new_station_and_child_namespaces_are_disjoint():
    root = Path(__file__).parent / "fixtures/runtime_profiles"
    keys = {"dn", "stationDn", "deviceDn", "parentDn", "inverterDn", "devId", "parentDevId", "devIds", "conditionParams.parentDn"}

    def identities(obj):
        found = set()
        if isinstance(obj, dict):
            for key, item in obj.items():
                if key in keys:
                    found.update(item if isinstance(item, list) else [item])
                elif key == "schemaData":
                    found.update(identities(json.loads(item)))
                else:
                    found.update(identities(item))
        elif isinstance(obj, list):
            for item in obj:
                found.update(identities(item))
        return found

    profiles = {path.stem: identities(json.loads(path.read_text())) for path in root.glob("*.json")}
    for name in ("transitions-pv-meter", "transitions-topology"):
        assert profiles[name]
        for other, ids in profiles.items():
            if other != name:
                assert profiles[name].isdisjoint(ids), (name, other)
