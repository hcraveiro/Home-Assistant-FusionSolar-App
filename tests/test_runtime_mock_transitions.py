"""Deterministic faults/values at HTTP transport, never Device-state injection."""
from copy import deepcopy
import importlib

import pytest

from test_runtime_mock_api import runtime  # shared real assembled API fixture
from test_api_lifecycle_behavior import api_module, PREFIX


@pytest.fixture
def fast_poll(monkeypatch, runtime):
    # Only omit deliberate historical-request pacing in pure unit tests.
    # The isolated real-HA checker retains production timing.
    module = importlib.import_module(f"{PREFIX}.api.energy_balance")
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    return runtime


def value(devices, name):
    return next(device.state for device in devices if device.device_id == name)


def test_energy_real_readers_and_instance_local_frames(fast_poll):
    loader, backend = fast_poll
    api = backend.MockFusionSolarAPI(loader.load_profile("transitions-energy"))
    other = backend.MockFusionSolarAPI(loader.load_profile("transitions-energy"))
    api.login()
    other.login()
    identities = None
    for index, expected in enumerate((35, 34, None, None, None, 0, 34)):
        if index:
            api.queue_frame("advance")
            assert api.frame_index == index - 1  # applied only before next reader
        devices = api.get_devices()
        assert api.frame_index == index
        assert value(devices, "Panel Production Lifetime") == expected
        assert value(devices, "Panel Production Power") == 3.5
        current = {device.device_unique_id for device in devices}
        if identities is None:
            identities = current
        assert current == identities
        assert value(other.get_devices(), "Panel Production Lifetime") == 35
        assert not api.unexpected_requests
    with pytest.raises(ValueError, match="Final frame"):
        api.queue_frame("advance")
    api.reset_session()
    assert api.frame_id == "recovery-34"
    api.login()
    assert value(api.get_devices(), "Panel Production Lifetime") == 34
    api.queue_frame("reset")
    assert value(api.get_devices(), "Panel Production Lifetime") == 35
    api.close()
    other.close()


def test_optional_vs_required_faults_and_recovery(fast_poll, api_module):
    loader, backend = fast_poll
    profile = loader.load_profile("transitions-failures")
    api = backend.MockFusionSolarAPI(profile)
    api.login()
    session = api.session
    for index, frame in enumerate(profile["frames"]):
        if index:
            api.queue_frame("advance")
        required = frame["id"].startswith("required-")
        if required:
            with pytest.raises(api_module.APIConnectionError):
                api.get_devices()
        else:
            devices = api.get_devices()
            if frame["id"] in ("optional-config-403", "optional-config-418"):
                assert not any(d.device_id == "Battery Forced Charge Power" for d in devices)
            else:
                assert value(devices, "Battery Forced Charge Power") == 3.03
            assert value(devices, "Panel Production Power") == 3.5
            if frame["id"] == "historical-lifetime-418":
                assert value(devices, "Panel Production Lifetime") is None
            else:
                assert value(devices, "Panel Production Lifetime") == 100
        assert api.frame_id == frame["id"]
        assert api.connected and api.session is session
        assert not api.unexpected_requests
    api.close()


@pytest.mark.parametrize("change", [
    {"id": "bad", "responses": [{"route": -1, "body": {}}]},
    {"id": "bad", "responses": [{"route": True, "body": {}}]},
    {"id": "bad", "responses": [{"route": 0, "exception": "exec"}]},
    {"id": "bad", "responses": [{"route": 0, "exception": "timeout", "body": {}}]},
    {"id": "bad", "responses": [{"route": 0, "status": 999, "body": {}}]},
    {"id": "bad", "responses": [{"route": 0, "path": "/write", "body": {}}]},
    {"id": "bad", "responses": [{"route": 0, "body": {"dn": "REAL"}}]},
    {"id": "bad", "invalidate_battery_config": "yes", "responses": []},
    {"id": "bad", "code": "arbitrary"},
])
def test_strict_transition_schema(runtime, change):
    loader, backend = runtime
    profile = loader.load_profile("transitions-energy")
    profile["frames"] = [deepcopy(change)]
    with pytest.raises(ValueError):
        backend.MockFusionSolarAPI(profile)


def test_controls_static_rejection_pending_and_session_reset(fast_poll):
    loader, backend = fast_poll
    static = backend.MockFusionSolarAPI(loader.load_profile("single-battery-config-denied"))
    with pytest.raises(ValueError):
        static.queue_frame("advance")
    api = backend.MockFusionSolarAPI(loader.load_profile("transitions-energy"))
    with pytest.raises(ValueError):
        api.queue_frame("eval")
    api.queue_frame("advance")
    with pytest.raises(ValueError, match="pending"):
        api.queue_frame("reset")
    api.reset_session()
    api.login()
    assert value(api.get_devices(), "Panel Production Lifetime") == 34
    assert api.frame_id == "correction-34"
    api.close()
    static.close()
