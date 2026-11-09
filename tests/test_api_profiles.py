"""Offline profile -> real API readers -> real FusionSolarSensor contracts.

The HTTP boundary is replayed; Home Assistant interfaces/coordinator are fixture
stubs imported from test_sensor_full_behavior, not a running HA installation.
Discovery covers the real flow and DN/parent readers. This is deliberately NOT
full get_devices/coordinator/config-entry/login end-to-end coverage.
"""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from api_profiles import ProfileReplay, load_profile
from test_api_lifecycle_behavior import api_module  # noqa: F401
from test_sensor_full_behavior import sensor_module, coordinator  # noqa: F401


@pytest.fixture
def profile_api(api_module):
    api = api_module.FusionSolarAPI("offline-user", "unused", "example.invalid", None)
    api.restore_session("synthetic-session", "example.invalid")
    api.station = "MOCK_STATION"
    api.station_name = "Offline mock plant"
    api.csrf = "synthetic-csrf"
    api.csrf_time = datetime.now()
    yield api
    api.close()


@pytest.fixture
def sensor_context(profile_api, coordinator, sensor_module, monkeypatch):
    coordinator.api = profile_api
    coordinator.hass = object()
    coordinator.config_entry = SimpleNamespace(entry_id="offline-entry")
    registry = Mock()
    registry.async_get_device_by_identifier.side_effect = lambda identifier, entry: (
        SimpleNamespace(id="registry-" + identifier[1].rsplit("_", 1)[-1])
    )
    monkeypatch.setattr(sensor_module.dr, "async_get", lambda hass: registry)
    return coordinator


def replay(name, api, monkeypatch):
    return ProfileReplay(load_profile(name)).attach(api, monkeypatch)


def discover(api):
    """Real flow request and the same discovery stages used by get_devices."""
    nodes, links = api._get_installation_flow_data()
    assert links == []
    api._discover_battery_dn_from_flow_nodes(nodes)
    api._discover_inverter_dns_from_flow_nodes(nodes)
    api._discover_additional_batteries_from_v3()
    api._discover_battery_parents()


def find(devices, device_id, dn=None):
    return next(d for d in devices if d.device_id == device_id and d.dn == dn)


def sensor(sensor_module, context, device):
    return sensor_module.FusionSolarSensor(context, device)


def test_single_battery_discovery_optional_403_keeps_telemetry(
    profile_api, sensor_context, sensor_module, monkeypatch,
):
    transport = replay("single-battery-config-denied.json", profile_api, monkeypatch)
    discover(profile_api)
    assert list(profile_api.inverters) == ["MOCK_INV_A"]
    assert profile_api.battery_dns == ["MOCK_BAT_A"]
    assert profile_api._battery_parent_dns == {"MOCK_BAT_A": "MOCK_INV_A"}
    devices = profile_api._build_battery_devices()
    transport.assert_consumed()
    assert not any(d.device_id.startswith("Battery Forced") for d in devices)
    soc = sensor(sensor_module, sensor_context, find(devices, "Battery SOC"))
    assert soc.native_value == 77
    assert soc.name == "Battery SOC"
    assert soc.icon == "mdi:battery"
    assert soc.native_unit_of_measurement == "%"
    assert soc.unique_id == "fusion_solar_app-fusion_solar_app_mock_station_battery_soc"
    assert soc.device_info["identifiers"] == {
        ("fusion_solar_app", "fusion_solar_app_MOCK_STATION_battery_MOCK_BAT_A")
    }
    assert soc.device_info["via_device_id"] == "registry-A"
    power = sensor(sensor_module, sensor_context, find(devices, "Battery Charge/Discharge Power"))
    assert power.native_value == 2.125
    assert power.native_unit_of_measurement == "KILO_WATT"
    temperature = sensor(sensor_module, sensor_context, find(devices, "Battery Module 1 Internal Temperature"))
    assert temperature.native_value == 24.5
    assert temperature.icon == "mdi:thermometer"
    assert find(devices, "Battery Module 1 Pack 1 SOH").state == 97
    # Optional 403 is a local feature miss, not a forced account login.
    assert profile_api.connected


def test_two_inverters_have_independent_battery_readers_and_device_association(
    profile_api, sensor_context, sensor_module, monkeypatch,
):
    transport = replay("two-inverters-two-batteries.json", profile_api, monkeypatch)
    discover(profile_api)
    devices = profile_api._build_battery_devices()
    transport.assert_consumed()
    assert list(profile_api.inverters) == ["MOCK_INV_A", "MOCK_INV_B"]
    assert profile_api.battery_dns == ["MOCK_BAT_A", "MOCK_BAT_B"]
    assert profile_api._battery_parent_dns == {"MOCK_BAT_A": "MOCK_INV_A", "MOCK_BAT_B": "MOCK_INV_B"}
    primary = sensor(sensor_module, sensor_context, find(devices, "Battery SOC"))
    secondary = sensor(sensor_module, sensor_context, find(devices, "Battery SOC", "MOCK_BAT_B"))
    assert (primary.native_value, secondary.native_value) == (81, 39)
    assert primary.unique_id != secondary.unique_id
    assert primary.unique_id == "fusion_solar_app-fusion_solar_app_mock_station_battery_soc"
    assert "mock_bat_b" in secondary.unique_id
    for obj, dn in [(primary, "MOCK_BAT_A"), (secondary, "MOCK_BAT_B")]:
        assert obj.device_info["identifiers"] == {
            ("fusion_solar_app", f"fusion_solar_app_MOCK_STATION_battery_{dn}")
        }
        assert obj.device_info["via_device_id"] == f"registry-{dn[-1]}"
    assert profile_api.battery_dn == "MOCK_BAT_A"
    assert profile_api._battery_entity_dn is None
    assert len({d.device_unique_id for d in devices}) == len(devices)


def test_optimizer_day_offline_missing_and_recovery(
    profile_api, sensor_context, sensor_module, monkeypatch,
):
    transport = replay("optimizers-transitions.json", profile_api, monkeypatch)
    devices = profile_api.get_optimizer_devices()
    transport.assert_consumed()
    obj = sensor(sensor_module, sensor_context, find(devices, "Optimizer Output Power", "MOCK_OPT_1"))
    assert obj.native_value == 0.35  # wire watts -> native kW
    assert obj.name == "Output Power"
    assert obj.icon == "mdi:solar-power"
    assert obj.native_unit_of_measurement == "KILO_WATT"
    assert obj.device_info["identifiers"] == {
        ("fusion_solar_app", "fusion_solar_app_MOCK_STATION_optimizer_MOCK_OPT_1")
    }
    assert obj.device_info["via_device_id"] == "registry-A"
    assert profile_api._optimizers["MOCK_OPT_1"]["parent_dn"] == "MOCK_INV_A"
    identity = (obj.unique_id, obj.name, obj.icon, obj.device_info)
    for frame, expected, available in [("offline", None, False), ("missing", None, False), ("recovery", 0.35, True)]:
        transport.advance()
        assert transport.frame["name"] == frame
        sensor_context.data.devices = profile_api.get_optimizer_devices()
        transport.assert_consumed()
        obj._handle_coordinator_update()
        assert obj.native_value == expected
        # Explicit offline records retain entities with unknown readings;
        # a missing record removes the entity from the successful snapshot.
        assert obj.available is available
        assert (obj.unique_id, obj.name, obj.icon, obj.device_info) == identity
        if frame == "offline":
            assert find(sensor_context.data.devices, "Optimizer Connection", "MOCK_OPT_1").state == "disconnected"
            assert find(sensor_context.data.devices, "Optimizer Temperature", "MOCK_OPT_1").state is None


def test_observed_safe_optimizer_details_with_synthetic_sampling(
    profile_api, sensor_context, sensor_module, monkeypatch,
):
    transport = replay("optimizers-observed-day.json", profile_api, monkeypatch)
    devices = profile_api.get_optimizer_devices()
    transport.assert_consumed()
    assert find(devices, "Optimizer Name", "MOCK_OPT_1").state == "Mock optimizer 1"
    assert find(devices, "Optimizer Position", "MOCK_OPT_2").state == "2"
    obj = sensor(sensor_module, sensor_context, find(devices, "Optimizer Temperature", "MOCK_OPT_1"))
    assert obj.native_value == 15.1
    assert obj.native_unit_of_measurement == "CELSIUS"
    assert obj.name == "Temperature"
    assert obj.icon == "mdi:thermometer"


def test_observed_forced_charge_duration_403_cache_expiry_and_recovery(
    profile_api, sensor_context, sensor_module, monkeypatch,
):
    profile_api.battery_dn = "MOCK_BAT_A"
    transport = replay("forced-charge-observed.json", profile_api, monkeypatch)
    devices = profile_api.get_battery_config_devices()
    transport.assert_consumed()
    duration = sensor(sensor_module, sensor_context, find(devices, "Battery Forced Charge Discharge Period"))
    assert duration.native_value == 1440.0
    assert duration.native_unit_of_measurement == "min"
    assert duration.icon == "mdi:battery"
    assert duration.name == "Battery Forced Charge Discharge Period"
    assert find(devices, "Battery Forced Charge Power").state == 3.03
    assert find(devices, "Battery Forced Charge Discharge").state == "Charge"
    assert find(devices, "Battery Forced Charge Setting Mode").state == "Duration"
    energy = sensor(sensor_module, sensor_context, find(devices, "Battery Charged Energy"))
    assert energy.native_value == 1.75
    assert energy.name == "Battery Forced Charge Energy"
    assert energy.native_unit_of_measurement == "KILO_WATT_HOUR"
    assert energy.unique_id.endswith("battery_charged_energy")
    assert not any("Remaining" in d.name for d in devices)  # id 230320458 not invented as telemetry
    assert profile_api.get_battery_config_devices() == devices  # real one-hour cache
    transport.assert_consumed()
    identity = (duration.unique_id, duration.name, duration.device_info)
    for expected in [None, 1440.0]:
        transport.advance()
        # Expire the per-DN cache without a sleep or patching the reader.
        _, records = profile_api._battery_config_cache["MOCK_BAT_A"]
        profile_api._battery_config_cache["MOCK_BAT_A"] = (0, records)
        sensor_context.data.devices = profile_api.get_battery_config_devices()
        transport.assert_consumed()
        duration._handle_coordinator_update()
        assert duration.native_value == expected
        assert duration.available is (expected is not None)
        assert (duration.unique_id, duration.name, duration.device_info) == identity
    assert profile_api.connected


@pytest.mark.parametrize(("method", "url", "kwargs"), [
    ("GET", "https://example.invalid/not-recorded", {}),
    ("GET", "https://real-host.invalid/rest/pvms/web/device/v1/deviceExt/get-config-signals", {}),
    ("POST", "https://example.invalid/rest/pvms/web/device/v1/deviceExt/set-config-signals", {"json": {"value": 1}}),
    ("POST", "https://example.invalid/unisess/v1/auth", {}),
    ("PUT", "https://example.invalid/anything", {}),
    ("DELETE", "https://example.invalid/anything", {}),
])
def test_transport_rejects_unmatched_hosts_writes_and_auth(method, url, kwargs):
    transport = ProfileReplay(load_profile("forced-charge-observed.json"))
    with pytest.raises(AssertionError, match="Unexpected replay request"):
        transport(method, url, **kwargs)
    assert len(transport.unexpected) == 1
    with pytest.raises(AssertionError, match="Unexpected requests"):
        transport.assert_consumed()


def test_optional_reader_cannot_hide_an_unexpected_call(profile_api, monkeypatch):
    transport = ProfileReplay({"frames": [{"name": "empty", "routes": []}]}).attach(profile_api, monkeypatch)
    profile_api.battery_dn = "MOCK_BAT_A"
    assert profile_api.get_battery_config_devices() == []  # catches AssertionError
    assert transport.unexpected
    with pytest.raises(AssertionError, match="possibly swallowed"):
        transport.assert_consumed()


def test_real_responses_and_strict_order_params_body_consumption():
    profile = load_profile("optimizers-transitions.json")
    transport = ProfileReplay(profile)
    first = profile["frames"][0]["routes"][0]
    response = transport(first["method"], "https://example.invalid" + first["path"], params=first["params"])
    assert isinstance(response, requests.Response)
    assert response.json() == first["body"]
    response.raise_for_status()
    with pytest.raises(AssertionError, match="Unconsumed routes"):
        transport.assert_consumed()
    with pytest.raises(AssertionError, match="Unexpected replay request"):
        transport("GET", "https://example.invalid" + first["path"], params={"stationDn": "wrong"})


def test_allowed_read_only_post_still_requires_exact_json():
    transport = ProfileReplay({"frames": [{"name": "post", "routes": [{
        "method": "POST", "path": "/rest/pvms/web/station/v1/layout/device-sampling-data",
        "params": {}, "json": ["MOCK_OPT_1"], "status": 200, "body": {"success": True},
    }]}]})
    with pytest.raises(AssertionError, match="expected route"):
        transport("POST", "https://example.invalid/rest/pvms/web/station/v1/layout/device-sampling-data", json=["other"])
    assert transport.position == 0


def test_replaced_session_cannot_fall_back_to_network(profile_api, monkeypatch):
    transport = ProfileReplay(load_profile("forced-charge-observed.json")).attach(profile_api, monkeypatch)
    with requests.Session() as replacement:
        with pytest.raises(AssertionError, match="network adapter fallback forbidden"):
            replacement.get("https://example.invalid/")
    with pytest.raises(AssertionError, match="Unexpected requests"):
        transport.assert_no_unexpected()
