"""Exercise production Home Assistant sensor classes and forecast entities.

The Home Assistant interfaces are lightweight fixtures, but the integration's
sensor.py itself is imported and all assertions exercise its real methods.
"""

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock
from enum import StrEnum

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusionsolar_sensor_behavior"


@pytest.fixture(scope="module")
def sensor_module():
    old = {}

    def register(name, **attrs):
        old[name] = sys.modules.get(name)
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        sys.modules[name] = mod
        return mod

    def pkg(name):
        mod = register(name)
        mod.__path__ = []
        return mod

    def enum_values(*values):
        return types.SimpleNamespace(**{value: value for value in values})

    pkg("homeassistant")
    pkg("homeassistant.components")
    class SensorEntity:
        pass
    register("homeassistant.components.sensor",
             SensorEntity=SensorEntity,
             SensorDeviceClass=enum_values("POWER", "ENERGY", "TIMESTAMP", "BATTERY",
                                           "VOLTAGE", "CURRENT", "FREQUENCY", "TEMPERATURE",
                                           "REACTIVE_POWER"),
             SensorStateClass=enum_values("TOTAL", "TOTAL_INCREASING", "MEASUREMENT"))
    register("homeassistant.config_entries", ConfigEntry=object)
    register("homeassistant.const", MATCH_ALL="*",
             UnitOfElectricCurrent=enum_values("AMPERE"),
             UnitOfElectricPotential=enum_values("VOLT"),
             UnitOfEnergy=enum_values("KILO_WATT_HOUR"),
             UnitOfFrequency=enum_values("HERTZ"),
             UnitOfPower=enum_values("KILO_WATT"),
             UnitOfTemperature=enum_values("CELSIUS"))
    register("homeassistant.core", HomeAssistant=object, callback=lambda f: f)
    pkg("homeassistant.helpers")
    class EntityCategory:
        DIAGNOSTIC = "diagnostic"
    register("homeassistant.helpers.entity", EntityCategory=EntityCategory)
    registry = Mock()
    register("homeassistant.helpers.device_registry", DeviceInfo=dict,
             DeviceRegistry=type("DeviceRegistry", (), {
                 "async_get_or_create": lambda self, *, via_device_id=None: None
             }), async_get=lambda hass: registry)
    register("homeassistant.helpers.entity_platform", AddEntitiesCallback=object)
    class CoordinatorEntity:
        def __init__(self, coordinator):
            self.coordinator = coordinator
            self.written_states = []
        @property
        def available(self):
            return self.coordinator.last_update_success
        async def async_added_to_hass(self):
            self.coordinator.async_add_listener(self._handle_coordinator_update)
        def async_write_ha_state(self):
            self.written_states.append(self.native_value if self.available else "unavailable")
    register("homeassistant.helpers.update_coordinator", CoordinatorEntity=CoordinatorEntity)
    pkg("homeassistant.util")
    register("homeassistant.util.dt",
             parse_datetime=lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")) if s != "bad-date" else None,
             as_local=lambda d: d.replace(tzinfo=timezone.utc),
             now=lambda: datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
    package = pkg(PREFIX)
    package.__path__ = [str(ROOT)]
    model_spec = importlib.util.spec_from_file_location(f"{PREFIX}.models", ROOT / "api/models.py")
    model = importlib.util.module_from_spec(model_spec)
    old[model_spec.name] = sys.modules.get(model_spec.name)
    sys.modules[model_spec.name] = model
    model_spec.loader.exec_module(model)
    register(f"{PREFIX}.api", Device=model.Device, DeviceType=model.DeviceType)
    constants = register(f"{PREFIX}.const", DOMAIN="fusion_solar_app")
    register(f"{PREFIX}.coordinator", FusionSolarCoordinator=object)
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.sensor", ROOT / "sensor.py")
    module = importlib.util.module_from_spec(spec)
    old[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    for name, previous in reversed(list(old.items())):
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


@pytest.fixture
def coordinator():
    api = types.SimpleNamespace(
        station="Plant/1", station_name="Example Plant",
        controller_name="fusion_solar_app", inverter_dn="inverter-1",
        battery_dn="battery-1", power_sensor_dn="meter-1",
        inverter_model="SUN2000", battery_model="LUNA", power_sensor_model="DTSU",
    )
    data = types.SimpleNamespace(controller_name="fusion_solar_app", forecast=None, devices=[])
    listeners = []
    return types.SimpleNamespace(
        api=api, data=data, _plant_device_registry_id="parent-id",
        last_update_success=True, listeners=listeners,
        async_add_listener=lambda callback: listeners.append(callback) or (lambda: None),
        get_device_by_unique_id=Mock(side_effect=lambda unique_id: next(
            (item for item in data.devices if item.device_unique_id == unique_id), None
        )),
    )


def device(sensor_module, device_id="House Load Power", kind=None, state=1.2):
    kind = kind or sensor_module.DeviceType.SENSOR_KW
    return sensor_module.Device(device_id, "unique-test", kind, device_id, state, "mdi:flash", dn="inverter-1" if device_id.startswith("Inverter ") else None)


@pytest.mark.parametrize("value,expected", [
    ("2.5", 2.5), ("--", 0.0), (None, 0.0), ("invalid", -1.0),
])
def test_safe_float(sensor_module, value, expected):
    assert sensor_module._safe_float(value, -1.0 if value == "invalid" else 0.0) == expected


@pytest.mark.parametrize(("device_id", "fragment"), [
    ("House Load Power", "Plant/1"),
    ("Inverter Model", "_inverter_inverter-1"),
    ("Battery SOH", "_battery_battery-1"),
    ("Power Sensor Status", "_power_sensor_meter-1"),
])
def test_device_info_routes_to_correct_registry(coordinator, sensor_module, device_id, fragment):
    info = sensor_module._build_device_info(coordinator, device(sensor_module, device_id))
    assert any(fragment in identifier[1] for identifier in info["identifiers"])
    if device_id != "House Load Power":
        assert info["via_device_id"] == "parent-id"


@pytest.mark.parametrize(("kind","state","expected"), [
    ("SENSOR_KW", "3.4", 3.4),
    ("SENSOR_KWH", "7", 7.0),
    ("SENSOR_TEXT", 3, "3"),
    ("SENSOR_PERCENTAGE", "87", 87),
    ("SENSOR_RATIO", "44.456", 44.46),
    ("SENSOR_COUNT", "8", 8),
    ("SENSOR_MINUTES", "1440", 1440.0),
])
def test_real_sensor_native_values(coordinator, sensor_module, kind, state, expected):
    obj = sensor_module.FusionSolarSensor(
        coordinator, device(sensor_module, kind=getattr(sensor_module.DeviceType, kind), state=state))
    assert obj.native_value == expected
    assert obj.available
    assert obj.unique_id == "fusion_solar_app-unique-test"
    if kind == "SENSOR_MINUTES":
        assert sensor_module.DeviceType.SENSOR_MINUTES in sensor_module.SUPPORTED_SENSOR_DEVICE_TYPES
        assert obj.native_unit_of_measurement == "min"
        assert obj.state_class == "MEASUREMENT"


def test_mock_devices_are_visibly_marked_without_changing_identity(coordinator, sensor_module):
    obj = sensor_module.FusionSolarSensor(coordinator, device(sensor_module))
    original_id = obj.unique_id
    original_info = obj.device_info
    coordinator.api.mock_profile = {"id": "demo"}
    assert obj.device_info["name"] == f"MOCK [demo] {original_info['name']}"
    assert obj.device_info["identifiers"] == original_info["identifiers"]
    assert obj.unique_id == original_id


def test_sensor_coordinator_updates_invalidate_missing_and_recover(coordinator, sensor_module):
    initial = device(sensor_module, state=5)
    obj = sensor_module.FusionSolarSensor(coordinator, initial)
    identity = (obj.unique_id, obj.name, obj.icon, obj.device_info)
    updated = device(sensor_module, state=6)
    coordinator.data.devices = [updated]
    obj._handle_coordinator_update()
    assert obj.native_value == 6
    coordinator.data.devices = []
    for _ in range(3):
        obj._handle_coordinator_update()
        assert obj.device is None
        assert obj.native_value is None
        assert not obj.available
        assert obj.written_states[-1] == "unavailable"
        assert (obj.unique_id, obj.name, obj.icon, obj.device_info) == identity
    coordinator.data.devices = [device(sensor_module, state=0)]
    obj._handle_coordinator_update()
    assert obj.available
    assert obj.native_value == 0
    assert obj.written_states[-1] == 0
    assert (obj.unique_id, obj.name, obj.icon, obj.device_info) == identity


def test_latest_sensor_metadata_survives_missing_snapshot(coordinator, sensor_module):
    sensor = sensor_module.FusionSolarSensor(coordinator, device(sensor_module, state=1))
    updated = device(sensor_module, state=2)
    updated.name = "Upstream updated name"
    updated.icon = "mdi:solar-power"
    coordinator.data.devices = [updated]
    sensor._handle_coordinator_update()
    coordinator.data.devices = []
    sensor._handle_coordinator_update()
    assert not sensor.available
    assert sensor.native_value is None
    assert sensor.name == updated.name
    assert sensor.icon == updated.icon
    assert sensor.unique_id == "fusion_solar_app-unique-test"


@pytest.mark.parametrize(("device_id","expected"), [
    ("Battery SOH", "diagnostic"),
    ("Battery Module 1 Current", "diagnostic"),
    ("Power Sensor Status", "diagnostic"),
    ("House Load Power", None),
])
def test_sensor_categories(coordinator, sensor_module, device_id, expected):
    sensor = sensor_module.FusionSolarSensor(coordinator, device(sensor_module, device_id))
    assert sensor.entity_category == expected


@pytest.mark.parametrize(("kind","state_class"), [
    ("SENSOR_KWH", None), ("SENSOR_KW", "MEASUREMENT"),
    ("SENSOR_TEXT", None), ("SENSOR_TIME", None),
])
def test_sensor_state_class(coordinator, sensor_module, kind, state_class):
    obj = sensor_module.FusionSolarSensor(
        coordinator, device(sensor_module, kind=getattr(sensor_module.DeviceType, kind)))
    assert obj.state_class == state_class


def test_forecast_defaults(coordinator, sensor_module):
    obj = sensor_module.FusionSolarForecastedTodaySensor(coordinator)
    assert obj.native_value is None
    assert obj.unique_id == "fusion_solar_app-plant_1-forecasted_today"
    assert obj.native_unit_of_measurement == "KILO_WATT_HOUR"


@pytest.mark.parametrize(("value","expected"), [("8.2359",8.236),("invalid",None),(None,None)])
def test_forecast_state_with_real_entity(coordinator, sensor_module, value, expected):
    coordinator.data.forecast = {"forecasted_today": value}
    assert sensor_module.FusionSolarForecastedTodaySensor(coordinator).native_value == expected


def test_forecast_payload_attributes(coordinator, sensor_module):
    coordinator.data.forecast = {"forecasted_today": 12, "remaining_today": 5,
                                 "provider": "native", "debug": {}, "curve": []}
    forecast = sensor_module.FusionSolarForecastedTodaySensor(coordinator)
    assert forecast.extra_state_attributes["remaining_today"] == 5
    assert "debug" not in forecast.extra_state_attributes
    assert forecast.extra_state_attributes["forecast_power_chart"] == []
    remaining = sensor_module.FusionSolarRemainingTodaySensor(coordinator)
    assert remaining.native_value == 5
    assert remaining.extra_state_attributes["forecasted_today"] == 12


def test_forecast_chart_skips_invalid_and_past_samples(coordinator, sensor_module):
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    curve = [
        {"time": now - timedelta(minutes=5), "source": "actual", "power_w": 900, "value": 3},
        {"time": now + timedelta(minutes=5), "source": "forecast", "delta_kwh": 0.1, "value": 3.1},
        {"time": now + timedelta(minutes=10), "source": "forecast", "delta_kwh": 0.2, "value": 3.3},
        {"time": "bad-date", "source": "forecast", "delta_kwh": 10},
    ]
    payload = {"curve": curve, "step_minutes": 5}
    power = sensor_module._build_forecast_power_chart(payload)
    cumulative = sensor_module._build_forecast_cumulative_chart(payload)
    assert power[-2][1] == 1.2
    assert power[-1][1] == 2.4
    assert cumulative[-1][1] == 3.3


def test_no_forecast_future_returns_empty_chart(sensor_module):
    payload = {"curve": [{"source": "actual", "time": "2026-10-25T10:00:00+00:00", "value": 5}]}
    assert sensor_module._build_forecast_power_chart(payload) == []
    assert sensor_module._build_forecast_cumulative_chart(payload) == []


@pytest.mark.asyncio
async def test_sensors_discovered_after_initial_setup_without_duplicates(coordinator, sensor_module):
    """PV inputs found after a nighttime start should become new entities exactly once."""
    first = device(sensor_module, "Panel Production Power", state=0)
    coordinator.data.devices = [first]
    listeners = []
    coordinator.async_add_listener = lambda callback: listeners.append(callback) or (lambda: None)
    hass = types.SimpleNamespace(data={
        sensor_module.DOMAIN: {"entry-1": types.SimpleNamespace(coordinator=coordinator)}
    })
    entry = types.SimpleNamespace(entry_id="entry-1", async_on_unload=lambda unsubscribe: None)
    batches = []
    await sensor_module.async_setup_entry(hass, entry, lambda new: batches.append(list(new)))
    assert len(batches) == 2
    assert [sensor.device_id for sensor in batches[0]] == ["Panel Production Power"]
    assert len(batches[1]) == 2
    assert len(listeners) == 1

    # The inverter's PV string appears when production starts, without a reload.
    pv = device(sensor_module, "Inverter PV1 Voltage", state=400)
    pv.device_unique_id = "inverter-1-pv1-voltage"
    coordinator.data.devices = [first, pv]
    listeners[0]()
    assert [sensor.device_id for sensor in batches[-1] if isinstance(sensor, sensor_module.FusionSolarSensor)] == ["Inverter PV1 Voltage"]
    count = len(batches)
    listeners[0]()
    assert len(batches) == count


@pytest.mark.asyncio
async def test_dynamic_sensor_reappearing_with_same_identity_is_not_recreated(coordinator, sensor_module):
    first = device(sensor_module, "Inverter PV1 Current", state=3)
    coordinator.data.devices = []
    listener = []
    coordinator.async_add_listener = lambda callback: listener.append(callback) or (lambda: None)
    hass = types.SimpleNamespace(data={
        sensor_module.DOMAIN: {"entry-1": types.SimpleNamespace(coordinator=coordinator)}
    })
    entry = types.SimpleNamespace(entry_id="entry-1", async_on_unload=lambda unsubscribe: None)
    batches = []
    await sensor_module.async_setup_entry(hass, entry, lambda new: batches.append(list(new)))
    assert len(batches) == 1  # Only forecast sensors at setup.
    coordinator.data.devices = [first]
    listener[0]()
    assert len(batches) == 2
    sensor = batches[-1][0]
    await sensor.async_added_to_hass()
    coordinator.data.devices = []
    for callback in list(listener):
        callback()
    assert not sensor.available
    assert sensor.native_value is None
    coordinator.data.devices = [device(sensor_module, "Inverter PV1 Current", state=4)]
    for callback in list(listener):
        callback()
    assert len(batches) == 2
    assert sensor.available
    assert sensor.native_value == 4
    assert batches[-1][0] is sensor


def test_optimizer_registry_uses_inverter_parent_when_registered(coordinator, sensor_module, monkeypatch):
    """Optimizer entities belong to their parent inverter without changing their DN-based IDs."""
    inverter = types.SimpleNamespace(id="inverter-registry-id")
    registry = types.SimpleNamespace(async_get_device_by_identifier=Mock(return_value=inverter))
    monkeypatch.setattr(sensor_module.dr, "async_get", lambda hass: registry)
    coordinator.hass = object()
    coordinator.config_entry = types.SimpleNamespace(entry_id="entry-1")
    coordinator.api.inverters = {"NE=INV_1": types.SimpleNamespace(canonical_dn="NE=INV_1")}
    coordinator.api._optimizers = {
        "NE=OPT_2": {
            "parent_dn": "NE=INV_1",
            "position": "1.1.2",
            "model": "MERC-600W-PA0",
            "serial": "OPT_SN_2",
        }
    }
    optimizer = sensor_module.Device(
        "Optimizer Output Power", "station-opt2-output", sensor_module.DeviceType.SENSOR_KW,
        "Output Power", 0.1096, "mdi:solar-power", dn="NE=OPT_2",
    )
    info = sensor_module._build_device_info(coordinator, optimizer)
    assert info["name"] == "Optimizer 1.1.2"
    assert info["model"] == "MERC-600W-PA0"
    assert info["via_device_id"] == "inverter-registry-id"
    assert ("fusion_solar_app", "fusion_solar_app_Plant/1_optimizer_NE=OPT_2") in info["identifiers"]
    registry.async_get_device_by_identifier.assert_called_once_with(
        ("fusion_solar_app", "fusion_solar_app_Plant/1_inverter_NE=INV_1"), "entry-1"
    )


def test_optimizer_registry_falls_back_to_plant(coordinator, sensor_module, monkeypatch):
    registry = types.SimpleNamespace(async_get_device_by_identifier=Mock(return_value=None))
    monkeypatch.setattr(sensor_module.dr, "async_get", lambda hass: registry)
    coordinator.hass = object()
    coordinator.config_entry = types.SimpleNamespace(entry_id="entry-1")
    coordinator.api.inverters = {}
    coordinator.api._optimizers = {"NE=OPT_2": {"parent_dn": "NE=INV_1", "position": "1.1.2"}}
    optimizer = sensor_module.Device(
        "Optimizer Energy Today", "station-opt2-energy", sensor_module.DeviceType.SENSOR_KWH,
        "Energy Today", 0.11, "mdi:solar-power", dn="NE=OPT_2",
    )
    assert sensor_module._build_device_info(coordinator, optimizer)["via_device_id"] == "parent-id"


@pytest.mark.parametrize("device_id", ["Battery Percentage", "Battery Capacity"])
def test_aggregate_battery_sensors_belong_to_station_without_identity_change(coordinator, sensor_module, device_id):
    existing = device(sensor_module, device_id)
    sensor = sensor_module.FusionSolarSensor(coordinator, existing)
    assert sensor.unique_id == "fusion_solar_app-unique-test"
    assert sensor.device_info["identifiers"] == {("fusion_solar_app", "fusion_solar_app_Plant/1")}


@pytest.fixture
def sensor_lifecycle(coordinator, sensor_module):
    """Set up real sensor entities and deliver snapshots through their listeners."""
    async def setup(initial):
        coordinator.data.devices = list(initial)
        hass = types.SimpleNamespace(data={
            sensor_module.DOMAIN: {"entry-1": types.SimpleNamespace(coordinator=coordinator)}
        })
        entry = types.SimpleNamespace(entry_id="entry-1", async_on_unload=lambda unsubscribe: None)
        added = []
        await sensor_module.async_setup_entry(hass, entry, lambda entities: added.extend(entities))
        sensors = [entity for entity in added if isinstance(entity, sensor_module.FusionSolarSensor)]
        for entity in sensors:
            await entity.async_added_to_hass()
            entity.async_write_ha_state()

        def publish(devices, *, success=True):
            coordinator.data.devices = list(devices)
            coordinator.last_update_success = success
            for callback in list(coordinator.listeners):
                callback()

        return sensors, added, publish

    return setup


@pytest.mark.parametrize(("device_id", "dn", "kind", "registry_suffix"), [
    ("House Load Power", None, "SENSOR_KW", "Plant/1"),
    ("Battery Percentage", None, "SENSOR_PERCENTAGE", "Plant/1"),
    ("Battery Capacity", None, "SENSOR_KWH", "Plant/1"),
    ("Battery SOC", None, "SENSOR_PERCENTAGE", "_battery_battery-1"),
    ("Battery SOC", "battery-2", "SENSOR_PERCENTAGE", "_battery_battery-2"),
    ("Battery Rated Capacity", "battery-2", "SENSOR_KWH", "_battery_battery-2"),
    ("Battery Charge/Discharge Power", None, "SENSOR_KW", "_battery_battery-1"),
    ("Battery Energy Discharged Today", "battery-2", "SENSOR_KWH", "_battery_battery-2"),
    ("Battery Module 1 Internal Temperature", None, "SENSOR_TEMPERATURE", "_battery_battery-1"),
    ("Battery Module 2 Pack 3 Total discharge energy", "battery-2", "SENSOR_KWH", "_battery_battery-2"),
    ("Inverter PV1 Current", "inverter-1", "SENSOR_CURRENT", "_inverter_inverter-1"),
    ("Inverter PV1 Current", "inverter-2", "SENSOR_CURRENT", "_inverter_canonical-2"),
    ("Power Sensor Grid Voltage", None, "SENSOR_VOLTAGE", "_power_sensor_meter-1"),
    ("Optimizer Output Power", "optimizer-2", "SENSOR_KW", "_optimizer_optimizer-2"),
    ("Optimizer Input Voltage", "optimizer-2", "SENSOR_VOLTAGE", "_optimizer_optimizer-2"),
    ("Optimizer Output Voltage", "optimizer-2", "SENSOR_VOLTAGE", "_optimizer_optimizer-2"),
    ("Optimizer Input Current", "optimizer-2", "SENSOR_CURRENT", "_optimizer_optimizer-2"),
    ("Optimizer Power Percent", "optimizer-2", "SENSOR_RATIO", "_optimizer_optimizer-2"),
    ("Optimizer Temperature", "optimizer-2", "SENSOR_TEMPERATURE", "_optimizer_optimizer-2"),
    ("iSitePower Cluster Capacity", "cluster-2", "SENSOR_KWH", "_cluster_cluster-2"),
])
@pytest.mark.parametrize("invalid", [
    None, "--", "invalid", "NaN", float("nan"), float("inf"), float("-inf"), True,
])
@pytest.mark.asyncio
async def test_sensor_snapshot_lifecycle_preserves_all_identity_routes(
    coordinator, sensor_module, sensor_lifecycle, monkeypatch,
    device_id, dn, kind, registry_suffix, invalid,
):
    """Missing/invalid optional readings cannot stay live on successful plant polls."""
    coordinator.api.inverters = {
        "inverter-1": types.SimpleNamespace(canonical_dn="inverter-1"),
        "inverter-2": types.SimpleNamespace(canonical_dn="canonical-2"),
    }
    coordinator.api._battery_parent_dns = {"battery-1": "inverter-1", "battery-2": "inverter-2"}
    coordinator.api._optimizers = {"optimizer-2": {"parent_dn": "inverter-2", "position": "2.1"}}
    coordinator.hass = object()
    coordinator.config_entry = types.SimpleNamespace(entry_id="entry-1")
    registry = Mock()
    registry.async_get_or_create.return_value = types.SimpleNamespace(id="parent-id")
    registry.async_get_device_by_identifier.return_value = types.SimpleNamespace(id="inverter-parent-id")
    monkeypatch.setattr(sensor_module.dr, "async_get", lambda hass: registry)

    initial = sensor_module.Device(
        device_id, f"existing-{dn or 'legacy'}-{device_id}",
        getattr(sensor_module.DeviceType, kind), device_id, 5, "mdi:flash", dn=dn,
    )
    sensors, added, publish = await sensor_lifecycle([initial])
    sensor = sensors[0]
    identity = (sensor.unique_id, sensor.name, sensor.icon, sensor.device_info,
                sensor.native_unit_of_measurement, sensor.state_class)
    assert sensor.unique_id == f"fusion_solar_app-{initial.device_unique_id}"
    assert any(value.endswith(registry_suffix) for _, value in sensor.device_info["identifiers"])
    assert sensor.available
    assert sensor.written_states == [5]

    for _ in range(3):
        publish([])
        assert coordinator.last_update_success
        assert not sensor.available
        assert sensor.native_value is None
        assert sensor.device is None
        assert sensor.written_states[-1] == "unavailable"
        assert (sensor.unique_id, sensor.name, sensor.icon, sensor.device_info,
                sensor.native_unit_of_measurement, sensor.state_class) == identity

    invalid_device = sensor_module.Device(
        device_id, initial.device_unique_id, initial.device_type, device_id,
        invalid, initial.icon, dn=dn,
    )
    publish([invalid_device])
    assert not sensor.available
    assert sensor.native_value is None
    assert sensor.written_states[-1] == "unavailable"

    recovered = sensor_module.Device(
        device_id, initial.device_unique_id, initial.device_type, device_id,
        0, initial.icon, dn=dn,
    )
    publish([recovered])
    assert sensor.available
    assert sensor.native_value == 0
    assert sensor.written_states[-1] == 0
    assert len(added) == 3  # One original entity and the two forecasts, no recreation.
    assert sensors[0] is sensor
    assert (sensor.unique_id, sensor.name, sensor.icon, sensor.device_info,
            sensor.native_unit_of_measurement, sensor.state_class) == identity


@pytest.mark.parametrize(("device_id", "kind", "value"), [
    ("Battery Maximum Charge Power", "SENSOR_KW", 5),
    ("Battery End of Charge SOC", "SENSOR_PERCENTAGE", 90),
    ("Battery Charged Energy", "SENSOR_KWH", 10),
    ("Battery Discharged Energy", "SENSOR_KWH", 8),
    ("Battery Charge From AC", "SENSOR_TEXT", "Enabled"),
])
@pytest.mark.asyncio
async def test_cached_optional_configuration_remains_available_when_in_snapshot(
    coordinator, sensor_module, sensor_lifecycle, device_id, kind, value,
):
    cached = device(sensor_module, device_id, getattr(sensor_module.DeviceType, kind), value)
    cached.device_unique_id = f"cached-{device_id}"
    live = device(sensor_module, "Battery Charge/Discharge Power", state=3)
    sensors, _, publish = await sensor_lifecycle([cached, live])
    config_sensor, live_sensor = sensors
    for _ in range(3):
        publish([cached])  # API intentionally carries forward optional config.
        assert config_sensor.available
        assert config_sensor.native_value == value
        assert not live_sensor.available
        assert live_sensor.native_value is None
    publish([cached], success=False)
    assert not config_sensor.available
    publish([cached])
    assert config_sensor.available
    identity = (config_sensor.unique_id, config_sensor.device_info)
    # Once an expired optional config fetch fails, the API omits its devices.
    # They must become unavailable, not resurrect the preceding cached state.
    for _ in range(3):
        publish([])
        assert not config_sensor.available
        assert config_sensor.native_value is None
        assert config_sensor.written_states[-1] == "unavailable"
        assert (config_sensor.unique_id, config_sensor.device_info) == identity
    publish([cached])
    assert config_sensor.available
    assert config_sensor.native_value == value
    assert (config_sensor.unique_id, config_sensor.device_info) == identity


STATION_ENERGY_COUNTER_IDS = [
    f"{metric} {period}"
    for metric in (
        "House Load", "Panel Production", "Panel Production Consumption",
        "Battery Consumption", "Battery Injection", "Grid Consumption", "Grid Injection",
    )
    for period in ("Today", "Week", "Month", "Year", "Lifetime")
]
DEVICE_ENERGY_COUNTER_IDS = [
    "Battery Energy Charged Today", "Battery Energy Discharged Today",
    "Power Sensor Grid Injection Total", "Power Sensor Grid Consumption Total",
    "Optimizer Energy Today",
] + [
    f"Battery Module {module} {metric}"
    for module in range(1, 5)
    for metric in ("Total Charge Energy", "Total Discharge Energy")
] + [
    f"Battery Module {module} Pack {pack} Total discharge energy"
    for module in range(1, 5) for pack in range(1, 4)
]


@pytest.mark.parametrize("device_id", STATION_ENERGY_COUNTER_IDS + DEVICE_ENERGY_COUNTER_IDS)
def test_every_energy_counter_is_total_increasing(coordinator, sensor_module, device_id):
    initial = device(sensor_module, device_id, sensor_module.DeviceType.SENSOR_KWH, 5)
    sensor = sensor_module.FusionSolarSensor(coordinator, initial)
    assert sensor.state_class == "TOTAL_INCREASING"
    assert sensor.device_class == "ENERGY"
    assert sensor.native_unit_of_measurement == "KILO_WATT_HOUR"
    assert sensor.unique_id == "fusion_solar_app-unique-test"
    # Periodic and device resets are valid readings; HA handles them as resets,
    # rather than subtracting the previous period from accumulated consumption.
    coordinator.data.devices = [device(sensor_module, device_id, initial.device_type, 0)]
    sensor._handle_coordinator_update()
    assert sensor.available
    assert sensor.native_value == 0
    assert sensor.state_class == "TOTAL_INCREASING"


@pytest.mark.parametrize("device_id", [
    "Battery Capacity", "Battery Rated Capacity", "iSitePower Cluster Capacity",
    "Battery Charged Energy", "Battery Discharged Energy", "Unknown Energy Value",
])
def test_capacity_and_config_energy_do_not_accumulate_statistics(coordinator, sensor_module, device_id):
    sensor = sensor_module.FusionSolarSensor(
        coordinator, device(sensor_module, device_id, sensor_module.DeviceType.SENSOR_KWH, 5),
    )
    assert sensor.state_class is None  # ENERGY does not support MEASUREMENT.
    assert sensor.device_class == "ENERGY"
    assert sensor.native_unit_of_measurement == "KILO_WATT_HOUR"
    assert sensor.unique_id == "fusion_solar_app-unique-test"


def test_all_station_energy_definitions_have_explicit_semantic_classification(coordinator, sensor_module):
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.signal_maps", ROOT / "api/signal_maps.py")
    signal_maps = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signal_maps)
    energy_ids = {item["id"] for item in signal_maps.DEVICES
                  if item["type"] == sensor_module.DeviceType.SENSOR_KWH}
    assert energy_ids == set(STATION_ENERGY_COUNTER_IDS) | {"Battery Capacity"}


def test_forecast_energy_does_not_accumulate_statistics(coordinator, sensor_module):
    for cls in (sensor_module.FusionSolarForecastedTodaySensor, sensor_module.FusionSolarRemainingTodaySensor):
        sensor = cls(coordinator)
        assert sensor.state_class is None
        assert sensor.device_class == "ENERGY"
        assert sensor.native_unit_of_measurement == "KILO_WATT_HOUR"


@pytest.mark.parametrize(("device_id", "kind", "state"), [
    ("Battery Charge/Discharge Power", "SENSOR_KW", -3),
    ("Optimizer Temperature", "SENSOR_TEMPERATURE", -5),
    ("Optimizer Connection", "SENSOR_TEXT", "offline"),
    ("Battery Operating Status", "SENSOR_TEXT", "Standby"),
    ("Inverter Startup Time", "SENSOR_TIME", datetime(2026, 10, 25, tzinfo=timezone.utc)),
])
@pytest.mark.asyncio
async def test_signed_and_diagnostic_readings_survive_missing_and_recovery(
    sensor_module, sensor_lifecycle, device_id, kind, state,
):
    initial = device(sensor_module, device_id, getattr(sensor_module.DeviceType, kind), state)
    sensors, _, publish = await sensor_lifecycle([initial])
    sensor = sensors[0]
    assert sensor.available
    assert sensor.native_value == state
    publish([])
    assert not sensor.available
    assert sensor.native_value is None
    invalid = device(sensor_module, device_id, initial.device_type, None)
    publish([invalid])
    assert not sensor.available
    assert sensor.native_value is None
    publish([initial])
    assert sensor.available
    assert sensor.native_value == state


@pytest.mark.parametrize(("label", "first_dn", "second_dn"), [
    ("Inverter PV1 Power", "inverter-1", "inverter-2"),
    ("Battery SOC", None, "battery-2"),
    ("Optimizer Output Power", "optimizer-1", "optimizer-2"),
    ("Grid power", None, None),
])
@pytest.mark.asyncio
async def test_same_signal_names_keep_independent_lifecycle_and_no_duplicate_entities(
    sensor_module, sensor_lifecycle, label, first_dn, second_dn,
):
    kind = (sensor_module.DeviceType.SENSOR_PERCENTAGE if label == "Battery SOC"
            else sensor_module.DeviceType.SENSOR_KW)
    first = sensor_module.Device(label, "plant-1-signal", kind, label, 1, "mdi:flash", dn=first_dn)
    second = sensor_module.Device(label, "plant-2-signal", kind, label, 2, "mdi:flash", dn=second_dn)
    sensors, added, publish = await sensor_lifecycle([first, first, second])
    assert len(sensors) == 2  # Duplicate unique ID in the API never duplicates an entity.
    assert sensors[0].unique_id != sensors[1].unique_id
    publish([second])
    assert not sensors[0].available
    assert sensors[0].native_value is None
    assert sensors[1].available
    assert sensors[1].native_value == 2
    publish([first, second])
    assert sensors[0].available
    assert sensors[0].native_value == 1
    assert sensors[1].available
    assert sensors[1].native_value == 2
    assert len(added) == 4  # Still just two standard sensors and two forecasts.
