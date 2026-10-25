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
             SensorStateClass=enum_values("TOTAL", "MEASUREMENT"))
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
    register("homeassistant.helpers.device_registry", DeviceInfo=dict, async_get=lambda hass: registry)
    register("homeassistant.helpers.entity_platform", AddEntitiesCallback=object)
    class CoordinatorEntity:
        available = True
        def __init__(self, coordinator):
            self.coordinator = coordinator
        def async_write_ha_state(self):
            pass
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
    return types.SimpleNamespace(api=api, data=data, _plant_device_registry_id="parent-id",
                                 get_device_by_id=Mock(return_value=None))


def device(sensor_module, device_id="House Load Power", kind=None, state=1.2):
    kind = kind or sensor_module.DeviceType.SENSOR_KW
    return sensor_module.Device(device_id, "unique-test", kind, device_id, state, "mdi:flash")


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
])
def test_real_sensor_native_values(coordinator, sensor_module, kind, state, expected):
    obj = sensor_module.FusionSolarSensor(
        coordinator, device(sensor_module, kind=getattr(sensor_module.DeviceType, kind), state=state))
    assert obj.native_value == expected
    assert obj.available
    assert obj.unique_id == "fusion_solar_app-unique-test"


def test_sensor_coordinator_updates_preserve_previous_on_missing(coordinator, sensor_module):
    initial = device(sensor_module, state=5)
    obj = sensor_module.FusionSolarSensor(coordinator, initial)
    updated = device(sensor_module, state=6)
    coordinator.get_device_by_id.return_value = updated
    obj._handle_coordinator_update()
    assert obj.native_value == 6
    coordinator.get_device_by_id.return_value = None
    obj._handle_coordinator_update()
    assert obj.native_value == 6


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
    ("SENSOR_KWH", "TOTAL"), ("SENSOR_KW", "MEASUREMENT"),
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
async def test_late_sensor_discovery_adds_only_new_supported_entities(
    coordinator, sensor_module
):
    """A sensor appearing after setup must be added without duplicating old entities."""
    from unittest.mock import Mock

    hass = types.SimpleNamespace(
        data={sensor_module.DOMAIN: {"entry-1": types.SimpleNamespace(coordinator=coordinator)}}
    )
    entry = Mock()
    entry.entry_id = "entry-1"
    added = []
    add_entities = lambda items: added.append(items)
    coordinator.data.devices = [device(sensor_module, "First Meter")]
    coordinator.async_add_listener = Mock()

    await sensor_module.async_setup_entry(hass, entry, add_entities)

    assert len(added) == 2
    assert len(added[0]) == 1
    assert len(added[1]) == 2
    assert isinstance(added[0][0], sensor_module.FusionSolarSensor)
    registry_id = coordinator._plant_device_registry_id
    assert registry_id is not None

    listener = coordinator.async_add_listener.call_args.args[0]
    coordinator.data.devices = [
        device(sensor_module, "First Meter"),
        device(sensor_module, "Second Meter"),
    ]
    listener()

    assert len(added) == 3
    assert [sensor.device_id for sensor in added[-1]] == ["Second Meter"]
    listener()
    assert len(added) == 3
    entry.async_on_unload.assert_called_once()


@pytest.mark.asyncio
async def test_sensor_discovery_ignores_unsupported_device_types(
    coordinator, sensor_module
):
    from unittest.mock import Mock

    hass = types.SimpleNamespace(
        data={sensor_module.DOMAIN: {"entry-2": types.SimpleNamespace(coordinator=coordinator)}}
    )
    entry = Mock(entry_id="entry-2")
    added = []
    coordinator.data.devices = [
        device(sensor_module, "Invalid", kind="unsupported_device"),
        device(sensor_module, "Valid"),
    ]
    coordinator.async_add_listener = Mock()

    await sensor_module.async_setup_entry(hass, entry, lambda items: added.append(items))

    assert len(added[0]) == 1
    assert added[0][0].device_id == "Valid"


@pytest.mark.asyncio
async def test_late_device_with_same_name_but_different_type_is_distinct(
    coordinator, sensor_module
):
    from unittest.mock import Mock

    hass = types.SimpleNamespace(
        data={sensor_module.DOMAIN: {"entry-3": types.SimpleNamespace(coordinator=coordinator)}}
    )
    entry = Mock(entry_id="entry-3")
    initial = device(sensor_module, "Energy Reading", kind=sensor_module.DeviceType.SENSOR_KW)
    coordinator.data.devices = [initial]
    coordinator.async_add_listener = Mock()
    added = []

    await sensor_module.async_setup_entry(hass, entry, lambda items: added.append(items))
    listener = coordinator.async_add_listener.call_args.args[0]
    coordinator.data.devices = [initial, device(sensor_module, "Energy Reading",
        kind=sensor_module.DeviceType.SENSOR_KWH)]
    listener()

    assert len(added) == 3
    assert added[-1][0]._device_type == sensor_module.DeviceType.SENSOR_KWH
