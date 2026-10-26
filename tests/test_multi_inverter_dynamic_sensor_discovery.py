"""Regression tests for multi-inverter dynamic sensor discovery.

Execute the production sensor setup function against simulated HA registry and
coordinator interfaces. This detects collisions between equal sensor names
reported by different inverter DNs without network or HA dependencies.
"""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/sensor.py"
)


def run_sensor_setup(devices):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    fn = next(
        item for item in tree.body
        if isinstance(item, ast.AsyncFunctionDef)
        and item.name == "async_setup_entry"
    )
    added = []
    listeners = []

    class Sensor:
        def __init__(self, coordinator, device):
            self.device = device

    class Forecast:
        def __init__(self, coordinator):
            self.coordinator = coordinator

    coordinator = SimpleNamespace(
        api=SimpleNamespace(
            station="plant-1",
            station_name="Main plant",
            controller_name="cloud",
        ),
        data=SimpleNamespace(controller_name="cloud", devices=list(devices)),
        async_add_listener=lambda callback: listeners.append(callback) or (lambda: None),
    )
    registry = SimpleNamespace(
        async_get_or_create=lambda **kwargs: SimpleNamespace(id="plant-registry-id")
    )
    module = {
        "HomeAssistant": object,
        "ConfigEntry": object,
        "AddEntitiesCallback": object,
        "FusionSolarCoordinator": object,
        "DOMAIN": "fusion_solar_app",
        "dr": SimpleNamespace(async_get=lambda hass: registry),
        "SensorEntity": object,
        "DeviceType": object,
        "SUPPORTED_SENSOR_DEVICE_TYPES": {"sensor"},
        "callback": lambda func: func,
        "FusionSolarSensor": Sensor,
        "FusionSolarForecastedTodaySensor": Forecast,
        "FusionSolarRemainingTodaySensor": Forecast,
    }
    exec(compile(ast.fix_missing_locations(
        ast.Module(body=[fn], type_ignores=[])), str(SOURCE), "exec"), module)
    entry = SimpleNamespace(
        entry_id="entry-1",
        async_on_unload=lambda unsubscribe: None,
    )
    hass = SimpleNamespace(data={
        "fusion_solar_app": {
            "entry-1": SimpleNamespace(coordinator=coordinator)
        }
    })
    asyncio.run(module["async_setup_entry"](
        hass, entry, lambda entities: added.extend(entities)
    ))
    return coordinator, added, listeners


def device(unique_id, label="Inverter PV1 Power"):
    return SimpleNamespace(
        device_type="sensor",
        device_id=label,
        device_unique_id=unique_id,
    )


def test_same_signal_name_on_two_inverters_creates_two_entities():
    """Two DNs may publish identical signal names, but are different sensors."""
    first = device("plant_inv_ne=111_inverter_pv1_power")
    second = device("plant_inv_ne=222_inverter_pv1_power")
    coordinator, added, listeners = run_sensor_setup([first, second])
    assert [entity.device.device_unique_id for entity in added if hasattr(entity, "device")] == [
        first.device_unique_id, second.device_unique_id
    ]
    assert len(listeners) == 1


def test_duplicate_unique_id_is_not_created_twice():
    first = device("plant_inv_ne=111_inverter_pv1_power")
    again = device("plant_inv_ne=111_inverter_pv1_power")
    _, added, _ = run_sensor_setup([first, again])
    assert len([entity for entity in added if hasattr(entity, "device")]) == 1


def test_late_discovery_adds_second_inverter_without_readding_first():
    first = device("plant_inv_ne=111_inverter_pv1_power")
    second = device("plant_inv_ne=222_inverter_pv1_power")
    coordinator, added, listeners = run_sensor_setup([first])
    assert len([entity for entity in added if hasattr(entity, "device")]) == 1
    coordinator.data.devices = [first, second]
    listeners[0]()
    assert [entity.device.device_unique_id for entity in added if hasattr(entity, "device")] == [
        first.device_unique_id, second.device_unique_id
    ]
    listeners[0]()
    assert len([entity for entity in added if hasattr(entity, "device")]) == 2


def test_equal_name_and_type_distinct_non_inverter_ids_still_work():
    first = device("plant-1_grid_power", "Grid power")
    second = device("plant-2_grid_power", "Grid power")
    _, added, _ = run_sensor_setup([first, second])
    assert len([entity for entity in added if hasattr(entity, "device")]) == 2
