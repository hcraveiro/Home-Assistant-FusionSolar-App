#!/usr/bin/env python3
"""Instantiate actual HA SensorEntity subclasses against offline API replay.

Run with actual Home Assistant installed, NOT inside the pytest stub fixtures:
    python tests/api_profiles/check_homeassistant.py

No HA server is started, no entities registered, no registry/state writes, and
no authentication is attempted. This is class-instantiation/metadata coverage,
not config-entry setup, coordinator polling, recorder or full HA runtime E2E.
The container invocation in docs/mock-scenarios.md enforces --network none.
"""

import asyncio
from datetime import datetime
import importlib
import json
import logging
from pathlib import Path
import socket
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

# The support folder itself is on sys.path when invoked as a standalone script.
from replay import ProfileReplay, load_profile

ROOT = Path(__file__).resolve().parents[2]
PREFIX = "_fusionsolar_offline_actual_ha"


def import_integration():
    # Avoid custom_components/__init__ config-entry setup, but load all actual
    # integration modules (including its coordinator) and actual HA libraries.
    package = ModuleType(PREFIX)
    package.__path__ = [str(ROOT / "custom_components/fusion_solar_app")]
    sys.modules[PREFIX] = package
    return (importlib.import_module(f"{PREFIX}.api"),
            importlib.import_module(f"{PREFIX}.sensor"))


def deny_network(*args, **kwargs):
    raise AssertionError("Network access forbidden by offline HA checker")


async def main():
    from homeassistant.components.sensor import SensorEntity
    from homeassistant.const import UnitOfEnergy, UnitOfPower
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
    from homeassistant.const import __version__ as ha_version

    api_module, sensor_module = import_integration()
    api = api_module.FusionSolarAPI("offline-user", "unused", "example.invalid", None)
    api.restore_session("synthetic-session", "example.invalid")
    api.station = "MOCK_STATION"
    api.battery_dn = "MOCK_BAT_A"
    api.csrf, api.csrf_time = "synthetic-csrf", datetime.now()
    # HomeAssistant only supplies real framework objects; no start/setup calls.
    hass = HomeAssistant("/tmp/fusionsolar-offline-ha-check")
    coordinator = DataUpdateCoordinator(hass, logging.getLogger(__name__), name="offline-profile", config_entry=None)
    coordinator.api = api
    coordinator.data = SimpleNamespace(controller_name=api.controller_name, devices=[], forecast=None)
    coordinator.last_update_success = True
    coordinator._plant_device_registry_id = None
    output = []
    try:
        with patch("requests.sessions.Session.send", deny_network), patch.object(socket.socket, "connect", deny_network), patch("socket.create_connection", deny_network):
            transport = ProfileReplay(load_profile("forced-charge-observed.json"))
            api.session.request = transport
            devices = api.get_battery_config_devices()
            transport.assert_consumed()
            sensors = {device.device_id: sensor_module.FusionSolarSensor(coordinator, device) for device in devices}
            duration = sensors["Battery Forced Charge Discharge Period"]
            power = sensors["Battery Forced Charge Power"]
            energy = sensors["Battery Charged Energy"]
            assert isinstance(duration, SensorEntity)
            assert duration.native_value == 1440.0
            assert duration.native_unit_of_measurement == "min"
            assert duration.icon == "mdi:battery"
            assert duration.name == "Battery Forced Charge Discharge Period"
            assert duration.unique_id.endswith("battery_forced_charge_discharge_period")
            assert power.native_value == 3.03
            assert power.native_unit_of_measurement == UnitOfPower.KILO_WATT
            assert energy.native_value == 1.75
            assert energy.native_unit_of_measurement == UnitOfEnergy.KILO_WATT_HOUR
            assert energy.name == "Battery Forced Charge Energy"
            assert energy.unique_id.endswith("battery_charged_energy")
            assert duration.device_info["identifiers"] == {
                ("fusion_solar_app", "fusion_solar_app_MOCK_STATION_battery_MOCK_BAT_A")
            }
            for obj in (duration, power, energy):
                assert obj.available
                output.append({"name": obj.name, "value": obj.native_value,
                               "unit": obj.native_unit_of_measurement, "icon": obj.icon,
                               "unique_id": obj.unique_id})
            # Separate mixed optimizer profile: actual discovery/sampling/detail
            # readers and sensors. Do not access optimizer device_info here;
            # its registry-parent lookup belongs to the pytest fixture tests.
            transport = ProfileReplay(load_profile("optimizers-observed-day.json"))
            api.session.request = transport
            devices = api.get_optimizer_devices()
            transport.assert_consumed()
            opt = {device.device_id: sensor_module.FusionSolarSensor(coordinator, device)
                   for device in devices if device.dn == "MOCK_OPT_1"}
            assert opt["Optimizer Output Power"].native_value == 0.35
            assert opt["Optimizer Temperature"].native_value == 15.1
            assert opt["Optimizer Name"].native_value == "Mock optimizer 1"
            for name in ("Optimizer Output Power", "Optimizer Temperature", "Optimizer Name"):
                obj = opt[name]
                assert isinstance(obj, SensorEntity)
                output.append({"name": obj.name, "value": obj.native_value,
                               "unit": obj.native_unit_of_measurement, "icon": obj.icon,
                               "unique_id": obj.unique_id})
    finally:
        api.close()
    print(json.dumps({"status": "passed", "homeassistant": ha_version,
                      "coverage": "actual HA class instantiation only; no entity registration or live HA state", "sensors": output}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
