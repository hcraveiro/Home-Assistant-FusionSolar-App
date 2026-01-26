"""Interfaces with the Fusion Solar App api sensors."""

import logging
from datetime import datetime
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfPower, UnitOfEnergy
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import Device, DeviceType
from .const import DOMAIN
from .coordinator import FusionSolarCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up the Sensors."""
    # This gets the data update coordinator from hass.data as specified in your __init__.py
    coordinator: FusionSolarCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ].coordinator

    # Enumerate all the sensors in your data value from your DataUpdateCoordinator and add an instance of your sensor class
    # to a list for each one.
    # This maybe different in your specific case, depending on how your data is structured
    sensors = [
        FusionSolarSensor(coordinator, device)
        for device in coordinator.data.devices
        if device.device_type in {DeviceType.SENSOR_KW, DeviceType.SENSOR_KWH, DeviceType.SENSOR_PERCENTAGE, DeviceType.SENSOR_TIME}
    ]

    # Create the sensors.
    async_add_entities(sensors)


class FusionSolarSensor(CoordinatorEntity, SensorEntity):
    """Implementation of a sensor."""

    def __init__(self, coordinator: FusionSolarCoordinator, device: Device) -> None:
        """Initialise sensor."""
        super().__init__(coordinator)
        self.device = device
        self.device_id = device.device_id

    @callback
    def _handle_coordinator_update(self) -> None:
        """Update sensor with latest data from coordinator."""
        # This method is called by your DataUpdateCoordinator when a successful update runs.
        self.device = self.coordinator.get_device_by_id(
            self.device.device_type, self.device_id
        )
        _LOGGER.debug("Device: %s", self.device)
        self.async_write_ha_state()

    @property
    def device_class(self) -> str:
        """Return device class."""
        # https://developers.home-assistant.io/docs/core/entity/sensor/#available-device-classes
        if self.device.device_type == DeviceType.SENSOR_KW:
            return SensorDeviceClass.POWER
        elif self.device.device_type == DeviceType.SENSOR_KWH:
            return SensorDeviceClass.ENERGY
        elif self.device.device_type == DeviceType.SENSOR_TIME:
            return SensorDeviceClass.TIMESTAMP
        else:
            return SensorDeviceClass.BATTERY

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        # Identifiers are what group entities into the same device.
        # If your device is created elsewhere, you can just specify the indentifiers parameter.
        # If your device connects via another device, add via_device parameter with the indentifiers of that device.
        station_dn = getattr(self.coordinator.api, "station", None) or "unknown_station"
        return DeviceInfo(
            name=f"Fusion Solar ({station_dn})",
            manufacturer="Fusion Solar",
            model="Fusion Solar Model v1",
            sw_version="1.0",
            identifiers={
                (
                    DOMAIN,
                    f"{self.coordinator.data.controller_name}_{station_dn}",
                )
            },
        )

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        return self.device.name

    @property
    def native_value(self) -> float | int | datetime:
        """Return the state of the entity."""
        # Using native value and native unit of measurement, allows you to change units
        # in Lovelace and HA will automatically calculate the correct value.
        if self.device.device_type == DeviceType.SENSOR_TIME:
            return self.device.state
        elif self.device.device_type == DeviceType.SENSOR_PERCENTAGE:
           return int(self.device.state)
        else:
            return float(self.device.state)

    @property
    def native_unit_of_measurement(self) -> str | None:
        """Return unit of power."""
        if self.device.device_type == DeviceType.SENSOR_KW:
            return UnitOfPower.KILO_WATT
        elif self.device.device_type == DeviceType.SENSOR_KWH:
            return UnitOfEnergy.KILO_WATT_HOUR
        elif self.device.device_type == DeviceType.SENSOR_TIME:
            return ""
        else:
            return "%"

    @property
    def state_class(self) -> str | None:
        """Return state class."""
        # https://developers.home-assistant.io/docs/core/entity/sensor/#available-state-classes
        if self.device.device_type == DeviceType.SENSOR_TIME:
            return ""
        elif self.device.device_type == DeviceType.SENSOR_KWH:
            return SensorStateClass.TOTAL
        else:
            return SensorStateClass.MEASUREMENT

    @property
    def unique_id(self) -> str:
        """Return unique id."""
        # All entities must have a unique id.  Think carefully what you want this to be as
        # changing it later will cause HA to create new entities.
        return f"{DOMAIN}-{self.device.device_unique_id}"

    @property
    def icon(self) -> str:
        return self.device.icon

    @property
    def extra_state_attributes(self):
        """Return the extra state attributes."""
        # Add any additional attributes you want on your sensor.
        attrs = {}
        return attrs
