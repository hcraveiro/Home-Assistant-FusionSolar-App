"""Interfaces with the Fusion Solar App api sensors."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    MATCH_ALL,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import Device, DeviceType
from .const import DOMAIN
from .coordinator import FusionSolarCoordinator

_LOGGER = logging.getLogger(__name__)

SUPPORTED_SENSOR_DEVICE_TYPES = {
    DeviceType.SENSOR_KW,
    DeviceType.SENSOR_KWH,
    DeviceType.SENSOR_PERCENTAGE,
    DeviceType.SENSOR_TIME,
    DeviceType.SENSOR_VOLTAGE,
    DeviceType.SENSOR_CURRENT,
    DeviceType.SENSOR_FREQUENCY,
    DeviceType.SENSOR_TEMPERATURE,
    DeviceType.SENSOR_RESISTANCE,
    DeviceType.SENSOR_POWER_FACTOR,
    DeviceType.SENSOR_TEXT,
}


def _get_station_suffix(coordinator: FusionSolarCoordinator) -> str:
    """Return a sanitized station suffix for unique IDs."""
    station_dn = getattr(coordinator.api, "station", None) or "unknown_station"
    return (
        str(station_dn)
        .lower()
        .replace(" ", "_")
        .replace(":", "_")
        .replace("/", "_")
    )


def _build_device_info(coordinator: FusionSolarCoordinator) -> DeviceInfo:
    """Build device info shared by all Fusion Solar entities."""
    station_dn = getattr(coordinator.api, "station", None) or "unknown_station"
    controller_name = getattr(
        getattr(coordinator, "data", None),
        "controller_name",
        coordinator.api.controller_name,
    )

    return DeviceInfo(
        name=f"Fusion Solar ({station_dn})",
        manufacturer="Fusion Solar",
        model="Fusion Solar Model v1",
        sw_version="1.0",
        identifiers={
            (
                DOMAIN,
                f"{controller_name}_{station_dn}",
            )
        },
    )


def _forecast_to_dict(forecast: Any) -> dict[str, Any]:
    """Normalize forecast payload into a dictionary."""
    if forecast is None:
        return {}

    if isinstance(forecast, dict):
        payload = dict(forecast)
        if not payload.get("debug"):
            payload.pop("debug", None)
        return payload

    payload = {
        "forecasted_today": getattr(forecast, "forecasted_today", None),
        "remaining_today": getattr(forecast, "remaining_today", None),
        "actual_now_value": getattr(forecast, "actual_now_value", None),
        "correction_factor": getattr(forecast, "correction_factor", None),
        "curve": getattr(forecast, "curve", None),
        "generated_at": getattr(forecast, "generated_at", None),
        "source_entity_id": getattr(forecast, "source_entity_id", None),
        "step_minutes": getattr(forecast, "step_minutes", None),
        "days": getattr(forecast, "days", None),
        "start_of_day": getattr(forecast, "start_of_day", None),
        "end_of_day": getattr(forecast, "end_of_day", None),
    }

    debug = getattr(forecast, "debug", None)
    if debug:
        payload["debug"] = debug

    return payload


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up the sensors."""
    coordinator: FusionSolarCoordinator = hass.data[DOMAIN][
        config_entry.entry_id
    ].coordinator

    sensors: list[SensorEntity] = [
        FusionSolarSensor(coordinator, device)
        for device in coordinator.data.devices
        if device.device_type in SUPPORTED_SENSOR_DEVICE_TYPES
    ]

    sensors.extend(
        [
            FusionSolarForecastedTodaySensor(coordinator),
            FusionSolarRemainingTodaySensor(coordinator),
        ]
    )

    async_add_entities(sensors)


class FusionSolarSensor(CoordinatorEntity, SensorEntity):
    """Implementation of a standard Fusion Solar sensor."""

    DEVICE_CLASS_MAP = {
        DeviceType.SENSOR_KW: SensorDeviceClass.POWER,
        DeviceType.SENSOR_KWH: SensorDeviceClass.ENERGY,
        DeviceType.SENSOR_TIME: SensorDeviceClass.TIMESTAMP,
        DeviceType.SENSOR_PERCENTAGE: SensorDeviceClass.BATTERY,
        DeviceType.SENSOR_VOLTAGE: SensorDeviceClass.VOLTAGE,
        DeviceType.SENSOR_CURRENT: SensorDeviceClass.CURRENT,
        DeviceType.SENSOR_FREQUENCY: SensorDeviceClass.FREQUENCY,
        DeviceType.SENSOR_TEMPERATURE: SensorDeviceClass.TEMPERATURE,
    }

    UNIT_MAP = {
        DeviceType.SENSOR_KW: UnitOfPower.KILO_WATT,
        DeviceType.SENSOR_KWH: UnitOfEnergy.KILO_WATT_HOUR,
        DeviceType.SENSOR_PERCENTAGE: "%",
        DeviceType.SENSOR_VOLTAGE: UnitOfElectricPotential.VOLT,
        DeviceType.SENSOR_CURRENT: UnitOfElectricCurrent.AMPERE,
        DeviceType.SENSOR_FREQUENCY: UnitOfFrequency.HERTZ,
        DeviceType.SENSOR_TEMPERATURE: UnitOfTemperature.CELSIUS,
        DeviceType.SENSOR_RESISTANCE: "MΩ",
    }

    def __init__(self, coordinator: FusionSolarCoordinator, device: Device) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.device = device
        self.device_id = device.device_id
        self._device_name = device.name
        self._device_type = device.device_type
        self._device_unique_id = device.device_unique_id
        self._device_icon = device.icon

    @callback
    def _handle_coordinator_update(self) -> None:
        """Update sensor with latest data from coordinator."""
        updated_device = self.coordinator.get_device_by_id(
            self._device_type,
            self.device_id,
        )

        if updated_device is not None:
            self.device = updated_device

        _LOGGER.debug("Device: %s", self.device)
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Return availability."""
        return super().available and self.device is not None

    @property
    def device_class(self) -> str | None:
        """Return device class."""
        return self.DEVICE_CLASS_MAP.get(self._device_type)

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return _build_device_info(self.coordinator)

    @property
    def name(self) -> str:
        """Return the name of the sensor."""
        if self.device is not None:
            return self.device.name
        return self._device_name

    @property
    def native_value(self) -> float | int | datetime | str | None:
        """Return the state of the entity."""
        if self.device is None:
            return None

        dtype = self.device.device_type

        if dtype == DeviceType.SENSOR_TIME:
            return self.device.state
        if dtype == DeviceType.SENSOR_TEXT:
            return str(self.device.state)
        if dtype == DeviceType.SENSOR_PERCENTAGE:
            return int(self.device.state)

        return float(self.device.state)

    @property
    def native_unit_of_measurement(self) -> str | None:
        """Return unit of measurement."""
        return self.UNIT_MAP.get(self._device_type)

    @property
    def state_class(self) -> str | None:
        """Return state class."""
        if self._device_type in {DeviceType.SENSOR_TIME, DeviceType.SENSOR_TEXT}:
            return None
        if self._device_type == DeviceType.SENSOR_KWH:
            return SensorStateClass.TOTAL
        return SensorStateClass.MEASUREMENT

    @property
    def unique_id(self) -> str:
        """Return unique ID."""
        return f"{DOMAIN}-{self._device_unique_id}"

    @property
    def icon(self) -> str:
        """Return icon."""
        if self.device is not None:
            return self.device.icon
        return self._device_icon

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the extra state attributes."""
        return {}


class FusionSolarForecastSensor(CoordinatorEntity, SensorEntity):
    """Base class for Fusion Solar forecast sensors."""

    _attr_unrecorded_attributes = frozenset({MATCH_ALL})

    _forecast_key: str = ""
    _name: str = ""
    _icon: str = ""

    def __init__(self, coordinator: FusionSolarCoordinator) -> None:
        """Initialize the forecast sensor."""
        super().__init__(coordinator)

    def _get_forecast_payload(self) -> dict[str, Any]:
        """Return the normalized forecast payload from coordinator data."""
        forecast = getattr(getattr(self.coordinator, "data", None), "forecast", None)
        return _forecast_to_dict(forecast)

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return _build_device_info(self.coordinator)

    @property
    def device_class(self) -> str:
        """Return device class."""
        return SensorDeviceClass.ENERGY

    @property
    def native_unit_of_measurement(self) -> str:
        """Return unit of measurement."""
        return UnitOfEnergy.KILO_WATT_HOUR

    @property
    def state_class(self) -> str | None:
        """Return state class."""
        return None

    @property
    def name(self) -> str:
        """Return entity name."""
        return self._name

    @property
    def icon(self) -> str:
        """Return entity icon."""
        return self._icon

    @property
    def unique_id(self) -> str:
        """Return unique ID."""
        station_suffix = _get_station_suffix(self.coordinator)
        return f"{DOMAIN}-{station_suffix}-{self._forecast_key}"

    @property
    def native_value(self) -> float | None:
        """Return sensor value."""
        payload = self._get_forecast_payload()
        value = payload.get(self._forecast_key)

        if value is None:
            return None

        try:
            return round(float(value), 3)
        except (TypeError, ValueError):
            return None


class FusionSolarForecastedTodaySensor(FusionSolarForecastSensor):
    """Fusion Solar forecasted production today sensor."""

    _forecast_key = "forecasted_today"
    _name = "Panel Production Forecasted Today"
    _icon = "mdi:chart-timeline-variant"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes for ApexCharts and diagnostics."""
        payload = self._get_forecast_payload()
        attrs: dict[str, Any] = {}
    
        for key in (
            "curve",
            "remaining_today",
            "actual_now_value",
            "correction_factor",
            "generated_at",
            "source_entity_id",
            "step_minutes",
            "days",
            "start_of_day",
            "end_of_day",
            "debug",
        ):
            value = payload.get(key)
            if value is not None:
                attrs[key] = value
    
        return attrs


class FusionSolarRemainingTodaySensor(FusionSolarForecastSensor):
    """Fusion Solar remaining production today sensor."""

    _forecast_key = "remaining_today"
    _name = "Panel Production Remaining Today"
    _icon = "mdi:progress-clock"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra attributes for diagnostics."""
        payload = self._get_forecast_payload()
        attrs: dict[str, Any] = {}

        for key in (
            "forecasted_today",
            "actual_now_value",
            "generated_at",
            "source_entity_id",
        ):
            value = payload.get(key)
            if value is not None:
                attrs[key] = value

        return attrs