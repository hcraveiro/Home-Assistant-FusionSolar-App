from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class DeviceType(StrEnum):
    """Device types."""

    SENSOR_KW = "sensor"
    SENSOR_KWH = "sensor_kwh"
    SENSOR_PERCENTAGE = "sensor_percentage"
    SENSOR_RATIO = "sensor_ratio"
    SENSOR_TIME = "sensor_time"
    SENSOR_VOLTAGE = "sensor_voltage"
    SENSOR_CURRENT = "sensor_current"
    SENSOR_FREQUENCY = "sensor_frequency"
    SENSOR_TEMPERATURE = "sensor_temperature"
    SENSOR_RESISTANCE = "sensor_resistance"
    SENSOR_POWER_FACTOR = "sensor_power_factor"
    SENSOR_VAR = "sensor_var"
    SENSOR_TEXT = "sensor_text"
    SENSOR_KG = "sensor_kg"
    SENSOR_COUNT = "sensor_count"
    SENSOR_MINUTES = "sensor_minutes"


# Parsing contract matching sensor.UNIT_MAP, without importing the HA platform.
NUMERIC_DEVICE_UNITS = {
    DeviceType.SENSOR_KW: "kW",
    DeviceType.SENSOR_KWH: "kWh",
    DeviceType.SENSOR_PERCENTAGE: "%",
    DeviceType.SENSOR_RATIO: "%",
    DeviceType.SENSOR_VOLTAGE: "V",
    DeviceType.SENSOR_CURRENT: "A",
    DeviceType.SENSOR_FREQUENCY: "Hz",
    DeviceType.SENSOR_TEMPERATURE: "°C",
    DeviceType.SENSOR_RESISTANCE: "MΩ",
    DeviceType.SENSOR_POWER_FACTOR: "",
    DeviceType.SENSOR_VAR: "var",
    DeviceType.SENSOR_KG: "kg",
    DeviceType.SENSOR_COUNT: "",
    DeviceType.SENSOR_MINUTES: "min",
}


class ENERGY_BALANCE_CALL_TYPE(StrEnum):
    """Energy balance call types."""

    DAY = "2"
    PREVIOUS_MONTH = "3"
    MONTH = "4"
    YEAR = "5"
    LIFETIME = "6"


@dataclass
class Device:
    """FusionSolarAPI device."""

    device_id: str
    device_unique_id: str
    device_type: DeviceType
    name: str
    state: float | int | datetime | str
    icon: str
    dn: str | None = None


@dataclass
class InverterInfo:
    """Metadata for a single inverter, keyed by its DN."""

    dn: str
    # DN as reported by the device status endpoint. Usually identical to `dn`
    # (discovered from the flow nodes); kept separate because it is what the
    # Home Assistant device identifier has always been built from.
    canonical_dn: str | None = None
    device_id: str | None = None
    parent_dn: str | None = None
    name: str | None = None
    model: str | None = None
    software_version: str | None = None
    serial_number: str | None = None