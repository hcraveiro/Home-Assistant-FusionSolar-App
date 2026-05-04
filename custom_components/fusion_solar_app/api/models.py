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
    SENSOR_TEXT = "sensor_text"
    SENSOR_KG = "sensor_kg"
    SENSOR_COUNT = "sensor_count"


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