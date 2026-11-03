"""Fusion Solar App API."""

import logging
import threading
from datetime import datetime
from typing import Any, Dict, Optional

import requests

from ..const import DOMAIN
from ..utils import extract_numeric
from .auth import FusionSolarAuthMixin, normalize_fusionsolar_host
from .battery import FusionSolarBatteryMixin
from .energy_balance import FusionSolarEnergyBalanceMixin
from .exceptions import (
    APIAuthCaptchaError,
    APIAuthError,
    APIConnectionError,
    APIDataStructureError,
)
from .installation import FusionSolarInstallationMixin
from .inverter import FusionSolarInverterMixin
from .models import Device, DeviceType, ENERGY_BALANCE_CALL_TYPE, InverterInfo
from .optimizer import FusionSolarOptimizerMixin
from .social import FusionSolarSocialMixin
from .station import FusionSolarStationMixin
from .power_sensor import FusionSolarPowerSensorMixin


_LOGGER = logging.getLogger(__name__)


class FusionSolarAPI(
    FusionSolarAuthMixin,
    FusionSolarStationMixin,
    FusionSolarBatteryMixin,
    FusionSolarInverterMixin,
    FusionSolarSocialMixin,
    FusionSolarEnergyBalanceMixin,
    FusionSolarInstallationMixin,
    FusionSolarPowerSensorMixin,
    FusionSolarOptimizerMixin,
):
    """Class for Fusion Solar App API."""

    def __init__(self, user: str, pwd: str, login_host: str, captcha_input: str) -> None:
        """Initialise."""
        self.user = user
        self.pwd = pwd
        self.captcha_input = captcha_input
        self.captcha_img = None
        self.station = None
        self.station_name = None

        # Inverters keyed by DN, in discovery order.
        self.inverters: Dict[str, InverterInfo] = {}

        self.battery_dn = None
        self.battery_dns: list[str] = []
        # Parent inverter DNs are discovered separately from the station-wide
        # energy-flow graph, whose storage node intentionally aggregates batteries.
        self._battery_parent_dns: dict[str, str] = {}
        self._battery_entity_dn: str | None = None
        self.battery_model = None
        self.battery_serial_number = None
        self.battery_software_version = None
        self.battery_capacity = None

        self.power_sensor_dn = None
        self.power_sensor_name = None
        self.power_sensor_model = None
        self.power_sensor_serial_number = None
        self.power_sensor_software_version = None
        self.power_sensor_usage = None

        self.login_host = normalize_fusionsolar_host(login_host)
        self.data_host = None
        self.dp_session = ""
        self.connected: bool = False
        self.last_session_time: datetime | None = None
        # Session renewal is owned by the coordinator, never a background thread.
        self._closed = False
        self.csrf = None
        self.csrf_time = None
        self.request_timeout = 20
        self._session_lock = threading.RLock()
        self.session = requests.Session()
        self.session.cookies.set("locale", "en-us")

    @property
    def controller_name(self) -> str:
        """Return the name of the controller."""
        return DOMAIN

    def _create_dynamic_device(
        self,
        device_id: str,
        device_type: DeviceType,
        raw_value: Any,
        icon: str,
        dn: str | None = None,
    ) -> Device | None:
        """Create a dynamic device entity from a raw API value."""
        if device_type == DeviceType.SENSOR_TEXT:
            if raw_value is None:
                return None
            state = str(raw_value)
        elif device_type == DeviceType.SENSOR_PERCENTAGE:
            if raw_value in ("", "--", "null", None):
                return None
            state = int(round(extract_numeric(raw_value)))
        else:
            if raw_value in ("", "--", "null", None):
                return None
            state = round(float(extract_numeric(raw_value)), 4)

        return Device(
            device_id=device_id,
            device_unique_id=self.get_device_unique_id(device_id, device_type, dn=dn),
            device_type=device_type,
            name=self.get_device_name(device_id),
            state=state,
            icon=icon,
            dn=dn,
        )

    @staticmethod
    def sanitize_id_segment(value: str) -> str:
        """Sanitize a value for use as a unique ID segment."""
        return (
            str(value)
            .lower()
            .replace(" ", "_")
            .replace(":", "_")
            .replace("/", "_")
        )

    def get_device_unique_id(
        self,
        device_id: str,
        device_type: DeviceType,
        dn: str | None = None,
    ) -> str:
        """Return the unique ID for a device.

        When a device DN is given, it is inserted as an ``inv_<dn>`` scope so
        the same device_id stays unique across multiple inverters.
        """
        station_suffix = ""
        if self.station:
            station_suffix = f"_{self.sanitize_id_segment(self.station)}"

        dn_suffix = ""
        if dn:
            dn_suffix = f"_inv_{self.sanitize_id_segment(dn)}"

        return (
            f"{self.controller_name}{station_suffix}{dn_suffix}"
            f"_{device_id.lower().replace(' ', '_')}"
        )

    def get_device_name(self, device_id: str) -> str:
        """Return the device name."""
        return device_id

    def get_device_value(
        self,
        device_id: str,
        device_type: DeviceType,
        output: Dict[str, Optional[float | str]],
        default: int = 0,
    ) -> float | int | datetime | str:
        """Return the normalized device value for the requested entity."""
        if device_type == DeviceType.SENSOR_TIME:
            _LOGGER.debug(
                "%s: Value being returned is datetime: %s",
                device_id,
                self.last_session_time,
            )
            return self.last_session_time

        output_key = device_id.lower().replace(" ", "_")
        if output_key not in output:
            raise KeyError(f"'{device_id}' not found.")

        value = output[output_key]
        if value is None or value == "None":
            return default if default != 0 else None

        if device_type == DeviceType.SENSOR_TEXT:
            return str(value)

        if device_type == DeviceType.SENSOR_PERCENTAGE:
            return int(float(value))

        if device_type == DeviceType.SENSOR_COUNT:
            return int(round(float(value)))

        if device_type in (
            DeviceType.SENSOR_KW,
            DeviceType.SENSOR_KWH,
            DeviceType.SENSOR_RATIO,
            DeviceType.SENSOR_VOLTAGE,
            DeviceType.SENSOR_CURRENT,
            DeviceType.SENSOR_FREQUENCY,
            DeviceType.SENSOR_TEMPERATURE,
            DeviceType.SENSOR_RESISTANCE,
            DeviceType.SENSOR_POWER_FACTOR,
            DeviceType.SENSOR_KG,
        ):
            decimals = 2 if device_type == DeviceType.SENSOR_RATIO else 4
            _LOGGER.debug("%s: Value being returned is float: %s", device_id, value)
            return round(float(value), decimals)

        return value

    def close(self) -> None:
        """Release local HTTP resources; run in the executor, not the event loop.

        No server-side logout is sent: a config flow may have handed its token
        to a coordinator using a separate HTTP session.
        """
        with self._session_lock:
            if self._closed:
                return
            self._closed = True
            self.connected = False
            self.dp_session = ""
            self.csrf = None
            self.csrf_time = None
            self.session.close()

    def logout(self) -> bool:
        """Disconnect and release the HTTP session, idempotently."""
        self.close()
        return True
