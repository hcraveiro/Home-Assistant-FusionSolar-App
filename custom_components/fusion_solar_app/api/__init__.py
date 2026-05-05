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
from .models import Device, DeviceType, ENERGY_BALANCE_CALL_TYPE
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
    
        self.inverter_dn = None
        self.inverter_name = None
        self.inverter_model = None
        self.inverter_software_version = None
        self.inverter_serial_number = None
    
        self.battery_dn = None
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
        self._session_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self.csrf = None
        self.csrf_time = None
        self.request_timeout = 20
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
            device_unique_id=self.get_device_unique_id(device_id, device_type),
            device_type=device_type,
            name=self.get_device_name(device_id),
            state=state,
            icon=icon,
        )

    def get_device_unique_id(self, device_id: str, device_type: DeviceType) -> str:
        """Return the unique ID for a device."""
        station_suffix = ""
        if self.station:
            safe = (
                str(self.station)
                .lower()
                .replace(" ", "_")
                .replace(":", "_")
                .replace("/", "_")
            )
            station_suffix = f"_{safe}"

        return f"{self.controller_name}{station_suffix}_{device_id.lower().replace(' ', '_')}"

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
            return default

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

    def logout(self) -> bool:
        """Disconnect from api."""
        self.connected = False
        self._stop_session_monitor()
        return True

    def _renew_session(self) -> None:
        """Simulate session renewal."""
        _LOGGER.info("Renewing session.")
        self.reset_session()
        try:
            self.login()
        except APIAuthCaptchaError:
            _LOGGER.error(
                "Session renewal requires CAPTCHA. "
                "Automated renewal is not possible. "
                "Please reconfigure the integration."
            )
            self.connected = False
        except Exception as ex:
            _LOGGER.error("Session renewal failed: %s", ex)
            self.connected = False

    def _session_monitor(self) -> None:
        """Monitor session and renew if needed."""
        while not self._stop_event.is_set():
            if not self.connected:
                self._renew_session()
                if not self.connected:
                    _LOGGER.warning("Session monitor stopping: renewal failed")
                    self._stop_event.set()
                    break
            self._stop_event.wait(60)

    def _start_session_monitor(self) -> None:
        """Start the session monitor thread."""
        if self._session_thread is None or not self._session_thread.is_alive():
            self._stop_event.clear()
            self._session_thread = threading.Thread(target=self._session_monitor, daemon=True)
            self._session_thread.start()

    def _stop_session_monitor(self) -> None:
        """Stop the session monitor thread."""
        self._stop_event.set()
        if (
            self._session_thread is not None
            and self._session_thread.is_alive()
            and self._session_thread is not threading.current_thread()
        ):
            self._session_thread.join()