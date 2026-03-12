"""Fusion Solar App integration using DataUpdateCoordinator."""

from dataclasses import dataclass
from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import FusionSolarAPI, APIAuthError, APIAuthCaptchaError, Device, DeviceType
from .const import DEFAULT_SCAN_INTERVAL, FUSION_SOLAR_HOST, CAPTCHA_INPUT, CONF_STATION_DN, DOMAIN

_LOGGER = logging.getLogger(__name__)


@dataclass
class FusonSolarAPIData:
    """Class to hold api data."""

    controller_name: str
    devices: list[Device]
    #device


class FusionSolarCoordinator(DataUpdateCoordinator):
    """My coordinator."""

    data: FusonSolarAPIData

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize coordinator."""

        # Set variables from values entered in config flow setup
        self.user = config_entry.data[CONF_USERNAME]
        self.pwd = config_entry.data[CONF_PASSWORD]
        self.login_host = config_entry.data[FUSION_SOLAR_HOST]
        self.captcha_input = None

        # set variables from options.  You need a default here incase options have not been set
        self.poll_interval = config_entry.options.get(
            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
        )

        self.lastAuthentication = None

        # Initialise DataUpdateCoordinator
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ({config_entry.unique_id})",
            # Method to call on every update interval.
            update_method=self.async_update_data,
            # Polling interval. Will only be polled if there are subscribers.
            # Using config option here but you can just use a value.
            update_interval=timedelta(seconds=self.poll_interval),
        )

        # Initialise your api here
        self.api = FusionSolarAPI(user=self.user, pwd=self.pwd, login_host=self.login_host, captcha_input=None)
        self.api.station = config_entry.data.get(CONF_STATION_DN)

        # Restore authenticated session from config entry if available
        dp_session = config_entry.data.get("dp_session")
        data_host = config_entry.data.get("data_host")
        if dp_session and data_host:
            try:
                self.api.restore_session(dp_session, data_host)
                _LOGGER.info("Restored authenticated session from config entry")
            except Exception as ex:
                _LOGGER.warning("Failed to restore session, will login fresh: %s", ex)

    async def async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """
        try:
            if not self.api.connected:
                await self.hass.async_add_executor_job(self.api.login)
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
        except APIAuthCaptchaError as err:
            raise ConfigEntryAuthFailed(
                "Login requires CAPTCHA. Please reconfigure the integration."
            ) from err
        except APIAuthError as err:
            _LOGGER.warning("Auth error, attempting re-login: %s", err)
            try:
                self.api.reset_session()
                await self.hass.async_add_executor_job(self.api.login)
                devices = await self.hass.async_add_executor_job(self.api.get_devices)
            except APIAuthCaptchaError as captcha_err:
                raise ConfigEntryAuthFailed(
                    "Login requires CAPTCHA. Please reconfigure the integration."
                ) from captcha_err
            except Exception as retry_err:
                raise UpdateFailed(f"Re-login failed: {retry_err}") from retry_err
        except Exception as err:
            _LOGGER.error(err)
            raise UpdateFailed(f"Error communicating with API: {err}") from err

        # What is returned here is stored in self.data by the DataUpdateCoordinator
        return FusonSolarAPIData(self.api.controller_name, devices)

    def get_device_by_id(
        self, device_type: DeviceType, device_id: int
    ) -> Device | None:
        """Return device by device id."""
        # Called by the binary sensors and sensors to get their updated data from self.data
        try:
            return [
                device
                for device in self.data.devices
                if device.device_type == device_type and device.device_id == device_id
            ][0]
        except IndexError:
            return None
