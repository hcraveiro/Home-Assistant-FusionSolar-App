from __future__ import annotations

import time
import logging
from dataclasses import dataclass
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    APIAuthCaptchaError,
    APIAuthError,
    APIConnectionError,
    APIDataStructureError,
    Device,
    DeviceType,
    FusionSolarAPI,
)
from .const import (
    CAPTCHA_INPUT,
    CONF_FORECAST_PROVIDER,
    CONF_SOLCAST_FORECAST_TODAY_ENTITY,
    CONF_STATION_DN,
    DEFAULT_FORECAST_PROVIDER,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    FORECAST_PROVIDER_NATIVE,
    FORECAST_PROVIDER_SOLCAST,
    FUSION_SOLAR_HOST,
)
from .forecast import (
    ForecastProvider,
    FusionSolarForecastData,
    NativeForecastBuilder,
    SolcastForecastBuilder,
)

_LOGGER = logging.getLogger(__name__)

FORECAST_SOURCE_DEVICE_ID = "Panel Production Today"

@dataclass
class FusionSolarAPIData:
    """Class to hold api data."""

    controller_name: str
    devices: list[Device]
    forecast: FusionSolarForecastData | None = None


class FusionSolarCoordinator(DataUpdateCoordinator):
    """My coordinator."""

    data: FusionSolarAPIData

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize coordinator."""
        self.config_entry = config_entry
        self.user = config_entry.data[CONF_USERNAME]
        self.pwd = config_entry.data[CONF_PASSWORD]
        self.login_host = config_entry.data[FUSION_SOLAR_HOST]
        self.captcha_input = None
    
        self.poll_interval = config_entry.options.get(
            CONF_SCAN_INTERVAL,
            DEFAULT_SCAN_INTERVAL,
        )
    
        self.lastAuthentication = None
    
        self.native_forecast_builder = NativeForecastBuilder(
            hass=hass,
            entry_id=config_entry.entry_id,
        )

        self.solcast_forecast_builder = SolcastForecastBuilder(
            hass=hass,
            forecast_entity_id_getter=self._get_solcast_forecast_today_entity,
            actual_today_kwh_getter=self._get_actual_panel_production_today,
            actual_power_kw_getter=self._get_actual_panel_production_power,
        )
    
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN} ({config_entry.unique_id})",
            update_method=self.async_update_data,
            update_interval=timedelta(seconds=self.poll_interval),
        )
    
        self.api = FusionSolarAPI(
            user=self.user,
            pwd=self.pwd,
            login_host=self.login_host,
            captcha_input=None,
        )
        self.api.station = config_entry.data.get(CONF_STATION_DN)
    
        dp_session = config_entry.data.get("dp_session")
        data_host = config_entry.data.get("data_host")
        if dp_session and data_host:
            try:
                self.api.restore_session(dp_session, data_host)
                _LOGGER.info("Restored authenticated session from config entry")
            except Exception as ex:
                _LOGGER.warning(
                    "Failed to restore session, will login fresh: %s",
                    ex,
                )
    
    async def _ensure_station_dn(self) -> None:
        """Ensure the API has a station DN configured."""
        if self.api.station:
            return
    
        _LOGGER.warning(
            "FusionSolar station DN is missing from the config entry. "
            "Trying to auto-select the first available station."
        )
    
        station_data = await self.hass.async_add_executor_job(self.api.get_station_list)
        stations = station_data.get("data", {}).get("list") or []
    
        if not stations:
            raise UpdateFailed("No FusionSolar stations were returned by the API")
    
        station_dn = stations[0].get("dn")
    
        if not station_dn:
            raise UpdateFailed("FusionSolar station list did not include a station DN")
    
        self.api.station = station_dn
    
        updated_data = {
            **self.config_entry.data,
            CONF_STATION_DN: station_dn,
        }
    
        self.hass.config_entries.async_update_entry(
            self.config_entry,
            data=updated_data,
        )
    
        _LOGGER.info(
            "Auto-selected FusionSolar station DN and stored it in the config entry"
        )
        
    async def async_update_data(self) -> FusionSolarAPIData:
        """Fetch data from API endpoint."""
        started_at = time.monotonic()
    
        try:
            if not self.api.connected:
                _LOGGER.info("FusionSolar session not connected. Performing login.")
                await self.hass.async_add_executor_job(self.api.login)
    
            await self._ensure_station_dn()
            devices = await self.hass.async_add_executor_job(self.api.get_devices)
    
        except APIAuthCaptchaError as err:
            raise ConfigEntryAuthFailed(
                "Login requires CAPTCHA. Please reconfigure the integration."
            ) from err
    
        except (APIAuthError, APIDataStructureError) as err:
            _LOGGER.warning(
                "FusionSolar session looks invalid or inconsistent (%s). "
                "Resetting the session and retrying once.",
                err,
            )
            try:
                self.api.reset_session()
                await self.hass.async_add_executor_job(self.api.login)
    
                await self._ensure_station_dn()
                devices = await self.hass.async_add_executor_job(self.api.get_devices)
            except APIAuthCaptchaError as captcha_err:
                raise ConfigEntryAuthFailed(
                    "Login requires CAPTCHA. Please reconfigure the integration."
                ) from captcha_err
            except Exception as retry_err:
                raise UpdateFailed(f"Re-login failed: {retry_err}") from retry_err
    
        except APIConnectionError as err:
            _LOGGER.warning("FusionSolar API connection error: %s", err)
            raise UpdateFailed(f"Error communicating with API: {err}") from err
    
        except Exception as err:
            _LOGGER.error("Error communicating with FusionSolar API", exc_info=True)
            raise UpdateFailed(f"Error communicating with API: {err}") from err
    
        forecast: FusionSolarForecastData | None = None
        try:
            forecast = await self._build_panel_production_forecast(devices)
        except Exception as ex:
            _LOGGER.warning(
                "Failed to build forecast data: %s",
                ex,
                exc_info=True,
            )
    
        elapsed = time.monotonic() - started_at
        _LOGGER.debug(
            "FusionSolar refresh finished successfully in %.2fs with %s devices",
            elapsed,
            len(devices),
        )
    
        return FusionSolarAPIData(
            self.api.controller_name,
            devices,
            forecast,
        )

    def get_device_by_id(
        self,
        device_type: DeviceType,
        device_id: str,
    ) -> Device | None:
        """Return device by device id."""
        try:
            return [
                device
                for device in self.data.devices
                if device.device_type == device_type and device.device_id == device_id
            ][0]
        except IndexError:
            return None
            
    def _get_forecast_source_device(self, devices: list[Device]) -> Device | None:
        """Return the source device used for forecasting."""
        for device in devices:
            if (
                device.device_id == FORECAST_SOURCE_DEVICE_ID
                and device.device_type == DeviceType.SENSOR_KWH
            ):
                return device
    
        return None
    
    
    def _get_forecast_provider(self) -> str:
        """Return the configured forecast provider."""
        provider = self.config_entry.options.get(
            CONF_FORECAST_PROVIDER,
            DEFAULT_FORECAST_PROVIDER,
        )

        if provider not in {
            FORECAST_PROVIDER_NATIVE,
            FORECAST_PROVIDER_SOLCAST,
        }:
            return DEFAULT_FORECAST_PROVIDER

        return provider

    def _get_solcast_forecast_today_entity(self) -> str | None:
        """Return the configured Solcast forecast entity."""
        entity_id = self.config_entry.options.get(CONF_SOLCAST_FORECAST_TODAY_ENTITY)

        if not isinstance(entity_id, str) or not entity_id.strip():
            return None

        return entity_id.strip()

    def _get_actual_panel_production_power(
        self,
        devices: list[Device],
    ) -> float | None:
        """Return the current FusionSolar panel production power value in kW."""
        for device in devices:
            if (
                device.device_id == "Panel Production Power"
                and device.device_type == DeviceType.SENSOR_KW
            ):
                try:
                    return float(device.state)
                except (TypeError, ValueError):
                    return None

        return None

    def _get_actual_panel_production_today(
        self,
        devices: list[Device],
    ) -> float | None:
        """Return the current FusionSolar panel production today value."""
        source_device = self._get_forecast_source_device(devices)

        if source_device is None:
            return None

        try:
            return float(source_device.state)
        except (TypeError, ValueError):
            return None

    def _get_forecast_builder(self) -> ForecastProvider:
        """Return the configured forecast builder."""
        provider = self._get_forecast_provider()

        if provider == FORECAST_PROVIDER_SOLCAST:
            return self.solcast_forecast_builder

        return self.native_forecast_builder

    async def _build_panel_production_forecast(
        self,
        devices: list[Device],
    ) -> FusionSolarForecastData | None:
        """Build forecast data for panel production today."""
        forecast_builder = self._get_forecast_builder()
        return await forecast_builder.build(devices)
