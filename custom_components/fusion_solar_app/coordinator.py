from __future__ import annotations

import asyncio
import time
from contextlib import nullcontext
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
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
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
    CONF_MOCK_PROFILE,
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

    def __init__(
        self, hass: HomeAssistant, config_entry: ConfigEntry,
        *, mock_profile_data: dict | None = None,
    ) -> None:
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
        # The session's thread lock protects individual executor calls, not the
        # async gaps between fetch/retry/login. Drain a whole refresh on unload.
        self._update_lock = asyncio.Lock()
    
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
            update_method=self._async_update_data_locked,
            update_interval=timedelta(seconds=self.poll_interval),
        )
    
        if CONF_MOCK_PROFILE in config_entry.data:
            if (
                mock_profile_data is None
                or mock_profile_data["id"] != config_entry.data[CONF_MOCK_PROFILE]
                or mock_profile_data["station"]["dn"] != config_entry.data.get(CONF_STATION_DN)
            ):
                raise ValueError("Mock entry/profile identity mismatch; real API fallback forbidden")
            from .mock_api import MockFusionSolarAPI

            self.api = MockFusionSolarAPI(mock_profile_data)
            # Never restore persisted account/session fields into a mock API.
            return

        if mock_profile_data is not None:
            raise ValueError("A mock backend requires an explicitly marked mock entry")
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
    
        station_data = await self.hass.async_add_executor_job(self._call_api_serialized, self.api.get_station_list)
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
        
    async def _async_update_data_locked(self) -> FusionSolarAPIData:
        """Serialize complete refreshes, including executor retry/login gaps."""
        async with self._update_lock:
            if self._shutdown_requested:
                raise UpdateFailed("FusionSolar coordinator is shutting down")
            return await self.async_update_data()

    async def async_shutdown(self) -> None:
        """Stop new HA refreshes, then drain an active refresh before API close."""
        await super().async_shutdown()
        async with self._update_lock:
            pass

    def _call_api_serialized(self, method):
        """Prevent session renewal from replacing HTTP state during a request."""
        lock = getattr(self.api, "_session_lock", None)
        with lock if lock is not None else nullcontext():
            return method()

    async def _fetch_devices_with_connection_retry(self) -> list[Device]:
        """Retry a transient connection failure once without resetting the session."""
        try:
            return await self.hass.async_add_executor_job(self._call_api_serialized, self.api.get_devices)
        except APIConnectionError as err:
            _LOGGER.warning(
                "Transient FusionSolar device fetch failure; retrying once: %s",
                err,
            )
            await self.hass.async_add_executor_job(time.sleep, 1)
            return await self.hass.async_add_executor_job(self._call_api_serialized, self.api.get_devices)

    def _restore_known_battery_dn(self) -> None:
        """Restore the battery owning legacy unscoped IDs, never registry order.

        Secondary batteries can register before the primary when its first poll
        fails. Device registration order (or even a lone registered secondary)
        therefore does not establish which battery owns the legacy entities.
        """
        if self.api.battery_dn or not self.api.station:
            return
        self.api._battery_primary_ambiguous = False
        stored_dn = self.config_entry.data.get("primary_battery_dn")
        if (
            isinstance(stored_dn, str)
            and stored_dn.strip()
            and stored_dn != "unknown_battery"
            and self.config_entry.data.get("primary_battery_station_dn") == self.api.station
        ):
            self.api.battery_dn = stored_dn
            return

        prefix = f"{DOMAIN}_{self.api.station}_battery_"
        registry = dr.async_get(self.hass)
        device_dns: dict[str, set[str]] = {}
        for device in dr.async_entries_for_config_entry(
            registry, self.config_entry.entry_id
        ):
            dns = {
                identifier[len(prefix):]
                for identifier_domain, identifier in device.identifiers
                if identifier_domain == DOMAIN and identifier.startswith(prefix)
                and identifier[len(prefix):] not in {"", "unknown_battery"}
            }
            if dns:
                device_dns[device.id] = dns

        station_suffix = self.api.sanitize_id_segment(self.api.station)
        legacy_prefixes = (
            f"{DOMAIN}-{DOMAIN}_{station_suffix}_battery_",
            f"{DOMAIN}-{DOMAIN}_battery_",  # Before station-scoped unique IDs.
        )
        station_scope = f"{DOMAIN}-{DOMAIN}_{station_suffix}_inv_"
        legacy_dns: set[str] = set()
        secondary_dns: set[str] = set()
        has_legacy_entities = False
        for entity in er.async_entries_for_config_entry(
            er.async_get(self.hass), self.config_entry.entry_id
        ):
            if entity.platform != DOMAIN:
                continue
            if entity.unique_id.startswith(legacy_prefixes):
                # These installation totals exist even on stations without a
                # battery. Only per-device telemetry can identify a primary.
                suffix = next(
                    entity.unique_id[len(prefix):] for prefix in legacy_prefixes
                    if entity.unique_id.startswith(prefix)
                )
                if suffix in {"percentage", "capacity"} or suffix.startswith(
                    ("consumption_", "injection_")
                ):
                    continue
                has_legacy_entities = True
                legacy_dns.update(device_dns.get(entity.device_id, set()))
            elif entity.unique_id.startswith(station_scope):
                secondary_dns.update(device_dns.get(entity.device_id, set()))

        candidates = set().union(*device_dns.values()) if device_dns else set()
        if len(legacy_dns) == 1:
            self.api.battery_dn = next(iter(legacy_dns))
        elif (
            not has_legacy_entities and len(candidates) == 1
            and not secondary_dns
        ):
            # Safe migration for old single-battery entries without entities.
            self.api.battery_dn = next(iter(candidates))
        elif candidates or has_legacy_entities:
            # Do not let the next flow response silently assign legacy IDs to
            # whichever battery happens to appear first. Scoped telemetry can
            # still be polled while legacy entities remain unavailable.
            self.api._battery_primary_ambiguous = True
            _LOGGER.warning(
                "Cannot safely restore the primary FusionSolar battery; "
                "preserving legacy entity identities and using DN-scoped telemetry"
            )

    def _persist_primary_battery_dn(self) -> None:
        """Save the primary before entities register, even if its telemetry failed."""
        battery_dn = self.api.battery_dn
        if (
            not isinstance(battery_dn, str) or not battery_dn.strip()
            or battery_dn == "unknown_battery" or not self.api.station
        ):
            return
        identity = {
            "primary_battery_dn": battery_dn,
            "primary_battery_station_dn": self.api.station,
        }
        if all(self.config_entry.data.get(key) == value for key, value in identity.items()):
            return
        self.hass.config_entries.async_update_entry(
            self.config_entry, data={**self.config_entry.data, **identity}
        )

    async def async_update_data(self) -> FusionSolarAPIData:
        """Fetch data from API endpoint."""
        started_at = time.monotonic()
    
        try:
            if not self.api.connected:
                _LOGGER.info("FusionSolar session not connected. Performing login.")
                await self.hass.async_add_executor_job(self._call_api_serialized, self.api.login)
    
            await self._ensure_station_dn()
            self._restore_known_battery_dn()
            devices = await self._fetch_devices_with_connection_retry()
    
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
                await self.hass.async_add_executor_job(self._call_api_serialized, self.api.reset_session)
                await self.hass.async_add_executor_job(self._call_api_serialized, self.api.login)
    
                await self._ensure_station_dn()
                devices = await self.hass.async_add_executor_job(self._call_api_serialized, self.api.get_devices)
            except APIAuthCaptchaError as captcha_err:
                raise ConfigEntryAuthFailed(
                    "Login requires CAPTCHA. Please reconfigure the integration."
                ) from captcha_err
            except APIAuthError as auth_err:
                # A stale session gets one automatic renewal. If login or the
                # required fetch still rejects it, stop polling and let HA ask
                # for credentials rather than repeating login on every poll.
                raise ConfigEntryAuthFailed(
                    "Authentication failed after session renewal. Please reauthenticate."
                ) from auth_err
            except Exception as retry_err:
                raise UpdateFailed(f"Re-login failed: {retry_err}") from retry_err
    
        except APIConnectionError as err:
            _LOGGER.warning("FusionSolar API connection error: %s", err)
            raise UpdateFailed(f"Error communicating with API: {err}") from err
    
        except Exception as err:
            _LOGGER.error("Error communicating with FusionSolar API", exc_info=True)
            raise UpdateFailed(f"Error communicating with API: {err}") from err
    
        self._persist_primary_battery_dn()

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

    def get_device_by_unique_id(self, device_unique_id: str) -> Device | None:
        """Return device by its unique id."""
        try:
            return [
                device
                for device in self.data.devices
                if device.device_unique_id == device_unique_id
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
