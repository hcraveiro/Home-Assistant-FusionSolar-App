from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.components.recorder import get_instance
from homeassistant.components.recorder.history import get_significant_states
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .api import APIAuthCaptchaError, APIAuthError, Device, DeviceType, FusionSolarAPI
from .const import (
    CAPTCHA_INPUT,
    CONF_STATION_DN,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    FUSION_SOLAR_HOST,
)

_LOGGER = logging.getLogger(__name__)


FORECAST_DEBUG_ENABLED = False
FORECAST_CACHE_ALGORITHM_VERSION = 5
FORECAST_OUTLIER_FILTER_MIN_SAMPLES = 4
FORECAST_OUTLIER_FILTER_MIN_POSITIVE_SAMPLES = 3
FORECAST_OUTLIER_FILTER_MIN_DELTA_KWH = 0.005
FORECAST_OUTLIER_FILTER_LOW_FACTOR = 0.35
FORECAST_OUTLIER_FILTER_HIGH_FACTOR = 2.25
FORECAST_OUTLIER_FILTER_MIN_UPPER_MARGIN_KWH = 0.05
FORECAST_DELTA_SMOOTHING_RADIUS = 6
FORECAST_DELTA_SMOOTHING_PASSES = 3
FORECAST_CACHE_STORAGE_VERSION = 1
FORECAST_CACHE_STORAGE_KEY = f"{DOMAIN}_panel_production_forecast_cache"
FORECAST_SOURCE_DEVICE_ID = "Panel Production Today"
FORECAST_STEP_MINUTES = 5
FORECAST_DAYS = 7
FORECAST_LOOKBACKS = (
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(hours=1),
    timedelta(hours=3),
    timedelta(hours=6),
)
FORECAST_MAX_LOOKBACK = FORECAST_LOOKBACKS[-1]
FORECAST_WEIGHTS = [0.40, 0.25, 0.15, 0.10, 0.05, 0.03, 0.02]

@dataclass
class FusionSolarForecastData:
    """Class to hold forecast data."""

    source_entity_id: str | None = None
    forecasted_today: float | None = None
    remaining_today: float | None = None
    actual_now_value: float | None = None
    correction_factor: float | None = None
    curve: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str | None = None
    step_minutes: int | None = None
    days: int | None = None
    start_of_day: str | None = None
    end_of_day: str | None = None
    debug: dict[str, Any] = field(default_factory=dict)


@dataclass
class FusonSolarAPIData:
    """Class to hold api data."""

    controller_name: str
    devices: list[Device]
    forecast: FusionSolarForecastData | None = None


class FusionSolarCoordinator(DataUpdateCoordinator):
    """My coordinator."""

    data: FusonSolarAPIData

    def __init__(self, hass: HomeAssistant, config_entry: ConfigEntry) -> None:
        """Initialize coordinator."""
        self.user = config_entry.data[CONF_USERNAME]
        self.pwd = config_entry.data[CONF_PASSWORD]
        self.login_host = config_entry.data[FUSION_SOLAR_HOST]
        self.captcha_input = None
    
        self.poll_interval = config_entry.options.get(
            CONF_SCAN_INTERVAL,
            DEFAULT_SCAN_INTERVAL,
        )
    
        self.lastAuthentication = None
    
        self.forecast_step_minutes = FORECAST_STEP_MINUTES
        self.forecast_days = FORECAST_DAYS
    
        self._forecast_cache_loaded = False
        self._forecast_cache: dict[str, Any] | None = None
        self._forecast_store = Store(
            hass,
            FORECAST_CACHE_STORAGE_VERSION,
            f"{FORECAST_CACHE_STORAGE_KEY}_{config_entry.entry_id}",
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

    async def async_update_data(self) -> FusonSolarAPIData:
        """Fetch data from API endpoint."""
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
    
        forecast: FusionSolarForecastData | None = None
        try:
            forecast = await self._build_panel_production_forecast(devices)
        except Exception as ex:
            _LOGGER.warning(
                "Failed to build forecast data: %s",
                ex,
                exc_info=True,
            )
    
        return FusonSolarAPIData(
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
    
    
    def _resolve_sensor_entity_id(self, device: Device) -> str | None:
        """Resolve the entity_id for a device sensor using the entity registry."""
        entity_registry = er.async_get(self.hass)
        entity_unique_id = f"{DOMAIN}-{device.device_unique_id}"
    
        return entity_registry.async_get_entity_id(
            "sensor",
            DOMAIN,
            entity_unique_id,
        )
    
    
    async def _get_history_states(
        self,
        entity_id: str,
        start_dt: datetime,
        end_dt: datetime,
    ) -> list[Any]:
        """Fetch recorder history states for the given entity."""
        def _query() -> dict[str, list[Any]]:
            return get_significant_states(
                self.hass,
                start_dt,
                end_dt,
                [entity_id],
                include_start_time_state=True,
                significant_changes_only=False,
            )
    
        states = await get_instance(self.hass).async_add_executor_job(_query)
        return states.get(entity_id, [])
    
    
    def _build_history_index(
        self,
        history_states: list[Any],
    ) -> tuple[list[datetime], list[float]]:
        """Build an indexed numeric history representation."""
        timestamps: list[datetime] = []
        values: list[float] = []
    
        for state_obj in history_states:
            if state_obj.state in ("unknown", "unavailable"):
                continue
    
            try:
                value = float(state_obj.state)
            except (TypeError, ValueError):
                continue
    
            timestamps.append(state_obj.last_changed)
            values.append(value)
    
        return timestamps, values
    
    
    def _get_numeric_value_at(
        self,
        timestamps: list[datetime],
        values: list[float],
        target_dt: datetime,
    ) -> float | None:
        """Return the latest valid numeric value within the allowed lookback."""
        sample = self._get_numeric_sample_at(
            timestamps,
            values,
            target_dt,
            FORECAST_MAX_LOOKBACK,
        )
    
        if sample is None:
            return None
    
        return sample[1]
    
    
    async def _build_panel_production_forecast(
        self,
        devices: list[Device],
    ) -> FusionSolarForecastData | None:
        """Build forecast data for panel production today."""
        source_device = self._get_forecast_source_device(devices)
        if source_device is None:
            _LOGGER.debug("Forecast source device not found")
            return None
    
        now = dt_util.now()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)
    
        try:
            actual_now_value = float(source_device.state)
        except (TypeError, ValueError):
            actual_now_value = None
    
        forecast = FusionSolarForecastData(
            source_entity_id=None,
            forecasted_today=None,
            remaining_today=None,
            actual_now_value=(
                round(actual_now_value, 3)
                if actual_now_value is not None
                else None
            ),
            correction_factor=1.0,
            curve=[],
            generated_at=now.isoformat(),
            step_minutes=self.forecast_step_minutes,
            days=self.forecast_days,
            start_of_day=start_of_day.isoformat(),
            end_of_day=end_of_day.isoformat(),
        )
    
        entity_id = self._resolve_sensor_entity_id(source_device)
        forecast.source_entity_id = entity_id
    
        if entity_id is None:
            _LOGGER.debug(
                "Forecast source entity_id could not be resolved yet for %s",
                source_device.device_id,
            )
            return forecast
    
        history_start = (
            start_of_day
            - timedelta(days=self.forecast_days)
            - FORECAST_MAX_LOOKBACK
        )
    
        history_states = await self._get_history_states(
            entity_id,
            history_start,
            now,
        )
        timestamps, values = self._build_history_index(history_states)
    
        if not timestamps or not values:
            _LOGGER.debug(
                "No recorder history found for forecast source entity %s",
                entity_id,
            )
    
            if actual_now_value is not None:
                forecast.curve = [
                    {
                        "time": now.isoformat(),
                        "value": round(actual_now_value, 3),
                        "delta_kwh": 0,
                        "power_w": 0,
                    }
                ]
                forecast.forecasted_today = round(actual_now_value, 3)
                forecast.remaining_today = 0.0
    
            return forecast
    
        cache = await self._async_ensure_forecast_cache(
            source_entity_id=entity_id,
            now=now,
            start_of_day=start_of_day,
            end_of_day=end_of_day,
            timestamps=timestamps,
            values=values,
        )
    
        delta_curve = []
        if cache is not None and isinstance(cache.get("delta_curve"), list):
            delta_curve = cache["delta_curve"]
    
        curve: list[dict[str, Any]] = []
    
        total_steps = int(
            (end_of_day - start_of_day).total_seconds()
            / 60
            / self.forecast_step_minutes
        )
    
        # -------------------------
        # Real curve until now
        # -------------------------
        previous_value: float | None = None
    
        for step_index in range(total_steps + 1):
            point_dt = start_of_day + timedelta(
                minutes=step_index * self.forecast_step_minutes
            )
    
            if point_dt > now:
                break
    
            current_value = 0.0 if previous_value is None else previous_value
    
            sample = self._get_numeric_sample_at(
                timestamps,
                values,
                point_dt,
                FORECAST_MAX_LOOKBACK,
            )
    
            if sample is not None:
                sample_dt, sample_value = sample
    
                if sample_dt.date() < start_of_day.date():
                    current_value = 0.0
                else:
                    current_value = float(sample_value)
    
            if point_dt == start_of_day:
                current_value = 0.0
    
            if previous_value is not None and current_value < previous_value:
                current_value = previous_value
    
            if previous_value is None:
                delta_kwh = 0.0
                power_w = 0.0
            else:
                delta_kwh = max(0.0, current_value - previous_value)
                hours = self.forecast_step_minutes / 60
                power_w = (delta_kwh / hours) * 1000 if hours > 0 else 0.0
    
            previous_value = current_value
    
            curve.append(
                {
                    "time": point_dt.isoformat(),
                    "value": round(current_value, 3),
                    "delta_kwh": round(delta_kwh, 4),
                    "power_w": max(0, round(power_w, 0)),
                    "source": "actual",
                }
            )
    
        if actual_now_value is not None:
            if previous_value is not None and actual_now_value < previous_value:
                actual_now_value = previous_value
    
            current_power = curve[-1]["power_w"] if curve else 0
    
            curve.append(
                {
                    "time": now.isoformat(),
                    "value": round(actual_now_value, 3),
                    "delta_kwh": 0,
                    "power_w": current_power,
                    "source": "actual_now",
                }
            )
    
            current_value = actual_now_value
        else:
            current_value = previous_value
    
        # -------------------------
        # Forecast from cached deltas
        # -------------------------
        minutes_since_start = (now - start_of_day).total_seconds() / 60
        next_step_index = int(minutes_since_start // self.forecast_step_minutes) + 1
    
        remaining_delta_total = 0.0
    
        for step_index in range(next_step_index, total_steps + 1):
            point_dt = start_of_day + timedelta(
                minutes=step_index * self.forecast_step_minutes
            )
    
            cached_item = None
            if step_index < len(delta_curve):
                cached_item = delta_curve[step_index]
    
            if isinstance(cached_item, dict):
                try:
                    delta_kwh = float(cached_item.get("delta_kwh", 0.0))
                except (TypeError, ValueError):
                    delta_kwh = 0.0
    
                try:
                    power_w = float(cached_item.get("power_w", 0.0))
                except (TypeError, ValueError):
                    power_w = 0.0
            else:
                delta_kwh = 0.0
                power_w = 0.0
    
            delta_kwh = max(0.0, delta_kwh)
            remaining_delta_total += delta_kwh
    
            if current_value is None:
                current_value = actual_now_value if actual_now_value is not None else 0.0
    
            current_value += delta_kwh
    
            curve.append(
                {
                    "time": point_dt.isoformat(),
                    "value": round(current_value, 3),
                    "delta_kwh": round(delta_kwh, 4),
                    "power_w": max(0, round(power_w, 0)),
                    "source": "forecast",
                }
            )
    
        # -------------------------
        # Summary
        # -------------------------
        if actual_now_value is not None:
            forecasted_today = round(actual_now_value + remaining_delta_total, 3)
            forecasted_today = max(forecasted_today, actual_now_value)
            remaining_today = round(forecasted_today - actual_now_value, 3)
        else:
            forecasted_today = curve[-1]["value"] if curve else None
            remaining_today = None
    
        if FORECAST_DEBUG_ENABLED:
            forecast.debug = self._build_forecast_debug_summary(
                timestamps=timestamps,
                values=values,
                now=now,
                start_of_day=start_of_day,
                end_of_day=end_of_day,
                delta_curve=delta_curve,
                cache=cache,
            )
        else:
            forecast.debug = {}
        
        forecast.curve = curve
        forecast.forecasted_today = forecasted_today
        forecast.remaining_today = remaining_today
        forecast.correction_factor = 1.0
    
        _LOGGER.info(
            "[fusion_solar.forecast] generated %s points for %s "
            "(cache_date=%s, remaining=%.3f)",
            len(curve),
            entity_id,
            cache.get("date") if isinstance(cache, dict) else None,
            remaining_today if remaining_today is not None else 0,
        )
    
        return forecast
    
    def _get_numeric_sample_at(
        self,
        timestamps: list[datetime],
        values: list[float],
        target_dt: datetime,
        max_age: timedelta,
    ) -> tuple[datetime, float] | None:
        """Return the latest valid numeric sample within the allowed lookback."""
        if not timestamps:
            return None
    
        index = bisect_right(timestamps, target_dt) - 1
        if index < 0:
            return None
    
        state_dt = timestamps[index]
        state_value = values[index]
    
        age = target_dt - state_dt
        if age < timedelta(0):
            return None
    
        if age > max_age:
            return None
    
        return state_dt, state_value
    
    async def _async_load_forecast_cache(self) -> None:
        """Load the persisted forecast cache once."""
        if self._forecast_cache_loaded:
            return
    
        try:
            stored_cache = await self._forecast_store.async_load()
        except Exception as ex:
            _LOGGER.warning("Failed to load forecast cache: %s", ex)
            stored_cache = None
    
        self._forecast_cache = stored_cache if isinstance(stored_cache, dict) else None
        self._forecast_cache_loaded = True
    
        if self._forecast_cache is not None:
            _LOGGER.debug(
                "Loaded forecast cache for date %s",
                self._forecast_cache.get("date"),
            )
    
    async def _async_save_forecast_cache(self) -> None:
        """Persist the current forecast cache."""
        if self._forecast_cache is None:
            return
    
        try:
            await self._forecast_store.async_save(self._forecast_cache)
            _LOGGER.debug(
                "Saved forecast cache for date %s",
                self._forecast_cache.get("date"),
            )
        except Exception as ex:
            _LOGGER.warning("Failed to save forecast cache: %s", ex)
            
    def _is_forecast_cache_valid(
        self,
        cache: dict[str, Any] | None,
        cache_date: str,
        source_entity_id: str,
    ) -> bool:
        """Return whether the forecast cache can be used."""
        if not isinstance(cache, dict):
            return False
    
        if cache.get("date") != cache_date:
            return False
    
        if cache.get("source_entity_id") != source_entity_id:
            return False
    
        if cache.get("step_minutes") != self.forecast_step_minutes:
            return False
    
        if cache.get("days") != self.forecast_days:
            return False
    
        if cache.get("algorithm_version") != FORECAST_CACHE_ALGORITHM_VERSION:
            return False
    
        delta_curve = cache.get("delta_curve")
        if not isinstance(delta_curve, list) or not delta_curve:
            return False
    
        return True
        
    def _calculate_weighted_historical_delta(
        self,
        timestamps: list[datetime],
        values: list[float],
        point_dt: datetime,
    ) -> float:
        """Calculate weighted historical delta for a single forecast step."""
        expected_delta_gap = timedelta(minutes=self.forecast_step_minutes)
        max_delta_sample_age = expected_delta_gap * 2
        max_delta_gap = expected_delta_gap * 3
    
        weighted_deltas: list[tuple[float, float]] = []
    
        for day_offset in range(1, self.forecast_days + 1):
            if day_offset > len(FORECAST_WEIGHTS):
                break
    
            past_t2 = point_dt - timedelta(days=day_offset)
            past_t1 = past_t2 - timedelta(minutes=self.forecast_step_minutes)
    
            sample_1 = self._get_numeric_sample_at(
                timestamps,
                values,
                past_t1,
                max_delta_sample_age,
            )
            sample_2 = self._get_numeric_sample_at(
                timestamps,
                values,
                past_t2,
                max_delta_sample_age,
            )
    
            if sample_1 is None or sample_2 is None:
                continue
    
            sample_1_dt, v1 = sample_1
            sample_2_dt, v2 = sample_2
    
            sample_gap = sample_2_dt - sample_1_dt
    
            if sample_gap < timedelta(0):
                continue
    
            delta = v2 - v1
    
            if delta < 0:
                continue
    
            if sample_gap == timedelta(0):
                delta = 0.0
            elif sample_gap > max_delta_gap:
                continue
            elif sample_gap > expected_delta_gap:
                delta = delta * (
                    expected_delta_gap.total_seconds()
                    / sample_gap.total_seconds()
                )
    
            weighted_deltas.append(
                (delta, FORECAST_WEIGHTS[day_offset - 1])
            )
    
        if not weighted_deltas:
            return 0.0
    
        total_weight = sum(weight for _, weight in weighted_deltas)
        return max(
            0.0,
            sum(delta * weight for delta, weight in weighted_deltas) / total_weight,
        )
        
    def _build_forecast_delta_cache(
        self,
        timestamps: list[datetime],
        values: list[float],
        start_of_day: datetime,
        end_of_day: datetime,
    ) -> list[dict[str, Any]]:
        """Build the daily forecast delta cache."""
        total_steps = int(
            (end_of_day - start_of_day).total_seconds()
            / 60
            / self.forecast_step_minutes
        )
    
        historical_delta_curves: list[tuple[list[float], float]] = []
    
        for day_offset in range(1, self.forecast_days + 1):
            if day_offset > len(FORECAST_WEIGHTS):
                break
    
            historical_day_start = start_of_day - timedelta(days=day_offset)
            historical_day_end = end_of_day - timedelta(days=day_offset)
    
            historical_delta_curve = self._build_historical_day_delta_curve(
                timestamps,
                values,
                historical_day_start,
                historical_day_end,
            )
    
            if historical_delta_curve is None:
                continue
    
            historical_delta_curves.append(
                (
                    historical_delta_curve,
                    FORECAST_WEIGHTS[day_offset - 1],
                )
            )
    
        raw_delta_values: list[float] = []
    
        for step_index in range(total_steps + 1):
            if step_index == 0:
                delta_kwh = 0.0
            else:
                weighted_deltas: list[tuple[float, float]] = []
    
                for historical_delta_curve, weight in historical_delta_curves:
                    if step_index >= len(historical_delta_curve):
                        continue
    
                    weighted_deltas.append(
                        (
                            historical_delta_curve[step_index],
                            weight,
                        )
                    )
    
                if weighted_deltas:
                    delta_kwh = self._calculate_robust_weighted_delta(
                        weighted_deltas
                    )
                else:
                    delta_kwh = 0.0
    
            raw_delta_values.append(max(0.0, delta_kwh))
    
        smoothed_delta_values = self._smooth_delta_values(raw_delta_values)
    
        delta_curve: list[dict[str, Any]] = []
    
        for step_index, delta_kwh in enumerate(smoothed_delta_values):
            point_dt = start_of_day + timedelta(
                minutes=step_index * self.forecast_step_minutes
            )
    
            hours = self.forecast_step_minutes / 60
            power_w = (delta_kwh / hours) * 1000 if hours > 0 else 0.0
    
            delta_curve.append(
                {
                    "time": point_dt.isoformat(),
                    "delta_kwh": round(delta_kwh, 4),
                    "power_w": max(0, round(power_w, 0)),
                }
            )
    
        raw_total = sum(raw_delta_values)
        smoothed_total = sum(smoothed_delta_values)
    
        _LOGGER.info(
            "[fusion_solar.forecast] built robust smoothed delta cache "
            "(raw_total=%.3f, smoothed_total=%.3f, curves=%s)",
            raw_total,
            smoothed_total,
            len(historical_delta_curves),
        )
    
        return delta_curve
        
    async def _async_ensure_forecast_cache(
        self,
        source_entity_id: str,
        now: datetime,
        start_of_day: datetime,
        end_of_day: datetime,
        timestamps: list[datetime],
        values: list[float],
    ) -> dict[str, Any] | None:
        """Ensure there is a valid forecast cache for today."""
        await self._async_load_forecast_cache()
    
        cache_date = now.date().isoformat()
    
        if self._is_forecast_cache_valid(
            self._forecast_cache,
            cache_date,
            source_entity_id,
        ):
            return self._forecast_cache
    
        _LOGGER.info(
            "Building new forecast cache for %s using %s days",
            cache_date,
            self.forecast_days,
        )
    
        delta_curve = self._build_forecast_delta_cache(
            timestamps,
            values,
            start_of_day,
            end_of_day,
        )
    
        has_forecast_data = any(
            float(item.get("delta_kwh", 0) or 0) > 0
            for item in delta_curve
            if isinstance(item, dict)
        )
    
        if not has_forecast_data:
            _LOGGER.warning(
                "Forecast cache was not saved because no useful deltas were generated "
                "for %s. The next coordinator update will try again.",
                cache_date,
            )
    
            self._forecast_cache = None
            return None
    
        self._forecast_cache = {
            "date": cache_date,
            "source_entity_id": source_entity_id,
            "step_minutes": self.forecast_step_minutes,
            "days": self.forecast_days,
            "algorithm_version": FORECAST_CACHE_ALGORITHM_VERSION,
            "generated_at": now.isoformat(),
            "delta_curve": delta_curve,
        }
    
        await self._async_save_forecast_cache()
    
        return self._forecast_cache
        
    def _extract_day_samples(
        self,
        timestamps: list[datetime],
        values: list[float],
        day_start: datetime,
        day_end: datetime,
    ) -> tuple[list[datetime], list[float]]:
        """Extract monotonic samples for a single day."""
        sample_times: list[datetime] = []
        sample_values: list[float] = []
    
        running_max = 0.0
    
        for state_dt, state_value in zip(timestamps, values, strict=False):
            if not (day_start <= state_dt < day_end):
                continue
    
            try:
                value = float(state_value)
            except (TypeError, ValueError):
                continue
    
            if value < 0:
                continue
    
            if value < running_max:
                value = running_max
            else:
                running_max = value
    
            sample_times.append(state_dt)
            sample_values.append(value)
    
        return sample_times, sample_values
        
    def _interpolate_daily_value(
        self,
        sample_times: list[datetime],
        sample_values: list[float],
        target_dt: datetime,
        day_start: datetime,
        day_end: datetime,
        day_max_value: float,
    ) -> float | None:
        """Interpolate a daily cumulative value at the target time."""
        if not sample_times or not sample_values:
            return None
    
        if target_dt <= day_start:
            return 0.0
    
        if target_dt >= day_end:
            return day_max_value
    
        index = bisect_right(sample_times, target_dt) - 1
    
        if index < 0:
            return 0.0
    
        if index >= len(sample_times) - 1:
            return sample_values[index]
    
        previous_time = sample_times[index]
        previous_value = sample_values[index]
        next_time = sample_times[index + 1]
        next_value = sample_values[index + 1]
    
        if target_dt == previous_time:
            return previous_value
    
        if next_time <= previous_time:
            return previous_value
    
        interval_seconds = (next_time - previous_time).total_seconds()
        elapsed_seconds = (target_dt - previous_time).total_seconds()
    
        if interval_seconds <= 0:
            return previous_value
    
        ratio = max(0.0, min(1.0, elapsed_seconds / interval_seconds))
    
        return previous_value + ((next_value - previous_value) * ratio)
        
    def _build_historical_day_delta_curve(
        self,
        timestamps: list[datetime],
        values: list[float],
        day_start: datetime,
        day_end: datetime,
    ) -> list[float] | None:
        """Build an interpolated delta curve for a historical day."""
        sample_times, sample_values = self._extract_day_samples(
            timestamps,
            values,
            day_start,
            day_end,
        )
    
        if not sample_times or not sample_values:
            return None
    
        day_max_value = max(sample_values)
        if day_max_value <= 0:
            return None
    
        total_steps = int(
            (day_end - day_start).total_seconds()
            / 60
            / self.forecast_step_minutes
        )
    
        delta_curve: list[float] = []
        previous_value = 0.0
    
        for step_index in range(total_steps + 1):
            point_dt = day_start + timedelta(
                minutes=step_index * self.forecast_step_minutes
            )
    
            if step_index == 0:
                current_value = 0.0
            elif step_index == total_steps:
                current_value = day_max_value
            else:
                interpolated_value = self._interpolate_daily_value(
                    sample_times,
                    sample_values,
                    point_dt,
                    day_start,
                    day_end,
                    day_max_value,
                )
    
                if interpolated_value is None:
                    current_value = previous_value
                else:
                    current_value = interpolated_value
    
            if current_value < previous_value:
                current_value = previous_value
    
            delta_kwh = max(0.0, current_value - previous_value)
            delta_curve.append(delta_kwh)
    
            previous_value = current_value
    
        return delta_curve
    
    def _smooth_delta_values(
        self,
        delta_values: list[float],
    ) -> list[float]:
        """Smooth forecast delta values while preserving the total energy."""
        if not delta_values:
            return []
    
        raw_values = [max(0.0, float(value or 0.0)) for value in delta_values]
        raw_total = sum(raw_values)
    
        if raw_total <= 0:
            return raw_values
    
        smoothed_values = raw_values[:]
    
        for _ in range(FORECAST_DELTA_SMOOTHING_PASSES):
            next_values: list[float] = []
    
            for index in range(len(smoothed_values)):
                weighted_sum = 0.0
                total_weight = 0.0
    
                for neighbour_index in range(
                    index - FORECAST_DELTA_SMOOTHING_RADIUS,
                    index + FORECAST_DELTA_SMOOTHING_RADIUS + 1,
                ):
                    if neighbour_index < 0 or neighbour_index >= len(smoothed_values):
                        continue
    
                    distance = abs(index - neighbour_index)
                    weight = FORECAST_DELTA_SMOOTHING_RADIUS + 1 - distance
    
                    weighted_sum += smoothed_values[neighbour_index] * weight
                    total_weight += weight
    
                if total_weight > 0:
                    next_values.append(weighted_sum / total_weight)
                else:
                    next_values.append(smoothed_values[index])
    
            smoothed_values = next_values
    
        smoothed_total = sum(smoothed_values)
    
        if smoothed_total <= 0:
            return raw_values
    
        scale_factor = raw_total / smoothed_total
    
        return [
            max(0.0, value * scale_factor)
            for value in smoothed_values
        ]

    def _build_forecast_debug_summary(
        self,
        timestamps: list[datetime],
        values: list[float],
        now: datetime,
        start_of_day: datetime,
        end_of_day: datetime,
        delta_curve: list[dict[str, Any]],
        cache: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Build debug information for forecast diagnostics."""
        historical_day_summaries: list[dict[str, Any]] = []
    
        def _safe_float(value: Any) -> float | None:
            """Return a float value when possible."""
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
    
        def _parse_datetime(value: Any) -> datetime | None:
            """Parse a datetime value from a cache item."""
            if value is None:
                return None
    
            parsed = dt_util.parse_datetime(str(value))
            if parsed is None:
                return None
    
            if parsed.tzinfo is None:
                parsed = dt_util.as_local(parsed)
    
            return parsed
    
        def _get_day_max_value(
            day_start: datetime,
            day_end: datetime,
        ) -> float | None:
            """Return the maximum value recorded during a day."""
            day_values: list[float] = []
    
            for state_dt, state_value in zip(timestamps, values, strict=False):
                if day_start <= state_dt < day_end:
                    day_values.append(float(state_value))
    
            if not day_values:
                return None
    
            return max(day_values)
    
        def _get_value_at_same_day_time(
            target_dt: datetime,
            day_start: datetime,
            day_end: datetime,
        ) -> float | None:
            """Return the latest value at a time, ensuring it belongs to that day."""
            sample = self._get_numeric_sample_at(
                timestamps,
                values,
                target_dt,
                FORECAST_MAX_LOOKBACK,
            )
    
            if sample is None:
                return None
    
            sample_dt, sample_value = sample
    
            if not (day_start <= sample_dt < day_end):
                return None
    
            return float(sample_value)
    
        cache_full_day_delta_total = 0.0
        cache_remaining_delta_from_now = 0.0
        cache_delta_until_now = 0.0
    
        for item in delta_curve:
            if not isinstance(item, dict):
                continue
    
            delta = _safe_float(item.get("delta_kwh")) or 0.0
            item_dt = _parse_datetime(item.get("time"))
    
            cache_full_day_delta_total += delta
    
            if item_dt is None:
                continue
    
            if item_dt > now:
                cache_remaining_delta_from_now += delta
            else:
                cache_delta_until_now += delta
    
        weighted_remaining_total = 0.0
        weighted_remaining_weight = 0.0
        weighted_end_of_day_total = 0.0
        weighted_end_of_day_weight = 0.0
        weighted_value_at_now_total = 0.0
        weighted_value_at_now_weight = 0.0
    
        for day_offset in range(1, self.forecast_days + 1):
            if day_offset > len(FORECAST_WEIGHTS):
                break
    
            weight = FORECAST_WEIGHTS[day_offset - 1]
    
            past_now = now - timedelta(days=day_offset)
            past_start_of_day = start_of_day - timedelta(days=day_offset)
            past_end_of_day = end_of_day - timedelta(days=day_offset)
    
            value_at_now = _get_value_at_same_day_time(
                past_now,
                past_start_of_day,
                past_end_of_day,
            )
    
            end_of_day_value = _get_day_max_value(
                past_start_of_day,
                past_end_of_day,
            )
    
            remaining_after_now = None
    
            if value_at_now is not None and end_of_day_value is not None:
                remaining_after_now = max(
                    0.0,
                    end_of_day_value - value_at_now,
                )
    
            if remaining_after_now is not None:
                weighted_remaining_total += remaining_after_now * weight
                weighted_remaining_weight += weight
    
            if end_of_day_value is not None:
                weighted_end_of_day_total += end_of_day_value * weight
                weighted_end_of_day_weight += weight
    
            if value_at_now is not None:
                weighted_value_at_now_total += value_at_now * weight
                weighted_value_at_now_weight += weight
    
            historical_day_summaries.append(
                {
                    "day_offset": day_offset,
                    "date": past_now.date().isoformat(),
                    "weight": weight,
                    "value_at_now": (
                        round(value_at_now, 3)
                        if value_at_now is not None
                        else None
                    ),
                    "end_of_day_value": (
                        round(end_of_day_value, 3)
                        if end_of_day_value is not None
                        else None
                    ),
                    "remaining_after_now": (
                        round(remaining_after_now, 3)
                        if remaining_after_now is not None
                        else None
                    ),
                }
            )
    
        weighted_remaining_after_now = (
            weighted_remaining_total / weighted_remaining_weight
            if weighted_remaining_weight > 0
            else None
        )
    
        weighted_end_of_day_value = (
            weighted_end_of_day_total / weighted_end_of_day_weight
            if weighted_end_of_day_weight > 0
            else None
        )
    
        weighted_value_at_now = (
            weighted_value_at_now_total / weighted_value_at_now_weight
            if weighted_value_at_now_weight > 0
            else None
        )
    
        return {
            "cache_date": cache.get("date") if isinstance(cache, dict) else None,
            "cache_generated_at": (
                cache.get("generated_at") if isinstance(cache, dict) else None
            ),
            "cache_full_day_delta_total": round(cache_full_day_delta_total, 3),
            "cache_delta_until_now": round(cache_delta_until_now, 3),
            "cache_remaining_delta_from_now": round(
                cache_remaining_delta_from_now,
                3,
            ),
            "weighted_value_at_now": (
                round(weighted_value_at_now, 3)
                if weighted_value_at_now is not None
                else None
            ),
            "weighted_end_of_day_value": (
                round(weighted_end_of_day_value, 3)
                if weighted_end_of_day_value is not None
                else None
            ),
            "weighted_remaining_after_now": (
                round(weighted_remaining_after_now, 3)
                if weighted_remaining_after_now is not None
                else None
            ),
            "historical_day_summaries": historical_day_summaries,
        }
    
    def _calculate_weighted_average_delta(
        self,
        weighted_deltas: list[tuple[float, float]],
    ) -> float:
        """Calculate a weighted average delta."""
        valid_deltas = [
            (max(0.0, float(delta)), max(0.0, float(weight)))
            for delta, weight in weighted_deltas
            if weight > 0
        ]
    
        if not valid_deltas:
            return 0.0
    
        total_weight = sum(weight for _, weight in valid_deltas)
    
        if total_weight <= 0:
            return 0.0
    
        return max(
            0.0,
            sum(delta * weight for delta, weight in valid_deltas) / total_weight,
        )


    def _calculate_median_delta(
        self,
        delta_values: list[float],
    ) -> float:
        """Calculate the median delta value."""
        if not delta_values:
            return 0.0
    
        sorted_values = sorted(delta_values)
        middle_index = len(sorted_values) // 2
    
        if len(sorted_values) % 2 == 1:
            return sorted_values[middle_index]
    
        return (
            sorted_values[middle_index - 1]
            + sorted_values[middle_index]
        ) / 2
    
    
    def _calculate_robust_weighted_delta(
        self,
        weighted_deltas: list[tuple[float, float]],
    ) -> float:
        """Calculate a robust weighted delta by excluding low and high outliers."""
        valid_deltas = [
            (max(0.0, float(delta)), max(0.0, float(weight)))
            for delta, weight in weighted_deltas
            if weight > 0
        ]
    
        if len(valid_deltas) < FORECAST_OUTLIER_FILTER_MIN_SAMPLES:
            return self._calculate_weighted_average_delta(valid_deltas)
    
        positive_delta_values = [
            delta
            for delta, _ in valid_deltas
            if delta >= FORECAST_OUTLIER_FILTER_MIN_DELTA_KWH
        ]
    
        if len(positive_delta_values) < FORECAST_OUTLIER_FILTER_MIN_POSITIVE_SAMPLES:
            return self._calculate_weighted_average_delta(valid_deltas)
    
        median_delta = self._calculate_median_delta(positive_delta_values)
    
        if median_delta <= 0:
            return self._calculate_weighted_average_delta(valid_deltas)
    
        lower_limit = median_delta * FORECAST_OUTLIER_FILTER_LOW_FACTOR
        upper_limit = max(
            median_delta * FORECAST_OUTLIER_FILTER_HIGH_FACTOR,
            median_delta + FORECAST_OUTLIER_FILTER_MIN_UPPER_MARGIN_KWH,
        )
    
        filtered_deltas = [
            (delta, weight)
            for delta, weight in valid_deltas
            if lower_limit <= delta <= upper_limit
        ]
    
        if len(filtered_deltas) < FORECAST_OUTLIER_FILTER_MIN_POSITIVE_SAMPLES:
            return self._calculate_weighted_average_delta(valid_deltas)
    
        return self._calculate_weighted_average_delta(filtered_deltas)