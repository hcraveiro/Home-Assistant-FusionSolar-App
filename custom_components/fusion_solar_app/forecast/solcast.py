from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util

from ..api import Device
from ..const import FORECAST_PROVIDER_SOLCAST
from .models import FusionSolarForecastData

_LOGGER = logging.getLogger(__name__)

SOLCAST_FORECAST_STEP_MINUTES = 5
SOLCAST_FORECAST_BLEND_MINUTES = 30


class SolcastForecastBuilder:
    """Build forecast data from a Solcast forecast sensor."""

    def __init__(
        self,
        hass: HomeAssistant,
        forecast_entity_id_getter: Callable[[], str | None],
        actual_today_kwh_getter: Callable[[list[Device]], float | None],
        actual_power_kw_getter: Callable[[list[Device]], float | None],
    ) -> None:
        """Initialize the Solcast forecast builder."""
        self.hass = hass
        self._forecast_entity_id_getter = forecast_entity_id_getter
        self._actual_today_kwh_getter = actual_today_kwh_getter
        self._actual_power_kw_getter = actual_power_kw_getter

    async def build(
        self,
        devices: list[Device],
    ) -> FusionSolarForecastData | None:
        """Build forecast data from a Solcast forecast sensor."""
        forecast_entity_id = self._forecast_entity_id_getter()

        if forecast_entity_id is None:
            _LOGGER.warning(
                "Solcast forecast provider is selected but no Solcast entity is configured"
            )
            return None

        state = self.hass.states.get(forecast_entity_id)

        if state is None:
            _LOGGER.warning(
                "Configured Solcast forecast entity was not found: %s",
                forecast_entity_id,
            )
            return None

        detailed_hourly = state.attributes.get("detailedHourly")

        if not isinstance(detailed_hourly, list) or not detailed_hourly:
            _LOGGER.warning(
                "Configured Solcast forecast entity does not expose detailedHourly: %s",
                forecast_entity_id,
            )
            return None

        now = dt_util.now()
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)

        actual_today_kwh = self._actual_today_kwh_getter(devices)
        actual_power_kw = self._actual_power_kw_getter(devices)
        actual_power_w = (
            round(actual_power_kw * 1000, 0)
            if actual_power_kw is not None
            else 0
        )

        forecast = FusionSolarForecastData(
            source_entity_id=forecast_entity_id,
            provider=FORECAST_PROVIDER_SOLCAST,
            provider_entity_id=forecast_entity_id,
            forecasted_today=None,
            remaining_today=None,
            actual_now_value=(
                round(actual_today_kwh, 3)
                if actual_today_kwh is not None
                else None
            ),
            correction_factor=1.0,
            curve=[],
            generated_at=now.isoformat(),
            step_minutes=SOLCAST_FORECAST_STEP_MINUTES,
            days=None,
            start_of_day=start_of_day.isoformat(),
            end_of_day=end_of_day.isoformat(),
            estimate10_kwh=self._get_optional_float_attribute(
                state.attributes,
                "estimate10",
            ),
            estimate90_kwh=self._get_optional_float_attribute(
                state.attributes,
                "estimate90",
            ),
            confidence=None,
        )

        analysis = state.attributes.get("analysis")
        if isinstance(analysis, dict):
            forecast.confidence = self._get_optional_float_attribute(
                analysis,
                "confidence",
            )

        try:
            forecasted_today = float(state.attributes.get("estimate", state.state))
        except (TypeError, ValueError):
            forecasted_today = None

        parsed_intervals: list[tuple[datetime, float]] = []
        skipped_invalid_period_count = 0

        for item in detailed_hourly:
            if not isinstance(item, dict):
                continue

            period_start = self._parse_period_start(
                item.get("period_start"),
                start_of_day,
            )

            if period_start is None:
                skipped_invalid_period_count += 1
                continue

            if period_start < start_of_day or period_start >= end_of_day:
                continue

            try:
                interval_kwh = float(item.get("pv_estimate", 0.0))
            except (TypeError, ValueError):
                continue

            parsed_intervals.append((period_start, max(0.0, interval_kwh)))

        parsed_intervals.sort(key=lambda row: row[0])

        if not parsed_intervals:
            return None

        samples: list[tuple[datetime, float]] = [
            (period_start + timedelta(minutes=30), interval_kwh)
            for period_start, interval_kwh in parsed_intervals
        ]

        step_minutes = SOLCAST_FORECAST_STEP_MINUTES
        blend_minutes = SOLCAST_FORECAST_BLEND_MINUTES

        raw_steps: list[dict[str, Any]] = []
        target_remaining_kwh = 0.0

        for period_start, interval_kwh in parsed_intervals:
            period_end = period_start + timedelta(hours=1)

            if period_end <= now:
                continue

            effective_start = max(period_start, now)
            remaining_fraction = (
                (period_end - effective_start).total_seconds()
                / (period_end - period_start).total_seconds()
            )
            target_remaining_kwh += interval_kwh * max(0.0, remaining_fraction)

            step_start = period_start

            while step_start < period_end:
                step_end = step_start + timedelta(minutes=step_minutes)

                if step_end <= now:
                    step_start = step_end
                    continue

                point_dt = max(step_start, now)
                midpoint = point_dt + ((step_end - point_dt) / 2)

                previous_sample = samples[0]
                next_sample = samples[-1]

                for sample in samples:
                    if sample[0] <= midpoint:
                        previous_sample = sample

                    if sample[0] >= midpoint:
                        next_sample = sample
                        break

                if previous_sample[0] == next_sample[0]:
                    interpolated_power_kw = previous_sample[1]
                else:
                    total_seconds = (
                        next_sample[0] - previous_sample[0]
                    ).total_seconds()
                    elapsed_seconds = (
                        midpoint - previous_sample[0]
                    ).total_seconds()
                    position = max(0.0, min(1.0, elapsed_seconds / total_seconds))

                    interpolated_power_kw = previous_sample[1] + (
                        (next_sample[1] - previous_sample[1])
                        * self._smoothstep(position)
                    )

                if actual_power_kw is not None and point_dt <= now + timedelta(
                    minutes=blend_minutes
                ):
                    blend_position = (
                        (point_dt - now).total_seconds()
                        / (blend_minutes * 60)
                    )

                    interpolated_power_kw = (
                        actual_power_kw * (1 - self._smoothstep(blend_position))
                    ) + (
                        interpolated_power_kw * self._smoothstep(blend_position)
                    )

                step_duration_hours = (step_end - point_dt).total_seconds() / 3600

                raw_steps.append(
                    {
                        "time": point_dt,
                        "power_kw": max(0.0, interpolated_power_kw),
                        "duration_hours": max(0.0, step_duration_hours),
                    }
                )

                step_start = step_end

        smoothed_steps = self._build_smoothed_steps(raw_steps)

        raw_remaining_kwh = sum(
            step["power_kw"] * step["duration_hours"]
            for step in smoothed_steps
        )

        normalization_factor = (
            target_remaining_kwh / raw_remaining_kwh
            if raw_remaining_kwh > 0
            else 0.0
        )

        curve: list[dict[str, Any]] = []

        if actual_today_kwh is not None:
            curve.append(
                {
                    "time": now.isoformat(),
                    "value": round(actual_today_kwh, 3),
                    "delta_kwh": 0,
                    "power_w": max(0, actual_power_w),
                    "source": "actual_now",
                }
            )
            current_value = actual_today_kwh
        else:
            current_value = 0.0

        remaining_today = 0.0
        generated_step_count = 0

        for step in smoothed_steps:
            power_kw = step["power_kw"] * normalization_factor
            delta_kwh = power_kw * step["duration_hours"]

            if delta_kwh <= 0:
                continue

            current_value += delta_kwh
            remaining_today += delta_kwh
            generated_step_count += 1

            curve.append(
                {
                    "time": step["time"].isoformat(),
                    "value": round(current_value, 3),
                    "delta_kwh": round(delta_kwh, 5),
                    "power_w": round(power_kw * 1000, 0),
                    "source": "forecast",
                }
            )

        if forecasted_today is None:
            if actual_today_kwh is not None:
                forecasted_today = actual_today_kwh + remaining_today
            elif curve:
                forecasted_today = curve[-1]["value"]

        if actual_today_kwh is not None and forecasted_today is not None:
            remaining_today = max(0.0, forecasted_today - actual_today_kwh)
        elif not curve:
            remaining_today = None

        forecast.curve = curve
        forecast.forecasted_today = (
            round(forecasted_today, 3)
            if forecasted_today is not None
            else None
        )
        forecast.remaining_today = (
            round(remaining_today, 3)
            if remaining_today is not None
            else None
        )
        forecast.debug = {
            "provider": FORECAST_PROVIDER_SOLCAST,
            "solcast_entity_id": forecast_entity_id,
            "valid_interval_count": len(parsed_intervals),
            "generated_step_count": generated_step_count,
            "skipped_invalid_period_count": skipped_invalid_period_count,
            "source_state": state.state,
            "source_unit_of_measurement": state.attributes.get("unit_of_measurement"),
            "data_correct": state.attributes.get("dataCorrect"),
            "actual_power_kw": actual_power_kw,
            "interpolation": "smoothstep_between_hourly_centers_with_moving_average",
            "normalization_factor": round(normalization_factor, 5),
            "target_remaining_kwh": round(target_remaining_kwh, 5),
            "raw_remaining_kwh": round(raw_remaining_kwh, 5),
        }

        _LOGGER.info(
            "[fusion_solar.forecast] generated Solcast forecast from %s "
            "(forecasted=%.3f, remaining=%.3f, intervals=%s, steps=%s, skipped_invalid_periods=%s)",
            forecast_entity_id,
            forecast.forecasted_today if forecast.forecasted_today is not None else 0,
            forecast.remaining_today if forecast.remaining_today is not None else 0,
            len(parsed_intervals),
            generated_step_count,
            skipped_invalid_period_count,
        )

        return forecast

    def _get_optional_float_attribute(
        self,
        attributes: dict[str, Any],
        key: str,
    ) -> float | None:
        """Return an optional float attribute value."""
        try:
            value = attributes.get(key)
            if value is None:
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _parse_period_start(
        self,
        period_start_raw: Any,
        local_timezone_source: datetime,
    ) -> datetime | None:
        """Parse a Solcast period start value."""
        if isinstance(period_start_raw, datetime):
            period_start = period_start_raw
        elif isinstance(period_start_raw, str):
            period_start = dt_util.parse_datetime(period_start_raw)
        else:
            return None

        if period_start is None:
            return None

        if period_start.tzinfo is None:
            period_start = period_start.replace(tzinfo=local_timezone_source.tzinfo)

        return dt_util.as_local(period_start)

    def _smoothstep(
        self,
        position: float,
    ) -> float:
        """Return a smoothstep interpolation position."""
        normalized_position = max(0.0, min(1.0, position))
        return normalized_position * normalized_position * (3 - 2 * normalized_position)

    def _build_smoothed_steps(
        self,
        raw_steps: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Smooth raw forecast steps using a small moving average window."""
        smoothed_steps: list[dict[str, Any]] = []

        for index, step in enumerate(raw_steps):
            window_start = max(0, index - 2)
            window_end = min(len(raw_steps), index + 3)
            window = raw_steps[window_start:window_end]

            smoothed_power_kw = sum(
                window_step["power_kw"] for window_step in window
            ) / len(window)

            smoothed_steps.append(
                {
                    "time": step["time"],
                    "power_kw": smoothed_power_kw,
                    "duration_hours": step["duration_hours"],
                }
            )

        return smoothed_steps