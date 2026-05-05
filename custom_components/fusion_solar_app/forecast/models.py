from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..const import DEFAULT_FORECAST_PROVIDER


@dataclass
class FusionSolarForecastData:
    """Class to hold forecast data."""

    source_entity_id: str | None = None
    provider: str = DEFAULT_FORECAST_PROVIDER
    provider_entity_id: str | None = None
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
    estimate10_kwh: float | None = None
    estimate90_kwh: float | None = None
    confidence: float | None = None
    debug: dict[str, Any] = field(default_factory=dict)