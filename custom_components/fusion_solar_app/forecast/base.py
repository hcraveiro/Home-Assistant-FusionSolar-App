from __future__ import annotations

from typing import Protocol

from ..api import Device
from .models import FusionSolarForecastData


class ForecastProvider(Protocol):
    """Protocol for forecast providers."""

    async def build(
        self,
        devices: list[Device],
    ) -> FusionSolarForecastData | None:
        """Build forecast data."""