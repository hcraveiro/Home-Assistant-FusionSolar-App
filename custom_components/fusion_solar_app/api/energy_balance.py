import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import unquote, urlencode

from dateutil.relativedelta import relativedelta

from ..const import DATA_REFERER_URL, ENERGY_BALANCE_URL
from .exceptions import APIConnectionError, APIDataStructureError
from .models import ENERGY_BALANCE_CALL_TYPE


_LOGGER = logging.getLogger(__name__)


class FusionSolarEnergyBalanceMixin:
    """Energy balance helpers for FusionSolar API."""

    def _calculate_ratio_percentage(self, numerator: float, denominator: float) -> float:
        """Return a percentage ratio with safe division handling."""
        if denominator <= 0:
            return 0.0

        return round((numerator / denominator) * 100, 2)

    def _update_output_with_self_consumption_ratios(
        self,
        output: Dict[str, Optional[float | str]],
    ):
        """Populate self-consumption ratios for all supported periods."""
        periods = ("today", "week", "month", "year", "lifetime")

        for period in periods:
            consumption = self._optional_grid_energy(output, f"panel_production_consumption_{period}")
            load = self._optional_grid_energy(output, f"house_load_{period}")
            production = self._optional_grid_energy(output, f"panel_production_{period}")
            for suffix, denominator in (("", load), ("_by_production", production)):
                output[f"self_consumption_ratio{suffix}_{period}"] = (
                    self._calculate_ratio_percentage(consumption, denominator)
                    if consumption is not None and denominator is not None and denominator > 0
                    else None
                )

    @staticmethod
    def _optional_grid_energy(payload, key):
        """Read a measured counter; missing/invalid values are not zero."""
        if not isinstance(payload, dict):
            return None
        raw = payload.get(key)
        if raw is None or isinstance(raw, bool):
            return None
        if isinstance(raw, str) and raw.strip().lower() in ("", "--", "null", "none"):
            return None
        if isinstance(raw, str):
            # Retain this counter parser's established accepted formats and
            # Wh conversion; aggregation/placeholder policies depend on it.
            import re
            match = re.fullmatch(
                r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(?:kWh|Wh)?\s*",
                raw,
                flags=re.IGNORECASE,
            )
            if match is None:
                return None
            raw = match.group(1)
            unit = match.group(0).strip().lower()
            in_wh = unit.endswith("wh") and not unit.endswith("kwh")
        else:
            in_wh = False
        try:
            value = float(raw)
        except (ValueError, TypeError, OverflowError):
            return None
        if not __import__("math").isfinite(value):
            return None
        # Explicit Wh readings must be converted to the kWh exposed by HA.
        return value / 1000 if in_wh else value

    def _period_grid_energy(self, payload, key, period):
        """Parse an individual energy reading without inventing marker zeros."""
        return self._optional_grid_energy(payload, key)

    def _set_grid_energy(self, output, period, direction, payload):
        """Do not convert missing iSitePower-M counters into false zero kWh."""
        key = "totalBuyPower" if direction == "consumption" else "totalOnGridPower"
        output[f"grid_{direction}_{period}"] = self._period_grid_energy(payload, key, period)

    def update_output_with_battery_capacity(self, output: Dict[str, Optional[float | str]]):
        """Populate battery capacity in the output dictionary."""
        if self.battery_capacity is None or self.battery_capacity == 0.0:
            _LOGGER.debug("Getting Battery capacity")
            self.refresh_csrf()
            station_list = self.get_station_list()
            stations = station_list.get("data", {}).get("list") or []
            selected_dn = getattr(self, "station", None)
            station_data = next(
                (station for station in stations if station.get("dn") == selected_dn),
                None,
            )
            if station_data is None:
                if getattr(self, "_is_isitepower_m", False):
                    # A capacity from a different station is not a valid fallback.
                    station_data = {}
                else:
                    station_data = stations[0] if stations else {}
            capacity = station_data.get("batteryCapacity")
            # Normalize numeric strings for every station type. Unknown
            # capacity must not be interpreted as a battery-free system.
            capacity = self._optional_grid_energy({"capacity": capacity}, "capacity")
            if getattr(self, "_is_isitepower_m", False) and (
                capacity is None or capacity <= 0
            ):
                # iSitePower-M may have installed clusters despite zero here.
                capacity = None
            output["battery_capacity"] = capacity
            self.battery_capacity = capacity
        else:
            output["battery_capacity"] = self.battery_capacity

    def _update_isitepower_energy_balance(self, output):
        """Read only verified conventional energy fields on iSitePower-M.

        The iSitePower-M API can return incomplete or empty station balance
        payloads. Parse each available field independently. This does not map
        device-specific Mains counters to station totals.
        """
        fields = {
            "grid_consumption": "totalBuyPower",
            "grid_injection": "totalOnGridPower",
            "panel_production": "totalProductPower",
            "panel_production_consumption": "totalSelfUsePower",
            "house_load": "totalUsePower",
        }
        periods = {
            "month": ENERGY_BALANCE_CALL_TYPE.MONTH,
            "year": ENERGY_BALANCE_CALL_TYPE.YEAR,
            "lifetime": ENERGY_BALANCE_CALL_TYPE.LIFETIME,
        }
        for period, call_type in periods.items():
            try:
                response = self.call_energy_balance(call_type)
                payload = (
                    response.get("data")
                    if isinstance(response, dict) and response.get("success") is not False
                    else None
                )
                for category, key in fields.items():
                    output[f"{category}_{period}"] = self._period_grid_energy(payload, key, period)
                if period == "month" and isinstance(payload, dict):
                    # iSitePower-M can omit aggregate totals while still
                    # providing verified daily readings in monthly arrays.
                    day_index = datetime.now().day - 1
                    for category, array_key in (
                        ("panel_production", "productPower"),
                        ("panel_production_consumption", "selfUsePower"),
                        ("house_load", "usePower"),
                    ):
                        samples = payload.get(array_key)
                        if isinstance(samples, list) and day_index < len(samples):
                            reading = self._period_grid_energy(
                                {"value": samples[day_index]}, "value", "today"
                            )
                            if reading is not None:
                                output[f"{category}_today"] = reading
                if period in ("month", "year", "lifetime"):
                    for category, key in (
                        ("battery_injection", "chargePower"),
                        ("battery_consumption", "dischargePower"),
                    ):
                        readings = payload.get(key) if isinstance(payload, dict) else None
                        output[f"{category}_{period}"] = self._period_energy_sum(readings, period)
            except (KeyError, IndexError, TypeError, ValueError, APIConnectionError, APIDataStructureError) as ex:
                _LOGGER.warning("iSitePower-M %s energy not available: %s", period, ex)

        try:
            days = self.get_week_data()
            # Empty/incomplete week data is not evidence of zero energy.
            if days:
                daily_payloads = [
                    item.get("data")
                    if isinstance(item, dict) and item.get("success") is not False
                    else None
                    for item in days
                ]
                for category, key in fields.items():
                    complete_week = len(daily_payloads) == datetime.now().weekday() + 1
                    # Retain independently measured daily values from sparse
                    # responses, but never infer placeholder zero from a short week.
                    today_value = (
                        self._period_grid_energy(daily_payloads[-1], key, "today") if complete_week
                        else self._optional_grid_energy(daily_payloads[-1], key)
                    )
                    if today_value is not None:
                        output[f"{category}_today"] = today_value
                    if complete_week:
                        output[f"{category}_week"] = self._energy_sum([
                            item.get(key) if isinstance(item, dict) else None
                            for item in daily_payloads
                        ], period="week")
        except (KeyError, IndexError, TypeError, ValueError, APIConnectionError, APIDataStructureError) as ex:
            _LOGGER.warning("iSitePower-M daily energy not available: %s", ex)

        # Per-period battery/load arrays and energy direction are not reliably
        # described by the provided INTL samples. Do not extrapolate them.
        self._update_output_with_self_consumption_ratios(output)

    @staticmethod
    def _energy_payload(response):
        """Only successful, structured Huawei responses contain measurements."""
        if not isinstance(response, dict) or response.get("success") is False:
            return {}
        payload = response.get("data")
        return payload if isinstance(payload, dict) else {}

    def _energy_sum(self, readings, *, period=None):
        """Skip only literal markers; require at least one valid segment."""
        if not isinstance(readings, list) or not readings:
            return None
        values = [
            self._optional_grid_energy({"v": item}, "v")
            for item in readings if item != "--"
        ]
        if not values:
            return None
        return sum(values) if all(value is not None for value in values) else None

    def _period_energy_sum(self, readings, period):
        """Exclude known future calendar slots, never missing elapsed readings.

        Month vectors are day-indexed and year vectors month-indexed, as used
        for today's battery readings and the current month's house load. No
        lifetime start-year/index contract is known, so retain its whole vector.
        Literal '--' slots are skipped in every period; all-marker is unknown.
        Every other invalid elapsed reading rejects the aggregate.
        """
        count = {"month": datetime.now().day, "year": datetime.now().month}.get(period)
        if count is not None:
            if not isinstance(readings, list) or len(readings) < count:
                return None
            readings = readings[:count]
        return self._energy_sum(readings, period=period)

    def _history_energy_payload(self, call_type):
        """Isolate transport failures; auth and unexpected schemas still propagate.

        A failed period is unknown for this snapshot and is requested again on
        the next scheduled refresh, without replaying live device requests.
        """
        try:
            return self._energy_payload(self.call_energy_balance(call_type))
        except APIConnectionError as ex:
            _LOGGER.warning("FusionSolar %s energy not available: %s", call_type, ex)
            return {}

    def update_output_with_energy_balance(self, output: Dict[str, Optional[float | str]]):
        """Mirror Huawei readings, including corrections, without synthetic resets."""
        # Explicitly clear each snapshot, including when callers reuse a dict.
        categories = {
            "panel_production": "totalProductPower",
            "panel_production_consumption": "totalSelfUsePower",
            "house_load": "totalUsePower",
            "grid_consumption": "totalBuyPower",
            "grid_injection": "totalOnGridPower",
        }
        arrays = {
            "panel_production": "productPower",
            "panel_production_consumption": "selfUsePower",
            "house_load": "usePower",
            "battery_injection": "chargePower",
            "battery_consumption": "dischargePower",
        }
        for category in categories.keys() | arrays.keys():
            for period in ("today", "week", "month", "year", "lifetime"):
                output[f"{category}_{period}"] = None
        if getattr(self, "_is_isitepower_m", False):
            self._update_isitepower_energy_balance(output)
            return
        self.refresh_csrf()
        today = datetime.now()
        # Preserve the established request cadence: month, spaced daily/week
        # requests (and previous month when needed), then year and lifetime.
        payloads = {"month": self._history_energy_payload(ENERGY_BALANCE_CALL_TYPE.MONTH)}
        days = self.get_week_data()
        week_start = today - timedelta(days=today.weekday())
        dates = [week_start + timedelta(days=i) for i in range(today.weekday() + 1)]
        previous = {}
        if any((day.year, day.month) != (today.year, today.month) for day in dates):
            previous = self._history_energy_payload(ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH)
        payloads["year"] = self._history_energy_payload(ENERGY_BALANCE_CALL_TYPE.YEAR)
        payloads["lifetime"] = self._history_energy_payload(ENERGY_BALANCE_CALL_TYPE.LIFETIME)
        for period, payload in payloads.items():
            for category, key in categories.items():
                output[f"{category}_{period}"] = self._period_grid_energy(payload, key, period)
            for category, key in arrays.items():
                if category.startswith("battery_"):
                    output[f"{category}_{period}"] = self._period_energy_sum(payload.get(key), period)

        def sample(payload, field, index, *, raw=False, period="today"):
            readings = payload.get(field)
            if not isinstance(readings, list) or index >= len(readings):
                return None
            return readings[index] if raw else self._period_grid_energy({"v": readings[index]}, "v", period)

        for category, field in arrays.items():
            output[f"{category}_today"] = sample(payloads["month"], field, today.day - 1)
        output["house_load_month"] = sample(payloads["year"], "usePower", today.month - 1, period="month")
        daily = [self._energy_payload(day) for day in days] if isinstance(days, list) else []
        for category, key in (("grid_consumption", "totalBuyPower"), ("grid_injection", "totalOnGridPower")):
            complete_week = len(daily) == today.weekday() + 1
            if daily:
                output[f"{category}_today"] = (
                    self._period_grid_energy(daily[-1], key, "today") if complete_week
                    else self._optional_grid_energy(daily[-1], key)
                )
            if complete_week:
                output[f"{category}_week"] = self._energy_sum([day.get(key) for day in daily], period="week")
        for category, field in arrays.items():
            readings = [
                sample(payloads["month"] if (day.year, day.month) == (today.year, today.month) else previous, field, day.day - 1, raw=True)
                for day in dates
            ]
            output[f"{category}_week"] = self._energy_sum(readings, period="week")
        self._update_output_with_self_consumption_ratios(output)

    def call_energy_balance(
        self,
        call_type: ENERGY_BALANCE_CALL_TYPE,
        specific_date: datetime = None,
    ):
        """Call the energy balance endpoint and return parsed JSON."""
        self.refresh_csrf()

        currentTime = datetime.now()
        timestampNow = currentTime.timestamp() * 1000
        current_day = currentTime.day
        current_month = currentTime.month
        current_year = currentTime.year
        first_day_of_month = datetime(current_year, current_month, 1)
        first_day_of_previous_month = first_day_of_month - relativedelta(months=1)
        first_day_of_year = datetime(current_year, 1, 1)

        if call_type == ENERGY_BALANCE_CALL_TYPE.MONTH:
            timestamp = first_day_of_month.timestamp() * 1000
            dateStr = first_day_of_month.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH:
            timestamp = first_day_of_previous_month.timestamp() * 1000
            dateStr = first_day_of_previous_month.strftime("%Y-%m-%d %H:%M:%S")
            call_type = ENERGY_BALANCE_CALL_TYPE.MONTH
        elif call_type == ENERGY_BALANCE_CALL_TYPE.YEAR:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        elif call_type == ENERGY_BALANCE_CALL_TYPE.DAY:
            if specific_date is not None:
                specific_year = specific_date.year
                specific_month = specific_date.month
                specific_day = specific_date.day
                current_day_of_year = datetime(
                    specific_year,
                    specific_month,
                    specific_day,
                )
            else:
                current_day_of_year = datetime(current_year, current_month, current_day)

            timestamp = current_day_of_year.timestamp() * 1000
            dateStr = current_day_of_year.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp = first_day_of_year.timestamp() * 1000
            dateStr = first_day_of_year.strftime("%Y-%m-%d %H:%M:%S")

        headers = {
            "application/json": "text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf,
        }

        params = {
            "stationDn": unquote(self.station),
            "timeDim": call_type,
            "queryTime": int(timestamp),
            "timeZone": "0.0",
            "timeZoneStr": "Europe/London",
            "dateStr": dateStr,
            "_": int(timestampNow),
        }

        energy_balance_url = (
            f"https://{self.data_host}{ENERGY_BALANCE_URL}?{urlencode(params)}"
        )
        _LOGGER.debug("Getting Energy Balance at: %s", energy_balance_url)

        _, energy_balance_data = self._request_json(
            "GET",
            energy_balance_url,
            context=f"FusionSolar energy balance ({call_type})",
            headers=headers,
        )

        if "data" not in energy_balance_data:
            _LOGGER.error(
                "Energy balance response had an unexpected structure: %s",
                str(energy_balance_data)[:500],
            )
            raise APIDataStructureError("Energy balance response did not contain data")

        _LOGGER.debug("Energy Balance Response: %s", energy_balance_data)
        return energy_balance_data

    def get_week_data(self):
        """Return Monday-through-today responses, with None for failed dates.

        Successful responses retain their date's slot; callers must not sum an
        incomplete vector or mistake a preceding date's payload for today.
        """
        today = datetime.now()
        start_of_week = today - timedelta(days=today.weekday())
        days_to_process = []

        if today.weekday() == 6:
            days_to_process = [start_of_week + timedelta(days=i) for i in range(7)]
        else:
            days_to_process = [start_of_week + timedelta(days=i) for i in range(today.weekday() + 1)]

        week_data = []
        for day in days_to_process:
            try:
                day_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.DAY, specific_date=day)
            except APIConnectionError as ex:
                _LOGGER.warning("FusionSolar daily energy for %s not available: %s", day.date(), ex)
                # Keep one slot per requested date. Dropping a failed today
                # would incorrectly label yesterday's successful response today.
                day_data = None
            week_data.append(day_data)

        return week_data

    def calculate_week_energy(self, data, days, field):
        """Return the summed energy for the provided days and field."""
        payload = self._energy_payload(data)
        readings = payload.get(field)
        if not isinstance(readings, list) or any(day < 1 or day > len(readings) for day in days):
            return None
        return self._energy_sum([readings[day - 1] for day in days], period="week")
