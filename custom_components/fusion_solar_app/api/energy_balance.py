import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import unquote, urlencode

from dateutil.relativedelta import relativedelta

from ..const import DATA_REFERER_URL, ENERGY_BALANCE_URL
from ..utils import extract_numeric
from .exceptions import APIDataStructureError
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
            self_use_value = float(output.get(f"panel_production_consumption_{period}", 0.0) or 0.0)
            house_load_value = float(output.get(f"house_load_{period}", 0.0) or 0.0)
            panel_production_value = float(output.get(f"panel_production_{period}", 0.0) or 0.0)

            output[f"self_consumption_ratio_{period}"] = self._calculate_ratio_percentage(
                self_use_value,
                house_load_value,
            )
            output[f"self_consumption_ratio_by_production_{period}"] = self._calculate_ratio_percentage(
                self_use_value,
                panel_production_value,
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
        try:
            value = float(extract_numeric(raw))
        except (ValueError, TypeError, OverflowError):
            return None
        return value if __import__("math").isfinite(value) else None

    def _set_grid_energy(self, output, period, direction, payload):
        """Do not convert missing iSitePower-M counters into false zero kWh."""
        key = "totalBuyPower" if direction == "consumption" else "totalOnGridPower"
        if getattr(self, "_is_isitepower_m", False):
            output[f"grid_{direction}_{period}"] = self._optional_grid_energy(payload, key)
        else:
            output[f"grid_{direction}_{period}"] = extract_numeric(payload[key])

    def update_output_with_battery_capacity(self, output: Dict[str, Optional[float | str]]):
        """Populate battery capacity in the output dictionary."""
        if self.battery_capacity is None or self.battery_capacity == 0.0:
            _LOGGER.debug("Getting Battery capacity")
            self.refresh_csrf()
            station_list = self.get_station_list()
            stations = station_list.get("data", {}).get("list") or []
            station_data = next(
                (station for station in stations if station.get("dn") == getattr(self, "station", None)),
                stations[0] if stations else {},
            )
            capacity = station_data.get("batteryCapacity")
            if getattr(self, "_is_isitepower_m", False):
                # A power_cube with no conventional capacity field is still
                # an installed battery; zero is not a verified capacity.
                capacity = self._optional_grid_energy({"capacity": capacity}, "capacity")
                if capacity is None or capacity <= 0:
                    capacity = None
            output["battery_capacity"] = capacity
            self.battery_capacity = capacity
        else:
            output["battery_capacity"] = self.battery_capacity

    def update_output_with_energy_balance(self, output: Dict[str, Optional[float | str]]):
        """Populate energy balance values in the output dictionary."""
        self.refresh_csrf()

        _LOGGER.debug("Getting Month's energy data")
        month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.MONTH)
        output["panel_production_month"] = extract_numeric(month_data["data"]["totalProductPower"])
        output["panel_production_consumption_month"] = extract_numeric(month_data["data"]["totalSelfUsePower"])
        self._set_grid_energy(output, "month", "injection", month_data["data"])
        self._set_grid_energy(output, "month", "consumption", month_data["data"])

        month_charge_power_list = month_data["data"]["chargePower"]
        if month_charge_power_list:
            month_total_charge_power = sum(
                extract_numeric(value)
                for value in month_charge_power_list
                if (value != "--" and value != "null")
            )
            output["battery_injection_month"] = month_total_charge_power

        month_discharge_power_list = month_data["data"]["dischargePower"]
        if month_discharge_power_list:
            month_total_discharge_power = sum(
                extract_numeric(value)
                for value in month_discharge_power_list
                if (value != "--" and value != "null")
            )
            output["battery_consumption_month"] = month_total_discharge_power

        _LOGGER.debug("Getting Today's energy data")
        week_data = self.get_week_data()
        self._set_grid_energy(output, "today", "consumption", week_data[-1]["data"])
        self._set_grid_energy(output, "today", "injection", week_data[-1]["data"])

        if month_charge_power_list:
            charge_value_today = month_charge_power_list[datetime.now().day - 1]
            charge_value_today = extract_numeric(charge_value_today)
            output["battery_injection_today"] = charge_value_today

        if month_discharge_power_list:
            discharge_value_today = month_discharge_power_list[datetime.now().day - 1]
            discharge_value_today = extract_numeric(discharge_value_today)
            output["battery_consumption_today"] = discharge_value_today

        month_self_use_list = month_data["data"]["selfUsePower"]
        if month_self_use_list:
            self_use_value_today = month_self_use_list[datetime.now().day - 1]
            self_use_value_today = extract_numeric(self_use_value_today)
            output["panel_production_consumption_today"] = self_use_value_today

        month_house_load_list = month_data["data"]["usePower"]
        if month_house_load_list:
            house_load_value_today = month_house_load_list[datetime.now().day - 1]
            house_load_value_today = extract_numeric(house_load_value_today)
            output["house_load_today"] = house_load_value_today

        month_panel_production_list = month_data["data"]["productPower"]
        if month_panel_production_list:
            panel_production_value_today = month_panel_production_list[datetime.now().day - 1]
            panel_production_value_today = extract_numeric(panel_production_value_today)
            output["panel_production_today"] = panel_production_value_today

        _LOGGER.debug("Getting Week's energy data")
        today = datetime.now()
        start_day_week = today - timedelta(days=today.weekday())

        days_previous_month = []
        days_current_month = []

        for i in range(7):
            current_day = start_day_week + timedelta(days=i)
            if current_day.month < today.month:
                days_previous_month.append(current_day.day)
            else:
                days_current_month.append(current_day.day)

        panel_production_value_week = 0
        panel_production_consumption_value_week = 0
        house_load_value_week = 0
        battery_injection_value_week = 0
        battery_consumption_value_week = 0

        if days_previous_month:
            previous_month_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.PREVIOUS_MONTH)
            panel_production_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(previous_month_data, days_previous_month, "dischargePower")

        if days_current_month:
            panel_production_value_week += self.calculate_week_energy(month_data, days_current_month, "productPower")
            panel_production_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "selfUsePower")
            house_load_value_week += self.calculate_week_energy(month_data, days_current_month, "usePower")
            battery_injection_value_week += self.calculate_week_energy(month_data, days_current_month, "chargePower")
            battery_consumption_value_week += self.calculate_week_energy(month_data, days_current_month, "dischargePower")

        output["panel_production_week"] = panel_production_value_week
        output["panel_production_consumption_week"] = panel_production_consumption_value_week
        output["house_load_week"] = house_load_value_week
        output["battery_injection_week"] = battery_injection_value_week
        output["battery_consumption_week"] = battery_consumption_value_week
        if week_data:
            if getattr(self, "_is_isitepower_m", False):
                for direction, field in (
                    ("consumption", "totalBuyPower"),
                    ("injection", "totalOnGridPower"),
                ):
                    readings = [
                        self._optional_grid_energy(day.get("data"), field)
                        for day in week_data
                    ]
                    output[f"grid_{direction}_week"] = (
                        round(sum(readings), 4)
                        if readings and all(value is not None for value in readings)
                        else None
                    )
            else:
                output["grid_consumption_week"] = sum(
                    extract_numeric(day["data"]["totalBuyPower"])
                    for day in week_data
                    if (day["data"]["totalBuyPower"] != "--" and day["data"]["totalBuyPower"] != "null")
                )
                output["grid_injection_week"] = sum(
                    extract_numeric(day["data"]["totalOnGridPower"])
                    for day in week_data
                    if (day["data"]["totalOnGridPower"] != "--" and day["data"]["totalOnGridPower"] != "null")
                )
    
        _LOGGER.debug("Getting Years's energy data")
        year_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.YEAR)
        output["panel_production_consumption_year"] = extract_numeric(year_data["data"]["totalSelfUsePower"])
        output["house_load_year"] = extract_numeric(year_data["data"]["totalUsePower"])
        output["panel_production_year"] = extract_numeric(year_data["data"]["totalProductPower"])
        self._set_grid_energy(output, "year", "consumption", year_data["data"])
        self._set_grid_energy(output, "year", "injection", year_data["data"])

        charge_power_list = year_data["data"]["chargePower"]
        if charge_power_list:
            total_charge_power = sum(
                extract_numeric(value)
                for value in charge_power_list
                if (value != "--" and value != "null")
            )
            output["battery_injection_year"] = total_charge_power

        discharge_power_list = year_data["data"]["dischargePower"]
        if discharge_power_list:
            total_discharge_power = sum(
                extract_numeric(value)
                for value in discharge_power_list
                if (value != "--" and value != "null")
            )
            output["battery_consumption_year"] = total_discharge_power

        use_power_list = year_data["data"]["usePower"]
        if use_power_list:
            charge_value_this_month = use_power_list[datetime.now().month - 1]
            charge_value_this_month = extract_numeric(charge_value_this_month)
            output["house_load_month"] = charge_value_this_month

        _LOGGER.debug("Getting Lifetime's energy data")
        lifetime_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.LIFETIME)
        output["panel_production_lifetime"] = extract_numeric(lifetime_data["data"]["totalProductPower"])
        output["panel_production_consumption_lifetime"] = extract_numeric(lifetime_data["data"]["totalSelfUsePower"])
        output["house_load_lifetime"] = extract_numeric(lifetime_data["data"]["totalUsePower"])
        self._set_grid_energy(output, "lifetime", "consumption", lifetime_data["data"])
        self._set_grid_energy(output, "lifetime", "injection", lifetime_data["data"])

        lifetime_charge_power_list = lifetime_data["data"]["chargePower"]
        if lifetime_charge_power_list:
            lifetime_total_charge_power = sum(
                extract_numeric(value)
                for value in lifetime_charge_power_list
                if (value != "--" and value != "--")
            )
            output["battery_injection_lifetime"] = lifetime_total_charge_power

        lifetime_discharge_power_list = lifetime_data["data"]["dischargePower"]
        if lifetime_discharge_power_list:
            lifetime_total_discharge_power = sum(
                extract_numeric(value)
                for value in lifetime_discharge_power_list
                if (value != "--" and value != "--")
            )
            output["battery_consumption_lifetime"] = lifetime_total_discharge_power

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
        """Return day-level energy balance data for the current week."""
        today = datetime.now()
        start_of_week = today - timedelta(days=today.weekday())
        days_to_process = []

        if today.weekday() == 6:
            days_to_process = [start_of_week + timedelta(days=i) for i in range(7)]
        else:
            days_to_process = [start_of_week + timedelta(days=i) for i in range(today.weekday() + 1)]

        week_data = []
        for day in days_to_process:
            day_data = self.call_energy_balance(ENERGY_BALANCE_CALL_TYPE.DAY, specific_date=day)
            week_data.append(day_data)
            time.sleep(1)

        return week_data

    def calculate_week_energy(self, data, days, field):
        """Return the summed energy for the provided days and field."""
        total = 0
        if data["data"][field]:
            for day in days:
                value = data["data"][field][day - 1]
                if value != "--" and value != "null":
                    total += extract_numeric(value)

        return total
