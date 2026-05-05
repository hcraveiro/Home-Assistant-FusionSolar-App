import logging

from ..const import DATA_REFERER_URL, STATION_LIST_URL
from .exceptions import APIDataStructureError


_LOGGER = logging.getLogger(__name__)


class FusionSolarStationMixin:
    """Station helpers for FusionSolar API."""

    def _update_station_metadata_from_station_list(self, station_data: dict) -> None:
        """Update station metadata such as station DN, station name and battery capacity."""
        stations = station_data.get("data", {}).get("list", [])
        if not isinstance(stations, list) or not stations:
            raise APIDataStructureError("Station list is empty or invalid.")

        selected_station = None

        if not self.station:
            selected_station = stations[0]
            self.station = selected_station.get("dn")
        else:
            selected_station = next((s for s in stations if s.get("dn") == self.station), None)
            if selected_station is None:
                raise APIDataStructureError(f"Station {self.station} not found.")

        if not self.station_name:
            self.station_name = selected_station.get("name")

        if self.battery_capacity is None or self.battery_capacity == 0.0:
            self.battery_capacity = selected_station.get("batteryCapacity")

    def get_station_id(self):
        """Return the first station DN from the station list response."""
        return self.get_station_list()["data"]["list"][0]["dn"]

    def get_station_list(self):
        """Return the list of stations for the authenticated account."""
        self.refresh_csrf()

        station_url = f"https://{self.data_host}{STATION_LIST_URL}"

        station_headers = {
            "accept": "application/json, text/javascript, */*; q=0.01",
            "accept-encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "Origin": f"https://{self.data_host}",
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "Roarand": f"{self.csrf}",
        }

        station_payload = {
            "curPage": 1,
            "pageSize": 10,
            "gridConnectedTime": "",
            "queryTime": 1666044000000,
            "timeZone": 2,
            "sortId": "createTime",
            "sortDir": "DESC",
            "locale": "en_US",
        }

        _LOGGER.debug("Getting Station at: %s", station_url)
        _, json_response = self._request_json(
            "POST",
            station_url,
            context="FusionSolar station list",
            headers=station_headers,
            json=station_payload,
        )

        if json_response.get("success") is False:
            _LOGGER.warning(
                "Station list response indicates failure. Body=%s",
                str(json_response)[:300],
            )
            raise APIDataStructureError("Station list response indicates failure")

        data = json_response.get("data")
        stations = data.get("list") if isinstance(data, dict) else None

        if not isinstance(stations, list):
            _LOGGER.warning(
                "Station list response did not contain the expected data.list structure. Body=%s",
                str(json_response)[:300],
            )
            raise APIDataStructureError("Station list response did not contain data.list")

        _LOGGER.debug("Station info: %s", json_response.get("data"))
        return json_response
