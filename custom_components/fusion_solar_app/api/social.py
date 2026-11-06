import json
import logging
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import unquote, urlencode

import requests

from ..const import DATA_REFERER_URL, SOCIAL_CONTRIBUTION_URL
from ..utils import extract_numeric
from .exceptions import APIAuthError, APIConnectionError, APIDataStructureError


_LOGGER = logging.getLogger(__name__)


class FusionSolarSocialMixin:
    """Social contribution helpers for FusionSolar API."""

    def call_social_contribution(self):
        """Call the social contribution endpoint and return parsed JSON."""
        self.refresh_csrf()

        current_time = int(datetime.now().timestamp() * 1000)
        local_offset = datetime.now().astimezone().utcoffset()
        time_zone_hours = int(local_offset.total_seconds() / 3600) if local_offset else 0

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "Host": self.data_host,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
            "X-Requested-With": "XMLHttpRequest",
            "Roarand": self.csrf,
        }

        params = {
            "dn": unquote(self.station),
            "clientTime": current_time,
            "timeZone": str(time_zone_hours),
            "_": current_time,
        }

        social_contribution_url = (
            f"https://{self.data_host}{SOCIAL_CONTRIBUTION_URL}?{urlencode(params)}"
        )
        _LOGGER.debug(
            "Getting Social Contribution at: https://%s%s",
            self.data_host,
            SOCIAL_CONTRIBUTION_URL,
        )

        response = self.session.get(
            social_contribution_url,
            headers=headers,
            timeout=20,
        )

        if response.status_code != 200:
            _LOGGER.error(
                "Social contribution request failed. Status=%s",
                response.status_code,
            )
            raise APIConnectionError("Social contribution request failed")

        try:
            social_contribution_data = response.json()
        except (requests.exceptions.JSONDecodeError, json.JSONDecodeError) as err:
            # Requests may use simplejson; the offline transport uses stdlib JSON.
            _LOGGER.error(
                "Social contribution did not return JSON. Status=%s Content-Type=%s",
                response.status_code,
                response.headers.get("Content-Type"),
            )
            raise APIAuthError("Social contribution did not return JSON") from err

        if "data" not in social_contribution_data:
            _LOGGER.error(
                "Social contribution response had an unexpected structure."
            )
            raise APIDataStructureError(
                "Social contribution response did not contain data"
            )

        _LOGGER.debug("Social Contribution Response: %s", social_contribution_data)
        return social_contribution_data

    def update_output_with_social_contribution(
        self,
        output: Dict[str, Optional[float | str]],
    ):
        """Populate social contribution values in the output dictionary."""
        _LOGGER.debug("Getting social contribution data")

        social_contribution_data = self.call_social_contribution()
        data = social_contribution_data.get("data", {})

        output["standard_coal_saved"] = extract_numeric(
            data.get("standardCoalSavings", 0)
        )
        output["standard_coal_saved_this_year"] = extract_numeric(
            data.get("standardCoalSavingsByYear", 0)
        )
        output["co2_avoided"] = extract_numeric(
            data.get("co2Reduction", 0)
        )
        output["co2_avoided_this_year"] = extract_numeric(
            data.get("co2ReductionByYear", 0)
        )
        output["equivalent_trees_planted"] = int(
            round(extract_numeric(data.get("equivalentTreePlanting", 0)))
        )
        output["equivalent_trees_planted_this_year"] = int(
            round(extract_numeric(data.get("equivalentTreePlantingByYear", 0)))
        )
