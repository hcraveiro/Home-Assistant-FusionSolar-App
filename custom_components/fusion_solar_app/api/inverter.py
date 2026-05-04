"""Fusion Solar App inverter helpers."""

import logging
import time
from typing import Any

from ..const import (
    DATA_REFERER_URL,
    DEVICE_REALTIME_DATA_URL,
    DEVICE_REAL_KPI_URL,
    INVERTER_CONFIG_SIGNAL_URL,
)
from ..utils import extract_numeric
from .signal_maps import get_inverter_signal_map


_LOGGER = logging.getLogger(__name__)


class FusionSolarInverterMixin:
    """Inverter helpers for FusionSolar API."""

    def _discover_inverter_dn_from_flow_nodes(self, flow_data_nodes: list[dict[str, Any]]) -> None:
        """Discover the inverter DN from installation flow nodes."""
        if self.inverter_dn is not None:
            return

        for node in flow_data_nodes:
            if node.get("name") == "neteco.pvms.devTypeLangKey.inverter":
                dev_ids = node.get("devIds") or []
                dn = dev_ids[0] if dev_ids else node.get("devDn")
                if dn:
                    self.inverter_dn = dn
                    _LOGGER.info("Discovered inverter DN: %s", self.inverter_dn)
                else:
                    _LOGGER.warning(
                        "Could not determine inverter DN from inverter node. Node: %s",
                        node,
                    )
                return

    def _ensure_inverter_metadata_loaded(self) -> None:
        """Load inverter metadata when the inverter DN is known and metadata is missing."""
        if not self.inverter_dn:
            return

        if (
            self.inverter_name is not None
            and self.inverter_model is not None
            and self.inverter_software_version is not None
            and self.inverter_serial_number is not None
        ):
            return

        try:
            self.get_inverter_config_info()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch inverter config info: %s", ex)

    def get_inverter_config_info(self) -> dict:
        """Fetch inverter configuration metadata such as model, software version and serial number."""
        if not self.inverter_dn:
            return {}

        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }

        params = {
            "dn": self.inverter_dn,
            "signals": "50009,50010,50012,33595393",
            "_": int(time.time() * 1000),
        }

        url = f"https://{self.data_host}{INVERTER_CONFIG_SIGNAL_URL}"
        _LOGGER.debug("Getting inverter config info at: %s", url)

        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar inverter config info",
            headers=headers,
            params=params,
        )

        payload = data.get("data", {})
        entries: list[dict[str, Any]] = []

        if isinstance(payload, list):
            entries = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            if isinstance(payload.get("signals"), list):
                entries = [item for item in payload["signals"] if isinstance(item, dict)]
            elif isinstance(payload.get("list"), list):
                entries = [item for item in payload["list"] if isinstance(item, dict)]
            else:
                for key, value in payload.items():
                    if str(key).isdigit():
                        if isinstance(value, dict):
                            entries.append({"signal": key, **value})
                        else:
                            entries.append({"signal": key, "value": value})

        parsed: dict[str, Any] = {}

        for entry in entries:
            signal_id = str(
                entry.get("signal")
                or entry.get("signalId")
                or entry.get("signal_id")
                or entry.get("id")
                or entry.get("sigId")
                or entry.get("sigid")
                or ""
            )

            raw_value = entry.get("realValue")
            if raw_value in (None, ""):
                raw_value = entry.get("value")

            if raw_value in (None, "", "--", "null"):
                continue

            parsed[signal_id] = raw_value

        if "33595393" in parsed:
            self.inverter_name = str(parsed["33595393"])

        if "50009" in parsed:
            self.inverter_model = str(parsed["50009"])

        if "50010" in parsed:
            self.inverter_software_version = str(parsed["50010"])

        if "50012" in parsed:
            self.inverter_serial_number = str(parsed["50012"])

        _LOGGER.debug(
            "Inverter config info loaded: name=%s model=%s sw=%s sn=%s",
            self.inverter_name,
            self.inverter_model,
            self.inverter_software_version,
            self.inverter_serial_number,
        )

        return data

    def get_inverter_realtime_data(self) -> dict:
        """Fetch real-time inverter data and dynamically expose only visible PV inputs."""
        if not self.inverter_dn:
            return {}

        signal_map = get_inverter_signal_map()

        self.refresh_csrf()
        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }
        params = {"deviceDn": self.inverter_dn, "displayAccessModel": "true"}

        realtime_url = f"https://{self.data_host}{DEVICE_REALTIME_DATA_URL}"
        _LOGGER.debug("Getting inverter realtime data at: %s", realtime_url)

        _, realtime_data = self._request_json(
            "GET",
            realtime_url,
            context="FusionSolar inverter realtime data",
            headers=headers,
            params=params,
        )

        if not realtime_data.get("success") or not realtime_data.get("data"):
            _LOGGER.warning(
                "Inverter realtime data response indicates failure: %s",
                realtime_data,
            )
            return {}

        result: dict[int, Any] = {}

        for entry in realtime_data["data"]:
            if not isinstance(entry, dict) or "signals" not in entry:
                continue

            for signal in entry["signals"]:
                signal_id = signal.get("id")
                signal_value = signal.get("value", "")

                if signal_id not in signal_map:
                    continue

                if signal_value in ("", "--", "null", None):
                    continue

                result[signal_id] = signal_value

        pv_voltage_current_signal_ids: list[int] = []
        for pv_index in range(1, 21):
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1
            pv_voltage_current_signal_ids.extend([voltage_id, current_id])

        pv_signal_meta: dict[int, dict[str, Any]] = {}

        if pv_voltage_current_signal_ids:
            try:
                self.refresh_csrf()
                headers["Roarand"] = self.csrf
                signal_str = "&".join(
                    f"signalIds={signal_id}"
                    for signal_id in pv_voltage_current_signal_ids
                )
                kpi_url = (
                    f"https://{self.data_host}{DEVICE_REAL_KPI_URL}"
                    f"?deviceDn={self.inverter_dn}&{signal_str}"
                )
                _LOGGER.debug("Getting inverter PV KPI data at: %s", kpi_url)

                _, kpi_data = self._request_json(
                    "GET",
                    kpi_url,
                    context="FusionSolar inverter PV KPI data",
                    headers=headers,
                )

                if kpi_data.get("success") and kpi_data.get("data", {}).get("signals"):
                    for sid_str, val in kpi_data["data"]["signals"].items():
                        sid = int(sid_str)

                        if sid not in signal_map:
                            continue

                        raw_value = val.get("value", "")
                        if raw_value in ("", "--", "null", None):
                            continue

                        pv_signal_meta[sid] = {
                            "value": raw_value,
                            "latestTime": val.get("latestTime"),
                        }
            except Exception as ex:
                _LOGGER.warning("Failed to fetch PV string KPI data: %s", ex)

        visible_pv_indexes = self._get_visible_pv_indexes_from_signal_meta(pv_signal_meta)

        for sid, meta in pv_signal_meta.items():
            pv_index = ((sid - 11001) // 3) + 1
            if pv_index not in visible_pv_indexes:
                continue
            result[sid] = meta["value"]

        for pv_index in visible_pv_indexes:
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1
            power_id = voltage_id + 2

            if voltage_id not in result or current_id not in result:
                continue

            voltage_value = extract_numeric(result[voltage_id])
            current_value = extract_numeric(result[current_id])
            result[power_id] = round(voltage_value * current_value / 1000, 4)

        _LOGGER.debug(
            "Inverter realtime data after PV filtering: visible_pv_indexes=%s result=%s",
            sorted(visible_pv_indexes),
            result,
        )
        return result

    def _get_visible_pv_indexes_from_signal_meta(
        self,
        pv_signal_meta: dict[int, dict[str, Any]],
        max_pv_inputs: int = 20,
    ) -> set[int]:
        """Determine which PV inputs should be exposed.

        The FusionSolar web UI requests many PV signal IDs, but on some inverters
        the API returns a repeated stale zero-value tail for non-existent inputs.
        This method keeps the contiguous real PV inputs and trims that placeholder tail.
        """
        pv_pairs: list[dict[str, Any]] = []

        for pv_index in range(1, max_pv_inputs + 1):
            voltage_id = 11001 + ((pv_index - 1) * 3)
            current_id = voltage_id + 1

            voltage_meta = pv_signal_meta.get(voltage_id)
            current_meta = pv_signal_meta.get(current_id)

            if voltage_meta is None and current_meta is None:
                continue

            voltage_value = (
                extract_numeric(voltage_meta.get("value"))
                if voltage_meta is not None
                else 0.0
            )
            current_value = (
                extract_numeric(current_meta.get("value"))
                if current_meta is not None
                else 0.0
            )
            voltage_time = voltage_meta.get("latestTime") if voltage_meta else None
            current_time = current_meta.get("latestTime") if current_meta else None

            pv_pairs.append(
                {
                    "pv_index": pv_index,
                    "voltage_value": voltage_value,
                    "current_value": current_value,
                    "voltage_time": voltage_time,
                    "current_time": current_time,
                    "is_zero_only": voltage_value == 0 and current_value == 0,
                    "time_tuple": (voltage_time, current_time),
                }
            )

        if not pv_pairs:
            return set()

        cutoff_index: int | None = None

        for pos, pair in enumerate(pv_pairs):
            tail = pv_pairs[pos:]

            if len(tail) < 2:
                continue

            if not pair["is_zero_only"]:
                continue

            placeholder_time_tuple = pair["time_tuple"]

            if all(
                tail_pair["is_zero_only"]
                and tail_pair["time_tuple"] == placeholder_time_tuple
                for tail_pair in tail
            ):
                cutoff_index = pair["pv_index"] - 1
                break

        if cutoff_index is None:
            cutoff_index = pv_pairs[-1]["pv_index"]

        visible_indexes = {
            pair["pv_index"]
            for pair in pv_pairs
            if pair["pv_index"] <= cutoff_index
        }

        _LOGGER.debug(
            "Visible PV indexes determined from signal metadata: %s (cutoff=%s, pairs=%s)",
            sorted(visible_indexes),
            cutoff_index,
            pv_pairs,
        )

        return visible_indexes