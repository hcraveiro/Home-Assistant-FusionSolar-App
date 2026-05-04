"""Fusion Solar App installation helpers."""

import logging
from typing import Any
from urllib.parse import unquote

from ..const import DATA_URL
from ..utils import extract_numeric
from .exceptions import APIDataStructureError
from .models import Device, DeviceType
from .signal_maps import DEVICES, get_inverter_signal_map


_LOGGER = logging.getLogger(__name__)


class FusionSolarInstallationMixin:
    """Installation helpers for FusionSolar API."""

    def _build_base_output(self) -> dict[str, float | int | str]:
        """Build the base output structure for installation-level sensors."""
        return {
            "panel_production_power": 0.0,
            "panel_production_today": 0.0,
            "panel_production_week": 0.0,
            "panel_production_month": 0.0,
            "panel_production_year": 0.0,
            "panel_production_lifetime": 0.0,
            "panel_production_consumption_today": 0.0,
            "panel_production_consumption_week": 0.0,
            "panel_production_consumption_month": 0.0,
            "panel_production_consumption_year": 0.0,
            "panel_production_consumption_lifetime": 0.0,
            "house_load_power": 0.0,
            "house_load_today": 0.0,
            "house_load_week": 0.0,
            "house_load_month": 0.0,
            "house_load_year": 0.0,
            "house_load_lifetime": 0.0,
            "grid_consumption_power": 0.0,
            "grid_consumption_today": 0.0,
            "grid_consumption_week": 0.0,
            "grid_consumption_month": 0.0,
            "grid_consumption_year": 0.0,
            "grid_consumption_lifetime": 0.0,
            "grid_injection_power": 0.0,
            "grid_injection_today": 0.0,
            "grid_injection_week": 0.0,
            "grid_injection_month": 0.0,
            "grid_injection_year": 0.0,
            "grid_injection_lifetime": 0.0,
            "battery_injection_power": 0.0,
            "battery_injection_today": 0.0,
            "battery_injection_week": 0.0,
            "battery_injection_month": 0.0,
            "battery_injection_year": 0.0,
            "battery_injection_lifetime": 0.0,
            "battery_consumption_power": 0.0,
            "battery_consumption_today": 0.0,
            "battery_consumption_week": 0.0,
            "battery_consumption_month": 0.0,
            "battery_consumption_year": 0.0,
            "battery_consumption_lifetime": 0.0,
            "battery_percentage": 0.0,
            "battery_capacity": 0.0,
            "self_consumption_ratio_today": 0.0,
            "self_consumption_ratio_week": 0.0,
            "self_consumption_ratio_month": 0.0,
            "self_consumption_ratio_year": 0.0,
            "self_consumption_ratio_lifetime": 0.0,
            "self_consumption_ratio_by_production_today": 0.0,
            "self_consumption_ratio_by_production_week": 0.0,
            "self_consumption_ratio_by_production_month": 0.0,
            "self_consumption_ratio_by_production_year": 0.0,
            "self_consumption_ratio_by_production_lifetime": 0.0,
            "standard_coal_saved": 0.0,
            "standard_coal_saved_this_year": 0.0,
            "co2_avoided": 0.0,
            "co2_avoided_this_year": 0.0,
            "equivalent_trees_planted": 0,
            "equivalent_trees_planted_this_year": 0,
            "exit_code": "SUCCESS",
        }

    def _get_installation_flow_data(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Fetch and validate installation realtime flow data."""
        self.refresh_csrf()

        if not self.station:
            raise APIDataStructureError("FusionSolar station DN is not configured")

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
        }

        params = {"stationDn": unquote(self.station)}

        data_access_url = f"https://{self.data_host}{DATA_URL}"
        _LOGGER.debug("Getting Data at: %s", data_access_url)

        _, data = self._request_json(
            "GET",
            data_access_url,
            context="FusionSolar realtime data",
            headers=headers,
            params=params,
        )

        if "data" not in data or "flow" not in data["data"]:
            _LOGGER.error(
                "FusionSolar realtime data response had an unexpected structure. "
                "Cookies=%s Headers=%s Body=%s",
                self.session.cookies.get_dict(),
                headers,
                str(data)[:500],
            )
            raise APIDataStructureError("FusionSolar realtime data structure is invalid")

        _LOGGER.debug("Get Data Response: %s", data)

        flow_data_nodes = data["data"]["flow"].get("nodes", [])
        flow_data_links = data["data"]["flow"].get("links", [])

        if not isinstance(flow_data_nodes, list) or not isinstance(flow_data_links, list):
            raise APIDataStructureError("FusionSolar flow nodes/links structure is invalid")

        return flow_data_nodes, flow_data_links

    def _parse_installation_flow_nodes(
        self,
        flow_data_nodes: list[dict[str, Any]],
        output: dict[str, float | int | str],
    ) -> None:
        """Parse installation flow nodes into the output structure."""
        node_map = {
            "neteco.pvms.energy.flow.buy.power": "grid_consumption_power",
            "neteco.pvms.devTypeLangKey.string": "panel_production_power",
            "neteco.pvms.devTypeLangKey.energy_store": "battery_injection_power",
            "neteco.pvms.KPI.kpiView.electricalLoad": "house_load_power",
        }

        for node in flow_data_nodes:
            label = node.get("name", "")
            value = node.get("description", {}).get("value", "")

            if label == "neteco.pvms.devTypeLangKey.energy_store":
                soc = extract_numeric(node.get("deviceTips", {}).get("SOC", ""))
                if soc is not None:
                    output["battery_percentage"] = soc

                battery_power = extract_numeric(
                    node.get("deviceTips", {}).get("BATTERY_POWER", "")
                )
                if battery_power is None or battery_power <= 0:
                    output["battery_consumption_power"] = extract_numeric(value)
                    output["battery_injection_power"] = 0.0
                else:
                    output[node_map[label]] = extract_numeric(value)
                    output["battery_consumption_power"] = 0.0

            elif label in node_map:
                output[node_map[label]] = extract_numeric(value)

    def _parse_installation_flow_links(
        self,
        flow_data_links: list[dict[str, Any]],
        output: dict[str, float | int | str],
    ) -> None:
        """Parse installation flow links into the output structure."""
        node_map = {
            "neteco.pvms.energy.flow.buy.power": "grid_consumption_power",
            "neteco.pvms.devTypeLangKey.string": "panel_production_power",
            "neteco.pvms.devTypeLangKey.energy_store": "battery_injection_power",
            "neteco.pvms.KPI.kpiView.electricalLoad": "house_load_power",
        }

        for node in flow_data_links:
            label = node.get("description", {}).get("label", "")
            value = node.get("description", {}).get("value", "")
            if label in node_map and label == "neteco.pvms.energy.flow.buy.power":
                grid_consumption_injection = extract_numeric(value)
                if (
                    output["panel_production_power"]
                    + output["battery_consumption_power"]
                    - output["battery_injection_power"]
                    - output["house_load_power"]
                ) > 0:
                    output["grid_injection_power"] = grid_consumption_injection
                    output["grid_consumption_power"] = 0.0
                else:
                    output["grid_consumption_power"] = grid_consumption_injection
                    output["grid_injection_power"] = 0.0

    def _discover_battery_dn_from_flow_nodes(self, flow_data_nodes: list[dict[str, Any]]) -> None:
        """Discover the battery DN from installation flow nodes."""
        if self.battery_dn is not None:
            return

        for node in flow_data_nodes:
            if node.get("name") != "neteco.pvms.devTypeLangKey.energy_store":
                continue

            dev_ids = node.get("devIds") or []
            dn = dev_ids[0] if dev_ids else node.get("devDn")
            if dn:
                self.battery_dn = dn
                _LOGGER.info("Discovered battery DN: %s", self.battery_dn)
                return

    def _enrich_installation_output(
        self,
        output: dict[str, float | int | str],
    ) -> None:
        """Enrich installation output with calculated and external domain data."""
        self.update_output_with_battery_capacity(output)
        self.update_output_with_energy_balance(output)
        self._update_output_with_self_consumption_ratios(output)

        try:
            self.update_output_with_social_contribution(output)
        except Exception as ex:
            _LOGGER.warning("Failed to fetch social contribution data: %s", ex)

        output["exit_code"] = "SUCCESS"
        _LOGGER.debug("output JSON: %s", output)

    def _build_installation_devices(
        self,
        output: dict[str, float | int | str],
    ) -> list[Device]:
        """Build installation-level device entities."""
        return [
            Device(
                device_id=device.get("id"),
                device_unique_id=self.get_device_unique_id(
                    device.get("id"),
                    device.get("type"),
                ),
                device_type=device.get("type"),
                name=self.get_device_name(device.get("id")),
                state=self.get_device_value(
                    device.get("id"),
                    device.get("type"),
                    output,
                ),
                icon=device.get("icon"),
            )
            for device in DEVICES
        ]

    def _build_inverter_devices(self) -> list[Device]:
        """Build inverter device entities."""
        devices: list[Device] = []

        try:
            inverter_data = self.get_inverter_realtime_data()
            signal_map = get_inverter_signal_map()

            for signal_id, value in inverter_data.items():
                if signal_id not in signal_map:
                    continue

                sig = signal_map[signal_id]
                sig_type = sig["type"]

                if sig_type == DeviceType.SENSOR_TEXT:
                    state = str(value)
                else:
                    try:
                        state = float(value)
                    except (ValueError, TypeError):
                        state = 0.0

                devices.append(
                    Device(
                        device_id=sig["id"],
                        device_unique_id=self.get_device_unique_id(
                            sig["id"],
                            sig_type,
                        ),
                        device_type=sig_type,
                        name=sig["id"],
                        state=state,
                        icon=sig["icon"],
                    )
                )

        except Exception as ex:
            _LOGGER.warning("Failed to fetch inverter realtime data: %s", ex)

        return devices

    def _build_battery_devices(self) -> list[Device]:
        """Build battery device entities."""
        try:
            return self.get_battery_devices()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery devices: %s", ex)
            return []

    def get_devices(self) -> list[Device]:
        """Fetch all device entities for the configured station."""
        output = self._build_base_output()

        flow_data_nodes, flow_data_links = self._get_installation_flow_data()

        self._parse_installation_flow_nodes(flow_data_nodes, output)
        self._parse_installation_flow_links(flow_data_links, output)

        self._discover_battery_dn_from_flow_nodes(flow_data_nodes)
        self._discover_inverter_dn_from_flow_nodes(flow_data_nodes)
        self._ensure_inverter_metadata_loaded()

        self._enrich_installation_output(output)

        devices = self._build_installation_devices(output)
        devices.extend(self._build_inverter_devices())
        devices.extend(self._build_battery_devices())

        return devices