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
            "panel_production_power": None,
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
            "house_load_power": None,
            "house_load_today": 0.0,
            "house_load_week": 0.0,
            "house_load_month": 0.0,
            "house_load_year": 0.0,
            "house_load_lifetime": 0.0,
            "grid_consumption_power": None,
            "grid_consumption_today": 0.0,
            "grid_consumption_week": 0.0,
            "grid_consumption_month": 0.0,
            "grid_consumption_year": 0.0,
            "grid_consumption_lifetime": 0.0,
            "grid_injection_power": None,
            "grid_injection_today": 0.0,
            "grid_injection_week": 0.0,
            "grid_injection_month": 0.0,
            "grid_injection_year": 0.0,
            "grid_injection_lifetime": 0.0,
            "battery_injection_power": None,
            "battery_injection_today": 0.0,
            "battery_injection_week": 0.0,
            "battery_injection_month": 0.0,
            "battery_injection_year": 0.0,
            "battery_injection_lifetime": 0.0,
            "battery_consumption_power": None,
            "battery_consumption_today": 0.0,
            "battery_consumption_week": 0.0,
            "battery_consumption_month": 0.0,
            "battery_consumption_year": 0.0,
            "battery_consumption_lifetime": 0.0,
            "battery_percentage": None,
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

    @staticmethod
    def _valid_flow_power(raw: Any) -> float | None:
        """Return an actual flow reading, never treating placeholders as zero."""
        if raw is None or isinstance(raw, bool):
            return None
        if isinstance(raw, str) and raw.strip().lower() in {"", "--", "null", "none"}:
            return None
        try:
            value = extract_numeric(raw)
            # extract_numeric returns zero for malformed strings; reject those.
            if isinstance(raw, str):
                float(raw.strip().split()[0])
            return value
        except (ValueError, TypeError, IndexError):
            return None

    def _parse_installation_flow_nodes(
        self,
        flow_data_nodes: list[dict[str, Any]],
        output: dict[str, float | int | str],
    ) -> None:
        """Parse actual flow readings; leave missing values unknown."""
        node_map = {
            "neteco.pvms.energy.flow.buy.power": "grid_consumption_power",
            "neteco.pvms.devTypeLangKey.string": "panel_production_power",
            "neteco.pvms.devTypeLangKey.energy_store": "battery_injection_power",
            "neteco.pvms.KPI.kpiView.electricalLoad": "house_load_power",
        }
        for node in flow_data_nodes:
            if not isinstance(node, dict):
                continue
            label = node.get("name", "")
            description = node.get("description") or {}
            value = self._valid_flow_power(description.get("value"))
            if label == "neteco.pvms.devTypeLangKey.energy_store":
                tips = node.get("deviceTips") or {}
                soc_raw = tips.get("SOC")
                if soc_raw not in (None, "", "--", "null"):
                    output["battery_percentage"] = self._valid_flow_power(soc_raw)
                signed_power = self._valid_flow_power(tips.get("BATTERY_POWER"))
                if value is None or signed_power is None:
                    continue
                if signed_power <= 0:
                    output["battery_consumption_power"] = value
                    output["battery_injection_power"] = 0.0
                else:
                    output["battery_injection_power"] = value
                    output["battery_consumption_power"] = 0.0
            elif label in node_map and value is not None:
                output[node_map[label]] = value

    def _parse_installation_flow_links(
        self,
        flow_data_links: list[dict[str, Any]],
        output: dict[str, float | int | str],
    ) -> None:
        """Determine grid flow direction only when all inputs are measured."""
        for node in flow_data_links:
            if not isinstance(node, dict):
                continue
            description = node.get("description") or {}
            if description.get("label") != "neteco.pvms.energy.flow.buy.power":
                continue
            grid_power = self._valid_flow_power(description.get("value"))
            keys = (
                "panel_production_power",
                "battery_consumption_power",
                "battery_injection_power",
                "house_load_power",
            )
            # Previously discovered batteries are not absent merely because telemetry drops.
            # Only a known zero capacity with no discovered DN establishes no battery.
            confirmed_no_battery = (
                getattr(self, "battery_dn", None) is None
                and getattr(self, "battery_capacity", None) == 0
            )
            if confirmed_no_battery:
                output["battery_consumption_power"] = 0.0
                output["battery_injection_power"] = 0.0
            if grid_power is None or any(output.get(key) is None for key in keys):
                continue
            balance = (
                output["panel_production_power"]
                + output["battery_consumption_power"]
                - output["battery_injection_power"]
                - output["house_load_power"]
            )
            if balance > 0:
                output["grid_injection_power"] = grid_power
                output["grid_consumption_power"] = 0.0
            else:
                output["grid_consumption_power"] = grid_power
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
        """Build inverter realtime, derived and metadata device entities."""
        devices: list[Device] = []

        try:
            devices.extend(self.get_inverter_metadata_devices())
        except Exception as ex:
            _LOGGER.warning("Failed to build inverter metadata devices: %s", ex)

        try:
            inverter_data = self.get_inverter_realtime_data()
            signal_map = get_inverter_signal_map()

            for signal_id, value in inverter_data.items():
                if signal_id not in signal_map:
                    continue

                sig = signal_map[signal_id]
                device = self._create_dynamic_device(
                    sig["id"],
                    sig["type"],
                    value,
                    sig["icon"],
                )
                if device is not None:
                    devices.append(device)

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

    def _build_power_sensor_devices(
        self,
        flow_data_nodes: list[dict[str, Any]],
    ) -> list[Device]:
        """Build power sensor device entities."""
        try:
            return self.get_power_sensor_devices(flow_data_nodes)
        except Exception as ex:
            _LOGGER.warning("Failed to fetch power sensor devices: %s", ex)
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
        devices.extend(self._build_power_sensor_devices(flow_data_nodes))
    
        return devices
