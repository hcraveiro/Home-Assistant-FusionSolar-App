import logging
import time
from typing import Any

from ..const import BATTERY_DC_URL, BATTERY_TYPE_URL, DATA_REFERER_URL, DEVICE_REALTIME_DATA_URL
from .exceptions import APIDataStructureError
from .models import Device, DeviceType
from .signal_maps import BATTERY_MODULE_1_SIGNAL_IDS


_LOGGER = logging.getLogger(__name__)


class FusionSolarBatteryMixin:
    """Battery helpers for FusionSolar API."""

    def get_battery_type(self) -> dict:
        """Fetch battery type information."""
        if not self.battery_dn:
            return {}

        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }

        params = {
            "deviceDn": self.battery_dn,
            "_": int(time.time() * 1000),
        }

        url = f"https://{self.data_host}{BATTERY_TYPE_URL}"
        _LOGGER.debug("Getting battery type at: %s", url)

        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar battery type",
            headers=headers,
            params=params,
        )

        battery_type_data = data.get("data", {})
        module_1_model = battery_type_data.get("module1DevType")
        module_model = battery_type_data.get("moduleDevType")

        if module_1_model and module_1_model != "ESS":
            self.battery_model = module_1_model
        elif module_model and module_model != "ESS":
            self.battery_model = module_model

        return data

    def get_battery_realtime_data(self) -> dict[int, Any]:
        """Fetch battery realtime data from the device endpoint."""
        if not self.battery_dn:
            return {}

        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }

        params = {
            "deviceDn": self.battery_dn,
            "displayAccessModel": "true",
        }

        url = f"https://{self.data_host}{DEVICE_REALTIME_DATA_URL}"
        _LOGGER.debug("Getting battery realtime data at: %s", url)

        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar battery realtime data",
            headers=headers,
            params=params,
        )

        if not data.get("success") or not data.get("data"):
            _LOGGER.warning("Battery realtime data response indicates failure: %s", data)
            return {}

        result: dict[int, Any] = {}

        for entry in data["data"]:
            if not isinstance(entry, dict) or "signals" not in entry:
                continue

            for signal in entry["signals"]:
                signal_id = signal.get("id")
                signal_value = signal.get("value", "")

                if signal_id is None:
                    continue

                result[signal_id] = signal_value

        _LOGGER.debug("Battery realtime data: %s", result)
        return result

    def _update_battery_metadata_from_module_1_data(
        self,
        module_1_name_map: dict[str, Any],
    ) -> None:
        """Update battery metadata from module 1 data when available."""
        serial_value = module_1_name_map.get("[Module 1] [DC/DC] SN")
        if serial_value not in (None, "", "--", "null"):
            self.battery_serial_number = str(serial_value)

        software_value = module_1_name_map.get("[Module 1] [DC/DC] Software version")
        if software_value not in (None, "", "--", "null"):
            self.battery_software_version = str(software_value)

        _LOGGER.debug(
            "Battery metadata loaded: model=%s sw=%s sn=%s",
            self.battery_model,
            self.battery_software_version,
            self.battery_serial_number,
        )

    def get_battery_module_1_data(self) -> list[dict[str, Any]]:
        """Fetch extended battery data for module 1."""
        if not self.battery_dn:
            return []

        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }

        params = {
            "dn": self.battery_dn,
            "sigids": ",".join(str(signal_id) for signal_id in BATTERY_MODULE_1_SIGNAL_IDS),
            "moduleId": 1,
            "_": int(time.time() * 1000),
        }

        url = f"https://{self.data_host}{BATTERY_DC_URL}"
        _LOGGER.debug("Getting battery module 1 data at: %s", url)

        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar battery module 1 data",
            headers=headers,
            params=params,
        )

        module_data = data.get("data", [])
        if not isinstance(module_data, list):
            raise APIDataStructureError("Battery module 1 response did not contain a list")

        _LOGGER.debug("Battery module 1 data: %s", module_data)
        return module_data

    def get_battery_devices(self) -> list[Device]:
        """Return battery device entities and battery pack diagnostic entities."""
        if not self.battery_dn:
            return []

        devices: list[Device] = []

        try:
            self.get_battery_type()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery type: %s", ex)

        realtime_data: dict[int, Any] = {}
        try:
            realtime_data = self.get_battery_realtime_data()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery realtime data: %s", ex)

        module_1_data: list[dict[str, Any]] = []
        try:
            module_1_data = self.get_battery_module_1_data()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery module 1 data: %s", ex)

        battery_realtime_definitions = [
            ("Battery Operating Status", DeviceType.SENSOR_TEXT, realtime_data.get(10003), "mdi:battery-heart-variant"),
            ("Battery Charge/Discharge Mode", DeviceType.SENSOR_TEXT, realtime_data.get(10008), "mdi:battery-sync"),
            ("Battery Backup Time", DeviceType.SENSOR_TEXT, realtime_data.get(10015), "mdi:clock-outline"),
            ("Battery Energy Charged Today", DeviceType.SENSOR_KWH, realtime_data.get(10001), "mdi:battery-arrow-up"),
            ("Battery Energy Discharged Today", DeviceType.SENSOR_KWH, realtime_data.get(10002), "mdi:battery-arrow-down"),
            ("Battery Charge/Discharge Power", DeviceType.SENSOR_KW, realtime_data.get(10004), "mdi:flash"),
            ("Battery Bus Voltage", DeviceType.SENSOR_VOLTAGE, realtime_data.get(10005), "mdi:flash"),
        ]

        for device_id, device_type, raw_value, icon in battery_realtime_definitions:
            device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
            if device is not None:
                devices.append(device)

        module_1_name_map: dict[str, Any] = {}
        for item in module_1_data:
            name = item.get("name")
            if not name:
                continue

            raw_value = item.get("realValue")
            if raw_value in (None, ""):
                raw_value = item.get("value")

            module_1_name_map[name] = raw_value

        self._update_battery_metadata_from_module_1_data(module_1_name_map)

        battery_module_definitions = [
            ("Battery Bus Current", DeviceType.SENSOR_CURRENT, module_1_name_map.get("[Module 1] [DC/DC] Bus current"), "mdi:current-dc"),
            ("Battery Internal Temperature", DeviceType.SENSOR_TEMPERATURE, module_1_name_map.get("[Module 1] [DC/DC] Internal temperature"), "mdi:thermometer"),
            ("Battery Total Charge Energy", DeviceType.SENSOR_KWH, module_1_name_map.get("[Module 1] Total charge energy"), "mdi:battery-arrow-up"),
            ("Battery Total Discharge Energy", DeviceType.SENSOR_KWH, module_1_name_map.get("[Module 1] Total discharge energy"), "mdi:battery-arrow-down"),
        ]

        for device_id, device_type, raw_value, icon in battery_module_definitions:
            device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
            if device is not None:
                devices.append(device)

        battery_pack_definitions = {
            "Operating status": (DeviceType.SENSOR_TEXT, "mdi:battery-medium"),
            "Voltage": (DeviceType.SENSOR_VOLTAGE, "mdi:flash"),
            "Charge/Discharge power": (DeviceType.SENSOR_KW, "mdi:flash"),
            "Maximum temperature": (DeviceType.SENSOR_TEMPERATURE, "mdi:thermometer-high"),
            "Minimum temperature": (DeviceType.SENSOR_TEMPERATURE, "mdi:thermometer-low"),
            "Total discharge energy": (DeviceType.SENSOR_KWH, "mdi:battery-arrow-down"),
            "SOH": (DeviceType.SENSOR_PERCENTAGE, "mdi:battery-check"),
            "Battery Health Check": (DeviceType.SENSOR_TEXT, "mdi:heart-pulse"),
            "Heating Status": (DeviceType.SENSOR_TEXT, "mdi:radiator"),
        }

        for pack_index in range(1, 4):
            pack_prefix = f"[Module 1] [Battery pack {pack_index}] "
            pack_status_key = f"{pack_prefix}Operating status"

            if pack_status_key not in module_1_name_map:
                continue

            for metric_name, (device_type, icon) in battery_pack_definitions.items():
                raw_value = module_1_name_map.get(f"{pack_prefix}{metric_name}")
                device_id = f"Battery Pack {pack_index} {metric_name}"
                device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
                if device is not None:
                    devices.append(device)

        _LOGGER.debug("Battery devices created: %s", [device.device_id for device in devices])
        return devices
