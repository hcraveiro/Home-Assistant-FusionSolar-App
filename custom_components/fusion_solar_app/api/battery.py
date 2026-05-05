import re
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
    
        for module_index in range(1, 5):
            module_model = battery_type_data.get(f"module{module_index}DevType")
            if module_model and module_model not in ("ESS", "--", "null"):
                self.battery_model = module_model
                break
    
        if not self.battery_model:
            module_model = battery_type_data.get("moduleDevType")
            if module_model and module_model not in ("ESS", "--", "null"):
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

    def _update_battery_metadata_from_module_name_map(
        self,
        module_name_map: dict[str, Any],
    ) -> None:
        """Update battery metadata from the first available DC/DC module data."""
        if not self.battery_serial_number:
            for key, value in module_name_map.items():
                if key.endswith("[DC/DC] SN") and value not in (None, "", "--", "null"):
                    self.battery_serial_number = str(value)
                    break
    
        if not self.battery_software_version:
            for key, value in module_name_map.items():
                if key.endswith("[DC/DC] Software version") and value not in (None, "", "--", "null"):
                    self.battery_software_version = str(value)
                    break
    
        _LOGGER.debug(
            "Battery metadata loaded: model=%s sw=%s sn=%s",
            self.battery_model,
            self.battery_software_version,
            self.battery_serial_number,
        )

    def get_battery_module_data(self, module_id: int) -> list[dict[str, Any]]:
        """Fetch extended battery data for the requested module."""
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
            "moduleId": module_id,
            "_": int(time.time() * 1000),
        }
    
        url = f"https://{self.data_host}{BATTERY_DC_URL}"
        _LOGGER.debug("Getting battery module %s data at: %s", module_id, url)
    
        _, data = self._request_json(
            "GET",
            url,
            context=f"FusionSolar battery module {module_id} data",
            headers=headers,
            params=params,
        )
    
        module_data = data.get("data", [])
        if not isinstance(module_data, list):
            raise APIDataStructureError(
                f"Battery module {module_id} response did not contain a list"
            )
    
        _LOGGER.debug("Battery module %s data: %s", module_id, module_data)
        return module_data

    def get_battery_devices(self) -> list[Device]:
        """Return battery device entities, battery module entities and battery pack entities."""
        if not self.battery_dn:
            return []
    
        devices: list[Device] = []
    
        battery_type_data: dict[str, Any] = {}
        try:
            battery_type_response = self.get_battery_type()
            battery_type_data = battery_type_response.get("data", {})
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery type: %s", ex)
    
        realtime_data: dict[int, Any] = {}
        try:
            realtime_data = self.get_battery_realtime_data()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch battery realtime data: %s", ex)
    
        battery_realtime_definitions = [
            (
                "Battery Operating Status",
                DeviceType.SENSOR_TEXT,
                realtime_data.get(10003),
                "mdi:battery-heart-variant",
            ),
            (
                "Battery Charge/Discharge Mode",
                DeviceType.SENSOR_TEXT,
                realtime_data.get(10008),
                "mdi:battery-sync",
            ),
            (
                "Battery Backup Time",
                DeviceType.SENSOR_TEXT,
                realtime_data.get(10015),
                "mdi:clock-outline",
            ),
            (
                "Battery Energy Charged Today",
                DeviceType.SENSOR_KWH,
                realtime_data.get(10001),
                "mdi:battery-arrow-up",
            ),
            (
                "Battery Energy Discharged Today",
                DeviceType.SENSOR_KWH,
                realtime_data.get(10002),
                "mdi:battery-arrow-down",
            ),
            (
                "Battery Charge/Discharge Power",
                DeviceType.SENSOR_KW,
                realtime_data.get(10004),
                "mdi:flash",
            ),
            (
                "Battery Bus Voltage",
                DeviceType.SENSOR_VOLTAGE,
                realtime_data.get(10005),
                "mdi:flash",
            ),
        ]
    
        for device_id, device_type, raw_value, icon in battery_realtime_definitions:
            device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
            if device is not None:
                devices.append(device)
    
        module_ids = self._get_available_battery_module_ids(battery_type_data)
    
        for module_id in module_ids:
            try:
                module_data = self.get_battery_module_data(module_id)
            except Exception as ex:
                _LOGGER.warning(
                    "Failed to fetch battery module %s data: %s",
                    module_id,
                    ex,
                )
                continue
    
            module_name_map = self._extract_battery_module_name_map(module_data)
            if not module_name_map:
                continue
    
            self._update_battery_metadata_from_module_name_map(module_name_map)
            devices.extend(self._build_battery_module_devices(module_id, module_name_map))
            devices.extend(self._build_battery_pack_devices(module_id, module_name_map))
    
        _LOGGER.debug("Battery devices created: %s", [device.device_id for device in devices])
        return devices
        
    def _get_available_battery_module_ids(
        self,
        battery_type_data: dict[str, Any] | None = None,
    ) -> list[int]:
        """Return the available battery module IDs."""
        module_ids: list[int] = []
    
        if isinstance(battery_type_data, dict):
            for module_index in range(1, 5):
                module_value = battery_type_data.get(f"module{module_index}DevType")
                if module_value not in (None, "", "--", "null", "ESS"):
                    module_ids.append(module_index)
    
        if module_ids:
            return module_ids
    
        detected_module_ids: list[int] = []
        for module_index in range(1, 5):
            try:
                module_data = self.get_battery_module_data(module_index)
            except Exception as ex:
                _LOGGER.debug(
                    "Battery module probe failed for module %s: %s",
                    module_index,
                    ex,
                )
                continue
    
            module_name_map = self._extract_battery_module_name_map(module_data)
            if module_name_map:
                detected_module_ids.append(module_index)
    
        if detected_module_ids:
            return detected_module_ids
    
        return [1]

    def _extract_battery_module_name_map(
        self,
        module_data: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Convert battery module data into a name-to-value map."""
        module_name_map: dict[str, Any] = {}
    
        for item in module_data:
            name = item.get("name")
            if not name:
                continue
    
            raw_value = item.get("realValue")
            if raw_value in (None, ""):
                raw_value = item.get("value")
    
            module_name_map[name] = raw_value
    
        return module_name_map
    
    def _build_battery_module_devices(
        self,
        module_id: int,
        module_name_map: dict[str, Any],
    ) -> list[Device]:
        """Build battery module device entities."""
        devices: list[Device] = []
    
        battery_module_definitions = [
            (
                f"Battery Module {module_id} Bus Current",
                DeviceType.SENSOR_CURRENT,
                module_name_map.get(f"[Module {module_id}] [DC/DC] Bus current"),
                "mdi:current-dc",
            ),
            (
                f"Battery Module {module_id} Internal Temperature",
                DeviceType.SENSOR_TEMPERATURE,
                module_name_map.get(f"[Module {module_id}] [DC/DC] Internal temperature"),
                "mdi:thermometer",
            ),
            (
                f"Battery Module {module_id} Total Charge Energy",
                DeviceType.SENSOR_KWH,
                module_name_map.get(f"[Module {module_id}] Total charge energy"),
                "mdi:battery-arrow-up",
            ),
            (
                f"Battery Module {module_id} Total Discharge Energy",
                DeviceType.SENSOR_KWH,
                module_name_map.get(f"[Module {module_id}] Total discharge energy"),
                "mdi:battery-arrow-down",
            ),
        ]
    
        for device_id, device_type, raw_value, icon in battery_module_definitions:
            device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
            if device is not None:
                devices.append(device)
    
        return devices
        
    def _build_battery_pack_devices(
        self,
        module_id: int,
        module_name_map: dict[str, Any],
    ) -> list[Device]:
        """Build battery pack device entities for the given module."""
        devices: list[Device] = []
    
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
    
        pack_quantity_raw = module_name_map.get(f"[Module {module_id}] Battery pack quantity")
        pack_quantity = 0
        if pack_quantity_raw not in (None, "", "--", "null"):
            try:
                pack_quantity = int(round(extract_numeric(pack_quantity_raw)))
            except (TypeError, ValueError):
                pack_quantity = 0
    
        detected_pack_indexes: set[int] = set()
        pack_regex = re.compile(
            rf"^\[Module {module_id}\] \[Battery pack (\d+)\] "
        )
    
        for key in module_name_map:
            match = pack_regex.match(key)
            if match:
                detected_pack_indexes.add(int(match.group(1)))
    
        if pack_quantity > 0:
            pack_indexes = sorted(detected_pack_indexes | set(range(1, pack_quantity + 1)))
        else:
            pack_indexes = sorted(detected_pack_indexes)
    
        for pack_index in pack_indexes:
            pack_prefix = f"[Module {module_id}] [Battery pack {pack_index}] "
            pack_status_key = f"{pack_prefix}Operating status"
    
            if pack_status_key not in module_name_map:
                continue
    
            for metric_name, (device_type, icon) in battery_pack_definitions.items():
                raw_value = module_name_map.get(f"{pack_prefix}{metric_name}")
                device_id = f"Battery Module {module_id} Pack {pack_index} {metric_name}"
                device = self._create_dynamic_device(device_id, device_type, raw_value, icon)
                if device is not None:
                    devices.append(device)
    
        return devices