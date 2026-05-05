"""Fusion Solar App power sensor helpers."""

import logging
import time
from typing import Any

from ..const import DATA_REFERER_URL, DEVICE_REALTIME_DATA_URL, INVERTER_CONFIG_SIGNAL_URL
from ..utils import extract_numeric
from .models import Device, DeviceType


_LOGGER = logging.getLogger(__name__)


POWER_SENSOR_SIGNAL_MAP = {
    10001: {
        "id": "Power Sensor Status",
        "type": DeviceType.SENSOR_TEXT,
        "icon": "mdi:information-outline",
    },
    10002: {
        "id": "Power Sensor Grid Voltage",
        "type": DeviceType.SENSOR_VOLTAGE,
        "icon": "mdi:flash",
    },
    10003: {
        "id": "Power Sensor Grid Current",
        "type": DeviceType.SENSOR_CURRENT,
        "icon": "mdi:current-ac",
    },
    10004: {
        "id": "Power Sensor Active Power",
        "type": DeviceType.SENSOR_KW,
        "icon": "mdi:flash",
    },
    10006: {
        "id": "Power Sensor Power Factor",
        "type": DeviceType.SENSOR_POWER_FACTOR,
        "icon": "mdi:angle-acute",
    },
    10007: {
        "id": "Power Sensor Grid Frequency",
        "type": DeviceType.SENSOR_FREQUENCY,
        "icon": "mdi:sine-wave",
    },
    10008: {
        "id": "Power Sensor Grid Consumption Total",
        "type": DeviceType.SENSOR_KWH,
        "icon": "mdi:transmission-tower-export",
    },
    10009: {
        "id": "Power Sensor Grid Injection Total",
        "type": DeviceType.SENSOR_KWH,
        "icon": "mdi:transmission-tower-import",
    },
}


class FusionSolarPowerSensorMixin:
    """Power sensor helpers for FusionSolar API."""

    def _discover_power_sensor_dn_from_flow_nodes(
        self,
        flow_data_nodes: list[dict[str, Any]],
    ) -> None:
        """Discover the power sensor DN from installation flow nodes."""
        if self.power_sensor_dn is not None:
            return

        candidate_labels = {
            "neteco.pvms.devTypeLangKey.powerMeter",
            "neteco.pvms.devTypeLangKey.powermeter",
            "neteco.pvms.devTypeLangKey.power_meter",
            "neteco.pvms.devTypeLangKey.meter",
            "neteco.pvms.devTypeLangKey.smartmeter",
            "neteco.pvms.devTypeLangKey.smart_meter",
        }

        for node in flow_data_nodes:
            label = str(node.get("name", ""))

            has_device_reference = bool(node.get("devIds") or node.get("devDn"))
            if not has_device_reference:
                continue

            if label not in candidate_labels and "meter" not in label.lower():
                continue

            dev_ids = node.get("devIds") or []
            dn = dev_ids[0] if dev_ids else node.get("devDn")
            if dn:
                self.power_sensor_dn = dn
                _LOGGER.info("Discovered power sensor DN: %s", self.power_sensor_dn)
                return

    def _normalize_power_sensor_usage(self, raw_value: Any) -> str | None:
        """Normalize the power sensor usage value."""
        if raw_value in (None, "", "--", "null"):
            return None

        normalized = str(raw_value).strip()

        usage_map = {
            "1": "Export+import meter",
            "2": "Production meter",
            "3": "Consumption meter",
        }

        return usage_map.get(normalized, normalized)

    def _normalize_power_sensor_signal_value(
        self,
        signal_id: int,
        raw_value: Any,
    ) -> Any:
        """Normalize raw power sensor signal values."""
        if raw_value in (None, "", "--", "null"):
            return None

        if signal_id == 10004:
            return round(float(extract_numeric(raw_value)) / 1000, 4)

        return raw_value

    def get_power_sensor_config_info(self) -> dict:
        """Fetch power sensor metadata such as name, model, firmware, serial number and usage."""
        if not self.power_sensor_dn:
            return {}
    
        self.refresh_csrf()
    
        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }
    
        params = {
            "dn": self.power_sensor_dn,
            "signals": "50009,50010,50012,33595393,20004",
            "_": int(time.time() * 1000),
        }
    
        url = f"https://{self.data_host}{INVERTER_CONFIG_SIGNAL_URL}"
        _LOGGER.debug("Getting power sensor config info at: %s", url)
    
        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar power sensor config info",
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
            self.power_sensor_name = str(parsed["33595393"])
    
        if "50009" in parsed:
            self.power_sensor_model = str(parsed["50009"])
    
        if "50010" in parsed:
            self.power_sensor_software_version = str(parsed["50010"])
    
        if "50012" in parsed:
            self.power_sensor_serial_number = str(parsed["50012"])
    
        if "20004" in parsed:
            self.power_sensor_usage = self._normalize_power_sensor_usage(parsed["20004"])
    
        _LOGGER.debug(
            "Power sensor config info loaded: name=%s model=%s sw=%s sn=%s usage=%s",
            self.power_sensor_name,
            self.power_sensor_model,
            self.power_sensor_software_version,
            self.power_sensor_serial_number,
            self.power_sensor_usage,
        )
    
        return data

    def get_power_sensor_realtime_data(self) -> dict[int, Any]:
        """Fetch realtime power sensor data."""
        if not self.power_sensor_dn:
            return {}

        self.refresh_csrf()

        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }

        params = {
            "deviceDn": self.power_sensor_dn,
            "displayAccessModel": "true",
        }

        url = f"https://{self.data_host}{DEVICE_REALTIME_DATA_URL}"
        _LOGGER.debug("Getting power sensor realtime data at: %s", url)

        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar power sensor realtime data",
            headers=headers,
            params=params,
        )

        if not data.get("success") or not data.get("data"):
            _LOGGER.warning("Power sensor realtime data response indicates failure: %s", data)
            return {}

        result: dict[int, Any] = {}

        for entry in data["data"]:
            if not isinstance(entry, dict) or "signals" not in entry:
                continue

            for signal in entry["signals"]:
                signal_id = signal.get("id")
                signal_value = signal.get("value", "")

                if signal_id not in POWER_SENSOR_SIGNAL_MAP:
                    continue

                normalized_value = self._normalize_power_sensor_signal_value(
                    signal_id,
                    signal_value,
                )
                if normalized_value is None:
                    continue

                result[signal_id] = normalized_value

        _LOGGER.debug("Power sensor realtime data: %s", result)
        return result

    def get_power_sensor_devices(
        self,
        flow_data_nodes: list[dict[str, Any]] | None = None,
    ) -> list[Device]:
        """Return power sensor device entities."""
        if self.power_sensor_dn is None and flow_data_nodes:
            self._discover_power_sensor_dn_from_flow_nodes(flow_data_nodes)
    
        if not self.power_sensor_dn:
            return []
    
        devices: list[Device] = []
    
        try:
            self.get_power_sensor_config_info()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch power sensor config info: %s", ex)
    
        try:
            self.get_power_sensor_type_name()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch power sensor type name: %s", ex)
    
        realtime_data: dict[int, Any] = {}
        try:
            realtime_data = self.get_power_sensor_realtime_data()
        except Exception as ex:
            _LOGGER.warning("Failed to fetch power sensor realtime data: %s", ex)
    
        if self.power_sensor_usage not in (None, "", "--", "null"):
            usage_device = self._create_dynamic_device(
                "Power Sensor Usage",
                DeviceType.SENSOR_TEXT,
                self.power_sensor_usage,
                "mdi:meter-electric",
            )
            if usage_device is not None:
                devices.append(usage_device)
    
        active_power = realtime_data.get(10004)
        if active_power not in (None, "", "--", "null"):
            direction_device = self._create_dynamic_device(
                "Power Sensor Direction",
                DeviceType.SENSOR_TEXT,
                self._get_power_sensor_direction(active_power),
                "mdi:swap-horizontal",
            )
            if direction_device is not None:
                devices.append(direction_device)
    
        for signal_id, signal_info in POWER_SENSOR_SIGNAL_MAP.items():
            raw_value = realtime_data.get(signal_id)
            device = self._create_dynamic_device(
                signal_info["id"],
                signal_info["type"],
                raw_value,
                signal_info["icon"],
            )
            if device is not None:
                devices.append(device)
    
        _LOGGER.debug(
            "Power sensor devices created: %s",
            [device.device_id for device in devices],
        )
        return devices

    def get_power_sensor_type_name(self) -> str | None:
        """Fetch the power sensor type name."""
        if not self.power_sensor_dn:
            return None
    
        self.refresh_csrf()
    
        headers = {
            "Accept": "application/json",
            "Roarand": self.csrf,
            "Referer": f"https://{self.data_host}{DATA_REFERER_URL}",
        }
    
        params = {
            "deviceDn": self.power_sensor_dn,
            "_": int(time.time() * 1000),
        }
    
        url = f"https://{self.data_host}/rest/neteco/web/config/device/v1/moc-type-name"
        _LOGGER.debug("Getting power sensor type name at: %s", url)
    
        _, data = self._request_json(
            "GET",
            url,
            context="FusionSolar power sensor type name",
            headers=headers,
            params=params,
        )
    
        type_name = data.get("data")
        if type_name:
            self.power_sensor_model = str(type_name)
    
        return self.power_sensor_model
    
    def _get_power_sensor_direction(self, active_power: Any) -> str:
        """Return the power sensor direction from signed active power."""
        power_value = extract_numeric(active_power)
    
        if power_value > 0:
            return "exporting"
    
        if power_value < 0:
            return "importing"
    
        return "idle"