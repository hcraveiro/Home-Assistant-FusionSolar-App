"""Read-only optimizer discovery and telemetry from FusionSolar layout endpoints."""

from __future__ import annotations

import html
import json
import logging
from typing import Any

from .models import Device, DeviceType

_LOGGER = logging.getLogger(__name__)
_LAYOUT = "/rest/pvms/web/station/v1/layout"
_COUNTS = "/rest/pvms/web/station/v1/layout/station-simple-devicedata"
_SAMPLING = "/rest/pvms/web/station/v1/layout/device-sampling-data"

# Values from device-sampling-data. Optimizer power is reported in watts.
_FIELDS = (
    ("Optimizer Output Power", "outputPower", DeviceType.SENSOR_KW, "mdi:solar-power"),
    ("Optimizer Input Voltage", "inputVoltage", DeviceType.SENSOR_VOLTAGE, "mdi:flash"),
    ("Optimizer Output Voltage", "outputVoltage", DeviceType.SENSOR_VOLTAGE, "mdi:flash"),
    ("Optimizer Input Current", "inputCurrent", DeviceType.SENSOR_CURRENT, "mdi:current-dc"),
    ("Optimizer Energy Today", "dailyEnergy", DeviceType.SENSOR_KWH, "mdi:solar-power"),
    ("Optimizer Power Percent", "powerPercent", DeviceType.SENSOR_RATIO, "mdi:percent"),
    ("Optimizer Connection", "connectStatus", DeviceType.SENSOR_TEXT, "mdi:lan-connect"),
    ("Optimizer Running Status", "runningStatusVal", DeviceType.SENSOR_COUNT, "mdi:information-outline"),
)


def _parse_optimizer_layout(data: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Read only optimizer DNs from a decoded TWaver layout; never trust layout positions as IDs."""
    payload = data.get("data")
    if not isinstance(payload, dict):
        return {}
    raw = payload.get("schemaData")
    if not isinstance(raw, str):
        return {}
    try:
        schema = json.loads(html.unescape(raw))
    except (ValueError, TypeError):
        return {}
    if not isinstance(schema, dict) or not isinstance(schema.get("datas"), list):
        return {}
    found: dict[str, dict[str, str]] = {}
    for node in schema["datas"]:
        if not isinstance(node, dict):
            continue
        info = node.get("c")
        if not isinstance(info, dict) or info.get("nodetype") != "assembly":
            continue
        if str(info.get("devTypeId", "")) != "20814":
            continue
        dn, parent = info.get("devId"), info.get("parentDevId")
        if not isinstance(dn, str) or not dn.strip() or not isinstance(parent, str) or not parent.strip():
            continue
        found[dn] = {
            "parent_dn": parent,
            "position": str(info.get("assemblyText1") or ""),
            "model": str(info.get("modelVersion") or "FusionSolar Optimizer"),
            "serial": str(info.get("bindNode") or ""),
        }
    return found


def _safe_number(value: Any) -> float | None:
    """Reject placeholders and unexpected values instead of manufacturing zeros."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str) and value.strip() in ("", "--", "null"):
            return None
        number = float(value)
        if not __import__("math").isfinite(number):
            return None
        return number
    except (ValueError, TypeError, OverflowError):
        return None


class FusionSolarOptimizerMixin:
    """Optional optimizer telemetry; errors must never break plant polling."""

    def _optimizer_request(self, method: str, endpoint: str, *, params=None, json_body=None):
        self.refresh_csrf()
        headers = {"Accept": "application/json", "Roarand": self.csrf}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        kwargs = {"headers": headers}
        if params is not None:
            kwargs["params"] = params
        if json_body is not None:
            kwargs["json"] = json_body
        _, result = self._request_json(
            method, f"https://{self.data_host}{endpoint}",
            context="FusionSolar optimizer telemetry", **kwargs
        )
        if not isinstance(result, dict) or result.get("success") is not True:
            raise ValueError("FusionSolar optimizer endpoint did not succeed")
        return result.get("data")

    def get_optimizer_devices(self) -> list[Device]:
        """Discover topology once and poll all optimizer DNs in a single request."""
        if not self.station:
            return []
        topology = getattr(self, "_optimizers", None)
        if topology is None:
            counts = self._optimizer_request(
                "GET", _COUNTS, params={"stationDn": self.station}
            )
            if not isinstance(counts, dict) or _safe_number(counts.get("optimizerNum")) in (None, 0):
                self._optimizers = {}
                return []
            layout = self._optimizer_request(
                "GET", _LAYOUT,
                params={"stationDn": self.station, "sheetNO": 0, "callerType": 0, "queryType": 0},
            )
            topology = _parse_optimizer_layout({"data": layout})
            # Do not permanently cache a malformed topology; retry next poll.
            if not topology:
                return []
            self._optimizers = topology
        if not topology:
            return []
        records = self._optimizer_request("POST", _SAMPLING, json_body=list(topology))
        if not isinstance(records, list):
            return []
        devices = []
        for record in records:
            if not isinstance(record, dict) or str(record.get("mocId")) != "20814":
                continue
            dn = record.get("dn")
            if not isinstance(dn, str) or dn not in topology:
                continue
            extra = record.get("optInfo") or {}
            if not isinstance(extra, dict):
                extra = {}
            is_disconnected = str(record.get("connectStatus") or "").strip().lower() in {
                "disconnected", "offline"
            }
            for name, key, dtype, icon in _FIELDS:
                raw = (extra.get(key) if key not in ("dailyEnergy", "powerPercent", "connectStatus") else record.get(key))
                if name == "Optimizer Running Status" and raw is None:
                    raw = record.get("runningStatus")
                if dtype == DeviceType.SENSOR_TEXT:
                    value = str(raw) if raw not in (None, "", "--") else None
                else:
                    value = _safe_number(raw)
                    if value is not None and key == "outputPower":
                        value /= 1000
                # Retain sensor identity while removing stale instantaneous readings.
                if is_disconnected and key in {
                    "outputPower", "inputVoltage", "outputVoltage", "inputCurrent", "powerPercent"
                }:
                    value = None
                if value is None and not (
                    is_disconnected and key in {
                        "outputPower", "inputVoltage", "outputVoltage", "inputCurrent", "powerPercent"
                    }
                ):
                    continue
                devices.append(Device(
                    device_id=name,
                    device_unique_id=self.get_device_unique_id(name, dtype, dn=dn),
                    device_type=dtype,
                    name=name.replace("Optimizer ", ""),
                    state=value,
                    icon=icon,
                    dn=dn,
                ))
        return devices
