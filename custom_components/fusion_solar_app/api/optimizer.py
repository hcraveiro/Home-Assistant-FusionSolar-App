"""Read-only optimizer discovery and telemetry from FusionSolar layout endpoints."""

from __future__ import annotations

import html
import json
import logging
from typing import Any

from .models import Device, DeviceType, is_periodic_energy_counter

_LOGGER = logging.getLogger(__name__)
_LAYOUT = "/rest/pvms/web/station/v1/layout"
_COUNTS = "/rest/pvms/web/station/v1/layout/station-simple-devicedata"
_SAMPLING = "/rest/pvms/web/station/v1/layout/device-sampling-data"
_OPTIMIZER_INFO = "/rest/pvms/web/station/v1/layout/optimizer-info"
_LOGICAL_TREE = "/rest/pvms/web/station/v1/layout/device-tree-page"

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
    # Some layouts contain only assembly nodes. Validate ownership when the
    # inverter nodes are present, without rejecting those older layouts.
    inverters = {
        info["devId"] for node in schema["datas"]
        if isinstance(node, dict)
        and isinstance(info := node.get("c"), dict)
        and (info.get("nodetype") == "inverter" or str(info.get("devTypeId")) == "20822")
        and isinstance(info.get("devId"), str) and info["devId"].strip()
    }
    found: dict[str, dict[str, str]] = {}
    conflicting: set[str] = set()
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
        if (inverters and parent not in inverters) or dn in conflicting:
            continue
        if dn in found and found[dn]["parent_dn"] != parent:
            del found[dn]
            conflicting.add(dn)
            continue
        found[dn] = {
            "parent_dn": parent,
            "position": str(info.get("assemblyText1") or ""),
            "model": str(info.get("modelVersion") or "FusionSolar Optimizer"),
            "serial": str(info.get("bindNode") or ""),
        }
    return found



def _parse_optimizer_logical_tree(data: Any) -> dict[str, dict[str, str]]:
    """Discover optimizer DNs from the logical inverter tree when no physical layout exists.

    The logical tree uses bindInverterDn for optimizer ownership. parentDn
    is not an inverter reference in this topology.
    """
    if not isinstance(data, dict) or not isinstance(data.get("list"), list):
        return {}

    inverters = {
        node["dn"] for node in data["list"]
        if isinstance(node, dict)
        and str(node.get("mocId")) == "20822"
        and isinstance(node.get("dn"), str)
        and node["dn"].strip()
    }
    found: dict[str, dict[str, str]] = {}
    conflicting: set[str] = set()
    for inverter in data["list"]:
        if not isinstance(inverter, dict) or str(inverter.get("mocId")) != "20822":
            continue
        children = inverter.get("children")
        if not isinstance(children, list):
            continue
        for child in children:
            if not isinstance(child, dict) or str(child.get("mocId")) != "20814":
                continue
            dn = child.get("dn")
            parent = child.get("bindInverterDn")
            if (
                not isinstance(dn, str) or not dn.strip()
                or not isinstance(parent, str) or parent not in inverters
                or parent != inverter.get("dn") or dn in conflicting
            ):
                continue
            entry = {
                "parent_dn": parent,
                "position": str(child.get("pvNum") or child.get("deviceNumber") or ""),
                "model": str(child.get("meType") or "FusionSolar Optimizer"),
                "serial": str(child.get("sn") or ""),
            }
            if dn in found and found[dn]["parent_dn"] != parent:
                del found[dn]
                conflicting.add(dn)
            else:
                found[dn] = entry
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
            context="FusionSolar optimizer telemetry", optional=True, **kwargs
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
            count = _safe_number(counts.get("optimizerNum")) if isinstance(counts, dict) else None
            if count is None or count < 0 or not count.is_integer():
                # A malformed response says nothing about the plant topology.
                # Leave discovery uncached so the next refresh can recover.
                return []
            if count == 0:
                self._optimizers = {}
                return []
            try:
                layout = self._optimizer_request(
                    "GET", _LAYOUT,
                    params={"stationDn": self.station, "sheetNO": 0, "callerType": 0, "queryType": 0},
                )
                topology = _parse_optimizer_layout({"data": layout})
            except Exception as ex:
                _LOGGER.debug("Physical optimizer layout unavailable: %s", type(ex).__name__)
                topology = {}
            if not topology:
                # HAR-confirmed logical-layout fallback for master/slave systems.
                # Do not change the existing physical-layout discovery path.
                try:
                    tree = self._optimizer_request(
                        "POST", _LOGICAL_TREE,
                        json_body={
                            "stationDn": self.station,
                            "layoutType": 2,
                            "deviceDn": self.station,
                            "invertDnlist": [],
                        },
                    )
                    topology = _parse_optimizer_logical_tree(tree)
                except Exception as ex:
                    _LOGGER.debug("Logical optimizer discovery unavailable: %s", type(ex).__name__)
                    topology = {}
            # Retry a missing or malformed topology at the next refresh.
            if not topology:
                return []
            self._optimizers = topology
        if not topology:
            return []
        records = self._optimizer_request("POST", _SAMPLING, json_body=list(topology))
        if not isinstance(records, list):
            return []
        # optimizer-info carries the human-facing name, module position and
        # temperature. Fetch once per parent inverter and keep it optional so
        # failures cannot suppress the existing sampling telemetry.
        optimizer_info: dict[str, dict[str, Any]] = {}
        conflicting_info: set[str] = set()
        for inverter_dn in dict.fromkeys(
            item.get("parent_dn") for item in topology.values()
            if isinstance(item.get("parent_dn"), str) and item.get("parent_dn")
        ):
            try:
                info_records = self._optimizer_request(
                    "GET", _OPTIMIZER_INFO, params={"inverterDn": inverter_dn}
                )
            except Exception as ex:
                _LOGGER.debug("Optimizer details unavailable: %s", type(ex).__name__)
                continue
            if not isinstance(info_records, list):
                continue
            for info in info_records:
                if not isinstance(info, dict):
                    continue
                dn = info.get("dn")
                if (
                    not isinstance(dn, str) or dn not in topology
                    or topology[dn].get("parent_dn") != inverter_dn
                    or dn in conflicting_info
                ):
                    continue
                # Do not let an unscoped/cross-inverter response overwrite the
                # requested parent's details, or choose an arbitrary duplicate.
                if any(
                    key in info and info[key] != inverter_dn
                    for key in ("inverterDn", "bindInverterDn")
                ):
                    continue
                if dn in optimizer_info and optimizer_info[dn] != info:
                    del optimizer_info[dn]
                    conflicting_info.add(dn)
                else:
                    optimizer_info[dn] = info
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
            info = optimizer_info.get(dn, {})
            for name, value in (
                ("Optimizer Name", info.get("optName")),
                ("Optimizer Position", info.get("optNumber") or info.get("optNum") or topology[dn].get("position")),
            ):
                if isinstance(value, str) and value.strip() and value.strip() not in ("--", "null"):
                    devices.append(Device(
                        device_id=name,
                        device_unique_id=self.get_device_unique_id(name, DeviceType.SENSOR_TEXT, dn=dn),
                        device_type=DeviceType.SENSOR_TEXT,
                        name=name.removeprefix("Optimizer "),
                        state=value.strip(),
                        icon="mdi:tag-outline" if name == "Optimizer Name" else "mdi:map-marker-outline",
                        dn=dn,
                    ))
            is_disconnected = str(record.get("connectStatus") or "").strip().lower() in {
                "disconnected", "offline", "unavailable"
            }
            temperature = None if is_disconnected else _safe_number(info.get("temperature"))
            # An explicit invalid reading must clear an existing sensor, just
            # like an offline sample, rather than preserving a live temperature.
            if "temperature" in info or is_disconnected:
                devices.append(Device(
                    device_id="Optimizer Temperature",
                    device_unique_id=self.get_device_unique_id(
                        "Optimizer Temperature", DeviceType.SENSOR_TEMPERATURE, dn=dn
                    ),
                    device_type=DeviceType.SENSOR_TEMPERATURE,
                    name="Temperature",
                    state=temperature,
                    icon="mdi:thermometer",
                    dn=dn,
                ))
            for name, key, dtype, icon in _FIELDS:
                raw = (extra.get(key) if key not in ("dailyEnergy", "powerPercent", "connectStatus") else record.get(key))
                if name == "Optimizer Running Status" and raw is None:
                    raw = record.get("runningStatus")
                if dtype == DeviceType.SENSOR_TEXT:
                    value = str(raw) if raw not in (None, "", "--") else None
                else:
                    value = (
                        0.0 if raw == "--" and is_periodic_energy_counter(name, dtype)
                        else _safe_number(raw)
                    )
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
