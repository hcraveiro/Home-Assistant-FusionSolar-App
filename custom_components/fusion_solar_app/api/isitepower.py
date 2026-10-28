"""Validated, read-only iSitePower-M battery-cluster signal interpretation.

Transport request shape still requires the original sanitized capture.
"""

from __future__ import annotations

import math
import re
from typing import Any

CLUSTER_MOC_ID = 60014
CLUSTER_TYPE_ID = 37895
SIGNAL_STATE = 10001
SIGNAL_SOC = 10005
SIGNAL_CAPACITY = 2101296
SIGNAL_MAINS_TOTAL_ENERGY = 10016

STATE_LABELS = {"4": "Discharging", "5": "Charging"}


def discover_cluster_dns(nodes: list[dict[str, Any]]) -> list[str]:
    """Discover actual cluster DNs, never layout IDs or converter IDs."""
    result: list[str] = []
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get("name") != "neteco.pvms.devTypeLangKey.power_cube":
            continue
        if str(node.get("mocId")) != str(CLUSTER_MOC_ID):
            continue
        for dn in node.get("devIds") or []:
            if isinstance(dn, str) and dn.strip() and dn not in result:
                result.append(dn)
    return result


def parse_measurement(value: Any, unit: str) -> float | None:
    """Parse a finite number with an optional matching unit."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        pattern = rf"^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(?:{re.escape(unit)})?\s*$"
        match = re.fullmatch(pattern, value, re.IGNORECASE)
        if not match:
            return None
        number = float(match.group(1))
    else:
        return None
    return number if math.isfinite(number) else None


def parse_cluster_signals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode verified 37895 sampling signals without assigning an aggregate SOC."""
    result: dict[str, Any] = {"state": None, "soc": None, "capacity_kwh": None}
    for row in rows:
        if not isinstance(row, dict):
            continue
        signal_id = row.get("id")
        try:
            signal_id = int(signal_id)
        except (ValueError, TypeError):
            continue
        raw = row.get("value")
        if signal_id == SIGNAL_STATE:
            result["state"] = STATE_LABELS.get(str(raw).strip())
        elif signal_id == SIGNAL_SOC:
            soc = parse_measurement(raw, "%")
            result["soc"] = soc if soc is not None and 0 <= soc <= 100 else None
        elif signal_id == SIGNAL_CAPACITY:
            capacity = parse_measurement(raw, "kWh")
            result["capacity_kwh"] = capacity if capacity is not None and capacity > 0 else None
    return result


def aggregate_cluster_capacity(
    cluster_dns: list[str], readings: dict[str, dict[str, Any]]
) -> float | None:
    """Only aggregate when every distinct discovered cluster has valid capacity."""
    if not cluster_dns or len(cluster_dns) != len(set(cluster_dns)):
        return None
    capacities = [
        readings.get(dn, {}).get("capacity_kwh") for dn in cluster_dns
    ]
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        for value in capacities
    ):
        return None
    return round(sum(capacities), 4)

SAMPLING_ENDPOINT = "/rest/neteco/monitor/v1/signal/common/sampling-signal"


def fetch_cluster_signals(api: Any, dn: str) -> list[dict[str, Any]]:
    """Fetch all pages using the verified form-encoded FusionSolar request."""
    rows: list[dict[str, Any]] = []
    total_size: int | None = None
    page = 1
    page_size = 20
    while page <= 20:
        api.refresh_csrf()
        form = {
            "samplingSigQueryCon.dn": dn,
            "samplingSigQueryCon.pageSize": str(page_size),
            "samplingSigQueryCon.pageIndex": str(page),
            "queryScene.businessDevice": "0",
            "queryScene.bindQuery": "false",
            "queryScene.queryAODO": "false",
            "filterParams.name": "",
            "filterParams.displayGroup": "",
            "filterParams.signalType": "AI;DI;AO;DO;OTHER",
        }
        _, response = api._request_json(
            "POST",
            f"https://{api.data_host}{SAMPLING_ENDPOINT}",
            context="FusionSolar iSitePower-M cluster sampling",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Roarand": api.csrf,
            },
            data=form,
        )
        if not isinstance(response, dict) or response.get("code") != 0:
            raise ValueError("iSitePower-M sampling request failed")
        payload = response.get("data")
        if not isinstance(payload, dict) or str(payload.get("rootDevTypeId")) != str(CLUSTER_TYPE_ID):
            raise ValueError("Unexpected iSitePower-M cluster response type")
        batch = payload.get("displayList")
        if not isinstance(batch, list):
            raise ValueError("iSitePower-M sampling response lacks displayList")
        for row in batch:
            if isinstance(row, dict) and row.get("dn") == dn and str(row.get("typeId")) == str(CLUSTER_TYPE_ID):
                rows.append(row)
        try:
            total_size = int(payload["totalSize"])
        except (ValueError, TypeError, KeyError):
            raise ValueError("iSitePower-M sampling response lacks totalSize") from None
        if total_size < 0 or total_size > 400:
            raise ValueError("Invalid iSitePower-M signal count")
        if len(batch) == 0 or len(rows) >= total_size:
            break
        page += 1
    if total_size is not None and len(rows) < total_size:
        raise ValueError("Incomplete iSitePower-M cluster signal pages")
    return rows


def build_cluster_devices(api: Any) -> tuple[list[Any], float | None]:
    """Create per-cluster telemetry without asserting an aggregate SOC."""
    from .models import DeviceType

    definitions = (
        ("State", "state", DeviceType.SENSOR_TEXT, "mdi:battery"),
        ("SOC", "soc", DeviceType.SENSOR_PERCENTAGE, "mdi:battery"),
        ("Capacity", "capacity_kwh", DeviceType.SENSOR_KWH, "mdi:battery-high"),
    )
    result = []
    readings: dict[str, dict[str, Any]] = {}
    for dn in getattr(api, "_isitepower_cluster_dns", []):
        try:
            rows = fetch_cluster_signals(api, dn)
            values = parse_cluster_signals(rows)
            readings[dn] = values
            for label, key, dtype, icon in definitions:
                value = values.get(key)
                if value is None:
                    continue
                device = api._create_dynamic_device(
                    f"iSitePower Cluster {label}", dtype, value, icon, dn=dn
                )
                if device is not None:
                    result.append(device)
        except Exception as ex:
            import logging
            logging.getLogger(__name__).warning(
                "Could not refresh iSitePower-M battery cluster %s: %s", dn, ex
            )
    return result, aggregate_cluster_capacity(getattr(api, "_isitepower_cluster_dns", []), readings)
