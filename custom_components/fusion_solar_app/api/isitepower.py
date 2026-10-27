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
