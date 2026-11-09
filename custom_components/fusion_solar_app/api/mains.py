"""Read-only iSitePower-M Mains State; never infer connectivity from power."""
from __future__ import annotations

import time
from typing import Any

MAINS_NAME = "neteco.pvms.pcs.station.energyflow.mains"
SAMPLING_ENDPOINT = "/rest/neteco/monitor/v1/signal/common/sampling-signal"


def discover_mains_dn(nodes: Any) -> str | None:
    """Accept exactly one documented mains node with exactly one explicit DN."""
    if not isinstance(nodes, list):
        return None
    mains = [node for node in nodes if isinstance(node, dict)
             and node.get("name") == MAINS_NAME and str(node.get("mocId")) == "60001"]
    if len(mains) != 1:
        return None
    dns = mains[0].get("devIds")
    if not isinstance(dns, list) or len(dns) != 1:
        return None
    dn = dns[0]
    return dn if isinstance(dn, str) and dn.strip() == dn and dn else None


def parse_mains_state(response: Any, dn: str) -> bool | None:
    """Validate endpoint, root, unique signal, device identity and strict enum.

    Native JSON integers 0/1 are equivalent to the captured strings; bools,
    floats, whitespace and other coercions are deliberately rejected.
    """
    if not isinstance(response, dict) or type(response.get("code")) is not int or response["code"] != 0:
        return None
    data = response.get("data")
    if not isinstance(data, dict) or str(data.get("rootDevTypeId")) != "36892":
        return None
    rows = data.get("displayList")
    if not isinstance(rows, list):
        return None
    matches = [row for row in rows if isinstance(row, dict) and str(row.get("id")) == "10001"]
    if len(matches) != 1:
        return None
    row = matches[0]
    if (row.get("dn") != dn or str(row.get("typeId")) != "36892"
            or str(row.get("mocId")) != "10001" or row.get("dataType") != "ENUM"
            or row.get("signalType") != "DI"):
        return None
    value = row.get("value")
    if type(value) is int and value in (0, 1):
        return value == 1
    if type(value) is str and value in ("0", "1"):
        return value == "1"
    return None


def parse_mains_power(response: Any, dn: str) -> float | None:
    """Read signal 10010 independently of connectivity; only kW is evidenced.

    Preserve finite negative readings unchanged, without assigning direction.
    """
    from ..utils import extract_numeric

    if not isinstance(response, dict) or type(response.get("code")) is not int or response["code"] != 0:
        return None
    data = response.get("data")
    if not isinstance(data, dict) or str(data.get("rootDevTypeId")) != "36892":
        return None
    rows = data.get("displayList")
    if not isinstance(rows, list):
        return None
    matches = [row for row in rows if isinstance(row, dict) and str(row.get("id")) == "10010"]
    if len(matches) != 1:
        return None
    row = matches[0]
    if (row.get("dn") != dn or str(row.get("typeId")) != "36892"
            or str(row.get("mocId")) != "10010" or row.get("dataType") != "FLOAT"
            or row.get("unit") != "kW"):
        return None
    # Reject embedded alternate units too: the row's unit is authoritative.
    return extract_numeric(row.get("value"))


def fetch_mains_state(api: Any, dn: str) -> bool | None:
    """One optional form POST per normal poll; transport errors reach isolation."""
    api.refresh_csrf()
    _, response = api._request_json(
        "POST", f"https://{api.data_host}{SAMPLING_ENDPOINT}",
        context="FusionSolar iSitePower-M mains sampling", optional=True,
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                 "Roarand": api.csrf},
        data={"samplingSigQueryCon.dn": dn, "samplingSigQueryCon.pageSize": "10",
              "samplingSigQueryCon.pageIndex": "1", "queryScene.businessDevice": "0",
              "queryScene.bindQuery": "false", "queryScene.queryAODO": "false",
              "filterParams.name": "", "filterParams.displayGroup": "",
              "filterParams.signalType": "AI;DI;AO;DO;OTHER"},
    )
    api._mains_active_power = parse_mains_power(response, dn)
    return parse_mains_state(response, dn)


def refresh_mains(api: Any, nodes: list[dict]) -> None:
    """Bound optional v3 discovery to relevant stations, retry missing DN hourly.

    v3 contributes identity only: v2 power, links and all energy stay untouched.
    Battery discovery owns a separate cache and excludes iSitePower-M stations.
    Clear state before every attempt so failures cannot retain an On/Off value.
    """
    api._mains_state = None
    api._mains_active_power = None
    api._mains_verified = bool(getattr(api, "_is_isitepower_m", False))
    if not api._mains_verified:
        api._mains_dn = None
        return
    try:
        dn = discover_mains_dn(nodes)
        # An explicit but ambiguous v2 mains descriptor must not be overridden.
        descriptors = [node for node in nodes if isinstance(node, dict)
                       and node.get("name") == MAINS_NAME]
        ambiguous = (len(descriptors) > 1
                     or any(node.get("devIds") for node in descriptors) and dn is None)
        if ambiguous:
            api._mains_dn = None
            return
        if dn is None:
            dn = getattr(api, "_mains_dn", None)
        if dn is None and time.monotonic() >= getattr(api, "_mains_next_probe", 0):
            api._mains_next_probe = time.monotonic() + 3600
            api.refresh_csrf()
            _, response = api._request_json(
                "GET", f"https://{api.data_host}/rest/pvms/web/station/v3/overview/energy-flow",
                context="FusionSolar iSitePower-M mains discovery", optional=True,
                headers={"Accept": "application/json", "Roarand": api.csrf},
                params={"stationDn": api.station, "featureId": "aifc"},
            )
            if (isinstance(response, dict) and response.get("success") is True
                    and type(response.get("failCode")) is int and response["failCode"] == 0):
                data = response.get("data")
                flow = data.get("flow") if isinstance(data, dict) else None
                dn = discover_mains_dn(flow.get("nodes") if isinstance(flow, dict) else None)
        api._mains_dn = dn
        if dn:
            api._mains_state = fetch_mains_state(api, dn)
    except Exception:
        # Optional telemetry must not take down measurements or authentication.
        # No state is synthesized, including on an API/HTTP error.
        api._mains_state = None
        api._mains_active_power = None
