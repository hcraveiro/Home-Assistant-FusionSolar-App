"""Fusion Solar App charger (Huawei SCharger wallbox) helpers.

Uses the same internal endpoints as the charger page of the FusionSolar web portal:

* device tree (``organization/v1/tree``) to find the charger (mocId 60080) and its
  charging connector (mocId 60081)
* ``homemgr/v1/device/get-realtime-info`` for live charger/connector values (power,
  energy, working status, working mode, phase currents, temperature)
* ``config-signal`` / ``deviceExt/get-config-signals`` for the configured power limits and
  the connector working mode
* ``deviceExt/set-config-signals`` to change the connector working mode
  (``0`` Normal charge / ``1`` PV Power Preferred) – the only write

Only the first charger and its first connector of a plant are supported.
Tested with a SCharger-22KT-S0 (FusionCharge V100R023C10SPC231) on an owner account.
The connector discovery and signal ids follow the approach of
https://github.com/jterpstra1/fusionsolar-charger.
"""

import json
import logging
import time
from datetime import datetime
from typing import Any

from ..const import DATA_REFERER_URL, DEVICE_REALTIME_DATA_URL
from .exceptions import APIAuthError
from .models import Device, DeviceType

_LOGGER = logging.getLogger(__name__)

CHARGER_MOC_ID = 60080
CONNECTOR_MOC_ID = 60081
CHARGER_TREE_URL = "/rest/dp/pvms/organization/v1/tree"
CHARGER_REALTIME_URL = "/rest/neteco/web/homemgr/v1/device/get-realtime-info"
# charger limits; this path (without /web/) is the one the portal uses for the charger
CHARGER_CONFIG_URL = "/rest/neteco/config/device/v1/config/config-signal"
CONNECTOR_GET_CONFIG_URL = "/rest/pvms/web/device/v1/deviceExt/get-config-signals"
CONNECTOR_SET_CONFIG_URL = "/rest/pvms/web/device/v1/deviceExt/set-config-signals"

# connector signals (get-realtime-info)
SIG_POWER = 10013            # Total Output Power (kW)
SIG_WORKING_STATUS = 10004   # e.g. "No Car Connected", "Charging"
SIG_LOCK = 10023             # "Locked" / "Unlocked"
SIG_REPORTED_STATUS = 2101763
SIG_WORKING_MODE = 2101764   # e.g. "PV Power" (reported for the last session)
# names reported by the portal: 10032 "A Output Current", 10034 "B ...", 10033 "C ..."
SIG_CURRENTS = ((10032, "L1"), (10034, "L2"), (10033, "L3"))
# charger signals (get-realtime-info / device-realtime-data)
SIG_TOTAL_ENERGY = 10008     # Total Energy Charged (kWh); same counter as connector signal 10014
SIG_MODEL = 10007
SIG_SOFTWARE = 10001
SIG_SERIAL = 2101252
SIG_TEMPERATURE = 2101271
# config signals
CFG_DYNAMIC_POWER = 20001          # charger
CFG_MAX_POWER = 538976598          # charger
CFG_WORKING_MODE = 20002           # connector, writable
WORKING_MODES = {"0": "Normal charge", "1": "PV Power Preferred"}

CHARGER_OFFSET = 1_000_000_000     # keeps charger signal ids apart from connector ids
CONFIG_CACHE_SECONDS = 900         # limits / working mode change rarely
DISCOVERY_RETRY_SECONDS = 600


def _sig_id(signal: dict[str, Any]) -> int | None:
    """Signal id as int (the portal sends ints; be tolerant of strings)."""
    try:
        return int(signal.get("id"))
    except (TypeError, ValueError):
        return None


def _valid_node(node: dict[str, Any] | None) -> bool:
    return bool(node) and str(node.get("elementDn", "")).startswith("NE=") and str(node.get("elementId", "")).isdigit()


class FusionSolarChargerMixin:
    """Charger helpers for FusionSolar API."""

    def _charger_headers(self, json_body: bool = False) -> dict[str, str]:
        headers = {"Referer": f"https://{self.data_host}{DATA_REFERER_URL}"}
        if json_body:
            self.refresh_csrf()
            headers.update({"Content-Type": "application/json", "Roarand": self.csrf or ""})
        return headers

    def _charger_get(self, path: str, params: dict[str, Any], context: str) -> dict[str, Any]:
        _, data = self._request_json(
            "GET", f"https://{self.data_host}{path}", context=context, params=params, headers=self._charger_headers()
        )
        return data

    def _charger_post(self, path: str, body: Any, context: str) -> Any:
        _, data = self._request_json(
            "POST", f"https://{self.data_host}{path}", context=context, data=json.dumps(body), headers=self._charger_headers(True)
        )
        return data

    def _charger_tree(self, parent_dn: str, moc_id: int) -> list[dict[str, Any]]:
        data = self._charger_post(
            CHARGER_TREE_URL,
            {
                "parentDn": parent_dn,
                "treeDepth": "device",
                "pageParam": {"pageId": 1, "pageSize": 100, "needPage": True},
                "filterCond": {"nameType": "device", "mocIdInclude": [moc_id]},
                "displayCond": {"self": False, "status": True},
            },
            "Charger device tree",
        )
        if not isinstance(data, dict) or not isinstance(data.get("childList"), list):
            # a successful tree answer always carries "childList"; anything else is an error, not "no charger"
            keys = list(data)[:5] if isinstance(data, dict) else type(data).__name__
            raise ValueError(f"Unexpected device tree response ({keys})")
        nodes: list[dict[str, Any]] = []
        stack = list(data["childList"])
        while stack:
            node = stack.pop()
            nodes.append(node)
            stack.extend(node.get("childList") or [])
        return [n for n in nodes if n.get("mocId") == moc_id and _valid_node(n)]

    def _discover_charger(self) -> None:
        """Find the first charger of the station and its charging connector.

        Charger and connector lookups are retried independently after failures.
        """
        if self.station is None or time.monotonic() < self._charger_retry_at:
            return
        try:
            if not self.charger_checked:
                chargers = self._charger_tree(self.station, CHARGER_MOC_ID)
                self.charger_checked = True
                if not chargers:
                    _LOGGER.debug("No charger found in station %s", self.station)
                    return
                self.charger_dn = chargers[0]["elementDn"]
                self.charger_id = int(chargers[0]["elementId"])
            if self.charger_dn and not self.charger_connector_dn:
                connectors = self._charger_tree(self.charger_dn, CONNECTOR_MOC_ID)
                if not connectors:
                    raise ValueError("charger has no charging connector (yet)")
                self.charger_connector_dn = connectors[0]["elementDn"]
                self.charger_connector_id = int(connectors[0]["elementId"])
        except APIAuthError:
            raise
        except Exception as err:  # noqa: BLE001
            self._charger_retry_at = time.monotonic() + DISCOVERY_RETRY_SECONDS
            _LOGGER.warning("Charger discovery incomplete, retrying later: %s", err)
            return
        _LOGGER.debug("Charger %s, connector %s", self.charger_dn, self.charger_connector_dn)

    def _charger_live(self) -> dict[int, dict[str, Any]]:
        """Live signals of connector and charger, keyed by signal id (charger ids offset)."""
        if not (self.charger_connector_id and self.charger_id):
            return {}
        data = self._charger_post(
            CHARGER_REALTIME_URL,
            {"conditions": [
                {"dnId": self.charger_connector_id, "queryAll": True},
                {"dnId": self.charger_id, "queryAll": True},
            ]},
            "Charger realtime",
        )
        live: dict[int, dict[str, Any]] = {}
        for offset, dn_id in ((0, self.charger_connector_id), (CHARGER_OFFSET, self.charger_id)):
            for signal in (data.get(str(dn_id)) if isinstance(data, dict) else None) or []:
                sig_id = _sig_id(signal)
                if sig_id is not None:
                    live[offset + sig_id] = signal
        return live

    def _charger_config(self) -> dict[int, Any]:
        """Configured limits (charger) and working mode (connector), cached; only updated on a successful read."""
        if self._charger_config_cache and time.monotonic() - self._charger_config_time < CONFIG_CACHE_SECONDS:
            return self._charger_config_cache
        cfg: dict[int, Any] = {}
        data = self._charger_get(CHARGER_CONFIG_URL, {"dn": self.charger_dn}, "Charger config")
        for group in data.get("data") or []:
            for signal in group.get("configSignalDisplayList") or []:
                if _sig_id(signal) is not None:
                    cfg[_sig_id(signal)] = signal.get("value")
        if self.charger_connector_dn:
            data = self._charger_get(
                CONNECTOR_GET_CONFIG_URL, {"dn": self.charger_connector_dn, "_": int(time.time() * 1000)}, "Charger connector config"
            )
            for group in data.get("data") or []:
                for signal in group.get("configSignalDisplayList") or []:
                    if _sig_id(signal) == CFG_WORKING_MODE and signal.get("value") is not None:
                        cfg[CFG_WORKING_MODE] = str(signal.get("value"))
        self._charger_config_cache, self._charger_config_time = cfg, time.monotonic()
        if CFG_WORKING_MODE in cfg:
            # observed (read back) mode; the select confirms a write only against this
            self.charger_working_mode_setting = cfg[CFG_WORKING_MODE]
            self.charger_config_read_at = time.monotonic()
        return cfg

    def _build_charger_devices(self) -> list[Device]:
        """Return charger entities (empty list if the station has no charger)."""
        with self._charger_lock:
            if not self.charger_checked or (self.charger_dn and not self.charger_connector_dn):
                self._discover_charger()
            if self.charger_dn is None:
                return []
            return self._build_charger_devices_locked()

    def _build_charger_devices_locked(self) -> list[Device]:
        values: dict[str, tuple[DeviceType, Any, str]] = {}

        live: dict[int, dict[str, Any]] = {}
        try:
            live = self._charger_live()
        except APIAuthError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Charger live data not readable: %s", err)

        def num(sig_id: int) -> float | None:
            try:
                return float(live[sig_id].get("value"))
            except (KeyError, TypeError, ValueError):
                return None

        def text(sig_id: int) -> str | None:
            sig = live.get(sig_id) or {}
            value = sig.get("realValue") or sig.get("value")
            return str(value) if value not in (None, "") else None

        energy = num(CHARGER_OFFSET + SIG_TOTAL_ENERGY)
        if live:
            power = num(SIG_POWER)
            if power is not None:   # missing value -> no state instead of a fake 0 kW / idle
                values["Charger Power"] = (DeviceType.SENSOR_KW, power, "mdi:ev-station")
                values["Charger Status"] = (DeviceType.SENSOR_TEXT, "charging" if power >= 0.3 else "idle", "mdi:ev-plug-type2")
            for name, sig_id, icon in (
                ("Charger Working Status", SIG_WORKING_STATUS, "mdi:car-electric"),
                ("Charger Working Mode", SIG_WORKING_MODE, "mdi:leaf"),
                ("Charger Reported Status", SIG_REPORTED_STATUS, "mdi:information-outline"),
                ("Charger Lock", SIG_LOCK, "mdi:lock-outline"),
            ):
                if text(sig_id) is not None:
                    values[name] = (DeviceType.SENSOR_TEXT, text(sig_id), icon)
            for sig_id, phase in SIG_CURRENTS:
                if num(sig_id) is not None:
                    values[f"Charger Current {phase}"] = (DeviceType.SENSOR_CURRENT, num(sig_id), "mdi:current-ac")
            if num(CHARGER_OFFSET + SIG_TEMPERATURE) is not None:
                values["Charger Temperature"] = (DeviceType.SENSOR_TEMPERATURE, num(CHARGER_OFFSET + SIG_TEMPERATURE), "mdi:thermometer")
            self.charger_model = text(CHARGER_OFFSET + SIG_MODEL) or self.charger_model
            self.charger_software_version = text(CHARGER_OFFSET + SIG_SOFTWARE) or self.charger_software_version
            self.charger_serial_number = text(CHARGER_OFFSET + SIG_SERIAL) or self.charger_serial_number
        if energy is None:
            # fallback: device-realtime-data of the charger (same energy signal 10008)
            try:
                realtime = self._charger_get(
                    DEVICE_REALTIME_DATA_URL, {"deviceDn": self.charger_dn, "displayAccessModel": "true"}, "Charger realtime fallback"
                )
                for group in realtime.get("data") or []:
                    for signal in group.get("signals") or []:
                        if _sig_id(signal) == SIG_TOTAL_ENERGY:
                            energy = float(signal.get("value"))
            except APIAuthError:
                raise
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Charger fallback data not readable: %s", err)
        if energy is not None:
            values["Charger Total Energy"] = (DeviceType.SENSOR_KWH, energy, "mdi:counter")

        try:
            cfg = self._charger_config()
            values["Charger Dynamic Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_DYNAMIC_POWER), "mdi:tune-variant")
            values["Charger Max Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_MAX_POWER), "mdi:speedometer")
        except APIAuthError:
            raise
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Charger config not readable: %s", err)

        devices: list[Device] = []
        for device_id, (dtype, raw, icon) in values.items():
            device = self._create_dynamic_device(device_id, dtype, raw, icon)
            if device is not None:
                devices.append(device)
        if live:
            devices.append(Device(
                device_id="Charger Data Time",
                device_unique_id=self.get_device_unique_id("Charger Data Time", DeviceType.SENSOR_TIME),
                device_type=DeviceType.SENSOR_TIME,
                name="Charger Data Time",
                state=datetime.now().astimezone(),
                icon="mdi:clock-outline",
            ))
        return devices

    def set_charger_working_mode(self, mode: str) -> bool:
        """Request a connector working mode ("0" Normal charge / "1" PV Power Preferred).

        Returns True when the portal accepted the request. The observed mode
        (``charger_working_mode_setting``) is only updated by the next config read.
        """
        if mode not in WORKING_MODES:
            raise ValueError(f"Unknown working mode {mode!r}")
        if not self.charger_connector_dn:
            raise RuntimeError("No charging connector discovered")
        with self._charger_lock:
            self.refresh_csrf()
            _, result = self._request_json(
                "POST",
                f"https://{self.data_host}{CONNECTOR_SET_CONFIG_URL}",
                context="Charger set working mode",
                data={
                    "dn": self.charger_connector_dn,
                    "changeValues": json.dumps([{"id": str(CFG_WORKING_MODE), "value": mode}], separators=(",", ":")),
                },
                headers={**self._charger_headers(), "Roarand": self.csrf or ""},
            )
            items = result.get("data") if isinstance(result, dict) else None
            ok = isinstance(result, dict) and result.get("code") == 0 and isinstance(items, list) and bool(items) and all(
                isinstance(i, dict) and i.get("code") == 0 for i in items
            )
            if ok:
                self._charger_config_time = 0.0      # read back on the next poll
            else:
                _LOGGER.warning(
                    "Charger working mode change not accepted (code=%s, description=%s)",
                    result.get("code") if isinstance(result, dict) else None,
                    result.get("description") if isinstance(result, dict) else None,
                )
            return ok
