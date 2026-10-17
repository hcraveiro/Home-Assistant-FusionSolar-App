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

Tested with a SCharger-22KT-S0 (FusionCharge V100R023C10SPC231) on an owner account.
The connector discovery and signal ids follow the approach of
https://github.com/jterpstra1/fusionsolar-charger.
"""

import json
import logging
import threading
import time
from datetime import datetime
from typing import Any

from ..const import DATA_REFERER_URL, DEVICE_REALTIME_DATA_URL
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
SIG_WORKING_MODE = 2101764   # e.g. "PV Power"
# names reported by the portal: 10032 "A Output Current", 10034 "B ...", 10033 "C ..."
SIG_CURRENTS = ((10032, "L1"), (10034, "L2"), (10033, "L3"))
# charger signals (get-realtime-info / device-realtime-data)
SIG_TOTAL_ENERGY = 10008     # Total Energy Charged (kWh) – single source for the energy counter
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


class FusionSolarChargerMixin:
    """Charger helpers for FusionSolar API."""

    _charger_lock = threading.Lock()

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

    def _charger_tree(self, parent_dn: str, moc_ids: list[int]) -> list[dict[str, Any]]:
        data = self._charger_post(
            CHARGER_TREE_URL,
            {
                "parentDn": parent_dn,
                "treeDepth": "device",
                "pageParam": {"pageId": 1, "pageSize": 100, "needPage": True},
                "filterCond": {"nameType": "device", "mocIdInclude": moc_ids},
                "displayCond": {"self": False, "status": True},
            },
            "Charger device tree",
        )
        nodes: list[dict[str, Any]] = []
        stack = list((data or {}).get("childList") or [])
        while stack:
            node = stack.pop()
            nodes.append(node)
            stack.extend(node.get("childList") or [])
        return nodes

    def _discover_charger(self) -> None:
        """Find the first charger of the station and its charging connector.

        ``charger_checked`` is only set after a successful lookup; failures are retried later.
        """
        if self.station is None or time.monotonic() < self._charger_retry_at:
            return
        try:
            charger = next((n for n in self._charger_tree(self.station, [CHARGER_MOC_ID]) if n.get("mocId") == CHARGER_MOC_ID), None)
            connector = None
            if charger is not None:
                connector = next(
                    (n for n in self._charger_tree(charger["elementDn"], [CONNECTOR_MOC_ID]) if n.get("mocId") == CONNECTOR_MOC_ID),
                    None,
                )
        except Exception as err:  # noqa: BLE001
            self._charger_retry_at = time.monotonic() + DISCOVERY_RETRY_SECONDS
            _LOGGER.warning("Charger discovery failed, retrying later: %s", err)
            return
        self.charger_checked = True
        if charger is None:
            _LOGGER.debug("No charger found in station %s", self.station)
            return
        self.charger_dn = charger.get("elementDn")
        self.charger_id = charger.get("elementId")
        if connector is not None:
            self.charger_connector_id = connector.get("elementId")
            self.charger_connector_dn = connector.get("elementDn")
        _LOGGER.debug("Charger %s, connector %s", self.charger_dn, self.charger_connector_dn)

    def _charger_live(self) -> dict[int, dict[str, Any]]:
        """Live signals of connector and charger, keyed by signal id (charger ids offset)."""
        if not (self.charger_connector_id and self.charger_id):
            return {}
        data = self._charger_post(
            CHARGER_REALTIME_URL,
            {"conditions": [
                {"dnId": int(self.charger_connector_id), "queryAll": True},
                {"dnId": int(self.charger_id), "queryAll": True},
            ]},
            "Charger realtime",
        )
        live = {s.get("id"): s for s in data.get(str(self.charger_connector_id), [])}
        for signal in data.get(str(self.charger_id), []):
            live[CHARGER_OFFSET + int(signal.get("id") or 0)] = signal
        return live

    def _charger_config(self) -> dict[int, Any]:
        """Configured limits (charger) and working mode (connector), cached."""
        if self._charger_config_cache and time.monotonic() - self._charger_config_time < CONFIG_CACHE_SECONDS:
            return self._charger_config_cache
        cfg: dict[int, Any] = {}
        data = self._charger_get(CHARGER_CONFIG_URL, {"dn": self.charger_dn}, "Charger config")
        for group in data.get("data") or []:
            for signal in group.get("configSignalDisplayList") or []:
                cfg[signal.get("id")] = signal.get("value")
        if self.charger_connector_dn:
            data = self._charger_get(
                CONNECTOR_GET_CONFIG_URL, {"dn": self.charger_connector_dn, "_": int(time.time() * 1000)}, "Charger connector config"
            )
            for group in data.get("data") or []:
                for signal in group.get("configSignalDisplayList") or []:
                    if signal.get("id") == CFG_WORKING_MODE:
                        cfg[CFG_WORKING_MODE] = str(signal.get("value"))
        self._charger_config_cache, self._charger_config_time = cfg, time.monotonic()
        return cfg

    def _build_charger_devices(self) -> list[Device]:
        """Return charger entities (empty list if the station has no charger)."""
        with self._charger_lock:
            if not self.charger_checked:
                self._discover_charger()
            if self.charger_dn is None:
                return []
            return self._build_charger_devices_locked()

    def _build_charger_devices_locked(self) -> list[Device]:
        values: dict[str, tuple[DeviceType, Any, str]] = {}

        live: dict[int, dict[str, Any]] = {}
        try:
            live = self._charger_live()
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

        if live:
            power = num(SIG_POWER)
            if power is not None:   # missing value -> no state instead of a fake 0 kW / idle
                values["Charger Power"] = (DeviceType.SENSOR_KW, power, "mdi:ev-station")
                values["Charger Status"] = (DeviceType.SENSOR_TEXT, "charging" if power >= 0.3 else "idle", "mdi:ev-plug-type2")
            energy = num(CHARGER_OFFSET + SIG_TOTAL_ENERGY)
            if energy is not None:
                values["Charger Total Energy"] = (DeviceType.SENSOR_KWH, energy, "mdi:counter")
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
        else:
            # fallback: device-realtime-data of the charger (same energy signal, no live power)
            try:
                realtime = self._charger_get(
                    DEVICE_REALTIME_DATA_URL, {"deviceDn": self.charger_dn, "displayAccessModel": "true"}, "Charger realtime fallback"
                )
                signals = {s.get("id"): s for g in realtime.get("data", []) for s in (g.get("signals") or [])}
                if SIG_TOTAL_ENERGY in signals:
                    values["Charger Total Energy"] = (DeviceType.SENSOR_KWH, signals[SIG_TOTAL_ENERGY].get("value"), "mdi:counter")
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Charger fallback data not readable: %s", err)

        try:
            cfg = self._charger_config()
            values["Charger Dynamic Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_DYNAMIC_POWER), "mdi:tune-variant")
            values["Charger Max Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_MAX_POWER), "mdi:speedometer")
            self.charger_working_mode_setting = cfg.get(CFG_WORKING_MODE)
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
        """Set the connector working mode ("0" Normal charge / "1" PV Power Preferred)."""
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
            items = result.get("data")
            ok = result.get("code") == 0 and isinstance(items, list) and bool(items) and all(i.get("code") == 0 for i in items)
            if ok:
                self.charger_working_mode_setting = mode
                self._charger_config_time = 0.0      # re-read config on the next poll
            else:
                _LOGGER.warning("Setting charger working mode was not accepted: %s", result)
            return ok
