"""Fusion Solar App charger (Huawei SCharger wallbox) helpers.

Read-only. Uses the same internal endpoints as the charger page of the FusionSolar web portal:

* device tree (``organization/v1/tree``) to find the charger (mocId 60080) and its
  charging connector (mocId 60081)
* ``homemgr/v1/device/get-realtime-info`` for live connector values (power, energy,
  working status, working mode, phase currents, temperature)
* ``config-signal`` for the configured power limits

Tested with a SCharger-22KT-S0 (FusionCharge V100R023C10SPC231) on an owner account.
The connector discovery and signal ids follow the approach of
https://github.com/jterpstra1/fusionsolar-charger.
"""

import json
import logging
from datetime import datetime
from typing import Any

from ..const import DATA_REFERER_URL, DEVICE_REALTIME_DATA_URL
from .models import Device, DeviceType

_LOGGER = logging.getLogger(__name__)

CHARGER_MOC_ID = 60080
CONNECTOR_MOC_ID = 60081
CHARGER_TREE_URL = "/rest/dp/pvms/organization/v1/tree"
CHARGER_CONFIG_URL = "/rest/neteco/config/device/v1/config/config-signal"
CHARGER_REALTIME_URL = "/rest/neteco/web/homemgr/v1/device/get-realtime-info"

# connector signals
SIG_POWER = 10013            # Total Output Power (kW)
SIG_ENERGY = 10014           # Total Energy Charged (kWh)
SIG_WORKING_STATUS = 10004   # e.g. "No Car Connected", "Charging"
SIG_LOCK = 10023             # "Locked" / "Unlocked"
SIG_REPORTED_STATUS = 2101763
SIG_WORKING_MODE = 2101764   # e.g. "PV Power" (app: "prefer green power")
SIG_CURRENTS = ((10032, "L1"), (10034, "L2"), (10033, "L3"))
# charger signals
SIG_TOTAL_ENERGY = 10008
SIG_MODEL = 10007
SIG_SOFTWARE = 10001
SIG_TEMPERATURE = 2101271
# config signals
CFG_DYNAMIC_POWER = 20001
CFG_MAX_POWER = 538976598
# connector config signal (writable): 0 = Normal charge, 1 = PV Power Preferred
CFG_WORKING_MODE = 20002
CHARGER_SET_CONFIG_URL = "/rest/pvms/web/device/v1/deviceExt/set-config-signals"
WORKING_MODES = {"0": "Normal charge", "1": "PV Power Preferred"}

CHARGER_OFFSET = 1_000_000_000  # keeps charger signal ids apart from connector ids


class FusionSolarChargerMixin:
    """Charger helpers for FusionSolar API."""

    def _charger_headers(self, json_body: bool = False) -> dict[str, str]:
        headers = {"Referer": f"https://{self.data_host}{DATA_REFERER_URL}"}
        if json_body:
            self.refresh_csrf()
            headers.update({"Content-Type": "application/json", "Roarand": self.csrf or ""})
        return headers

    def _charger_get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        response = self.session.get(
            f"https://{self.data_host}{path}", params=params, headers=self._charger_headers(), timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _charger_post(self, path: str, body: Any) -> Any:
        response = self.session.post(
            f"https://{self.data_host}{path}", data=json.dumps(body), headers=self._charger_headers(True), timeout=30
        )
        response.raise_for_status()
        return response.json()

    def _charger_tree(self, parent_dn: str, moc_ids: list[int] | None = None) -> list[dict[str, Any]]:
        filter_cond: dict[str, Any] = {"nameType": "device"}
        if moc_ids:
            filter_cond["mocIdInclude"] = moc_ids
        data = self._charger_post(
            CHARGER_TREE_URL,
            {
                "parentDn": parent_dn,
                "treeDepth": "device",
                "pageParam": {"pageId": 1, "pageSize": 100, "needPage": True},
                "filterCond": filter_cond,
                "displayCond": {"self": False, "status": True},
            },
        )
        nodes: list[dict[str, Any]] = []
        stack = list((data or {}).get("childList") or [])
        while stack:
            node = stack.pop()
            nodes.append(node)
            stack.extend(node.get("childList") or [])
        return nodes

    def _discover_charger(self) -> None:
        """Find the first charger of the station and its charging connector (once)."""
        self.charger_checked = True
        if self.station is None:
            return
        charger = next((n for n in self._charger_tree(self.station) if n.get("mocId") == CHARGER_MOC_ID), None)
        if charger is None:
            _LOGGER.debug("No charger found in station %s", self.station)
            return
        self.charger_dn = charger.get("elementDn")
        self.charger_id = charger.get("elementId")
        self.charger_name = charger.get("nodeName")
        connector = next(
            (n for n in self._charger_tree(self.charger_dn, [CONNECTOR_MOC_ID]) if n.get("mocId") == CONNECTOR_MOC_ID),
            None,
        )
        if connector is not None:
            self.charger_connector_id = connector.get("elementId")
            self.charger_connector_dn = connector.get("elementDn")
        _LOGGER.info("Charger %s (%s), connector %s", self.charger_name, self.charger_dn, self.charger_connector_id)

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
        )
        live = {s.get("id"): s for s in data.get(str(self.charger_connector_id), [])}
        for signal in data.get(str(self.charger_id), []):
            live[CHARGER_OFFSET + int(signal.get("id") or 0)] = signal
        return live

    def _build_charger_devices(self) -> list[Device]:
        """Return charger entities (empty list if the station has no charger)."""
        if not self.charger_checked:
            try:
                self._discover_charger()
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Charger discovery failed: %s", err)
                return []
        if self.charger_dn is None:
            return []

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

        def text(sig_id: int) -> str:
            sig = live.get(sig_id) or {}
            return str(sig.get("realValue") or sig.get("value") or "")

        if live:
            power = num(SIG_POWER) or 0.0
            if num(SIG_ENERGY) is not None:
                values["Charger Total Energy"] = (DeviceType.SENSOR_KWH, num(SIG_ENERGY), "mdi:counter")
            values["Charger Working Status"] = (DeviceType.SENSOR_TEXT, text(SIG_WORKING_STATUS), "mdi:car-electric")
            values["Charger Working Mode"] = (DeviceType.SENSOR_TEXT, text(SIG_WORKING_MODE), "mdi:leaf")
            values["Charger Reported Status"] = (DeviceType.SENSOR_TEXT, text(SIG_REPORTED_STATUS), "mdi:information-outline")
            values["Charger Lock"] = (DeviceType.SENSOR_TEXT, text(SIG_LOCK), "mdi:lock-outline")
            for sig_id, phase in SIG_CURRENTS:
                if num(sig_id) is not None:
                    values[f"Charger Current {phase}"] = (DeviceType.SENSOR_CURRENT, num(sig_id), "mdi:current-ac")
            if num(CHARGER_OFFSET + SIG_TEMPERATURE) is not None:
                values["Charger Temperature"] = (DeviceType.SENSOR_TEMPERATURE, num(CHARGER_OFFSET + SIG_TEMPERATURE), "mdi:thermometer")
            self.charger_model = text(CHARGER_OFFSET + SIG_MODEL) or self.charger_model
            self.charger_software_version = text(CHARGER_OFFSET + SIG_SOFTWARE) or self.charger_software_version
        else:
            # fallback: device-realtime-data of the charger (energy counter only, no live power)
            realtime = self._charger_get(DEVICE_REALTIME_DATA_URL, {"deviceDn": self.charger_dn, "displayAccessModel": "true"})
            signals = {s.get("id"): s for g in realtime.get("data", []) for s in (g.get("signals") or [])}
            if SIG_TOTAL_ENERGY in signals:
                values["Charger Total Energy"] = (DeviceType.SENSOR_KWH, signals[SIG_TOTAL_ENERGY].get("value"), "mdi:counter")
            power = 0.0

        values["Charger Power"] = (DeviceType.SENSOR_KW, power, "mdi:ev-station")
        values["Charger Status"] = (DeviceType.SENSOR_TEXT, "charging" if power >= 0.3 else "idle", "mdi:ev-plug-type2")

        try:
            config = self._charger_get(CHARGER_CONFIG_URL, {"dn": self.charger_dn})
            cfg = {s.get("id"): s.get("value") for g in config.get("data", []) for s in (g.get("configSignalDisplayList") or [])}
            values["Charger Dynamic Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_DYNAMIC_POWER), "mdi:tune-variant")
            values["Charger Max Power"] = (DeviceType.SENSOR_KW, cfg.get(CFG_MAX_POWER), "mdi:speedometer")
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Charger config not readable: %s", err)

        devices: list[Device] = []
        for device_id, (dtype, raw, icon) in values.items():
            device = self._create_dynamic_device(device_id, dtype, raw, icon)
            if device is not None:
                devices.append(device)
        values_time = datetime.now().astimezone()
        devices.append(Device(device_id="Charger Data Time", device_unique_id=self.get_device_unique_id("Charger Data Time", DeviceType.SENSOR_TIME),
                              device_type=DeviceType.SENSOR_TIME, name="Charger Data Time", state=values_time, icon="mdi:clock-outline"))
        return devices

    def set_charger_working_mode(self, mode: str) -> bool:
        """Set the connector working mode ("0" Normal charge / "1" PV Power Preferred)."""
        if mode not in WORKING_MODES:
            raise ValueError(f"Unknown working mode {mode!r}")
        if not self.charger_connector_dn:
            raise RuntimeError("No charging connector discovered")
        self.refresh_csrf()
        response = self.session.post(
            f"https://{self.data_host}{CHARGER_SET_CONFIG_URL}",
            data={
                "dn": self.charger_connector_dn,
                "changeValues": json.dumps([{"id": str(CFG_WORKING_MODE), "value": mode}], separators=(",", ":")),
            },
            headers={**self._charger_headers(), "Roarand": self.csrf or ""},
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()
        ok = result.get("code") == 0 and all(item.get("code") == 0 for item in result.get("data") or [])
        if not ok:
            _LOGGER.warning("Setting charger working mode failed: %s", result)
        return ok
