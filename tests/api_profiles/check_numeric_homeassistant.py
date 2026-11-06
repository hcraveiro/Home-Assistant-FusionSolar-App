#!/usr/bin/env python3
"""Disposable actual-HA numeric transitions from synthetic offline HTTP bodies.

Builds a temporary profile from the existing PV/meter routes; never adds an eighth
persistent profile. No Device-state injection, production/dev HA, recorder or
hardware evidence. Run standalone in the same --network none HA image as the
seven-profile runtime checker. All production pacing is retained.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime
import json
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

from check_runtime_homeassistant import ROOT, DOMAIN, require


def numeric_profile(load_profile):
    profile = load_profile("transitions-pv-meter")
    profile["id"] = "synthetic-numeric-disposable"
    profile["title"] = "MOCK disposable numeric transitions"
    profile["origin"] = "synthetic"
    profile["frames"] = []
    # Four full HTTP snapshots, not Device objects or direct HA state writes.
    for name, flow, meter, voltage, current, coal, trees in (
        ("valid", "600W", "0.6 kW", "400 V", "5 A", "3kg", "4.6"),
        ("malformed", "garbage", True, "NaN", "5 A", " -- ", "1e999"),
        ("zero", "0W", 0, "0 V", "0 A", "0 kg", "0"),
        ("recovery", "-600 W", "-0.6kW", "400 V", "5 A", "2.5kg", "3.6"),
    ):
        responses = []
        for index, route in enumerate(profile["routes"]):
            body = deepcopy(route["body"])
            path = route["path"]
            if path.endswith("energy-flow"):
                for node in body["data"]["flow"]["nodes"]:
                    if node.get("name") == "neteco.pvms.devTypeLangKey.string":
                        node["description"]["value"] = flow
            elif path.endswith("device-real-kpi"):
                body["data"]["signals"] = {
                    "11001": {"value": voltage, "latestTime": 1},
                    "11002": {"value": current, "latestTime": 1},
                }
            elif path.endswith("device-realtime-data"):
                # Distinguish the meter from the inverter by fictional DN.
                if route["params"]["deviceDn"].endswith("METER"):
                    for group in body["data"]:
                        for signal in group["signals"]:
                            if signal["id"] == 10004:
                                signal["value"] = meter
            elif path.endswith("social-contribution"):
                body["data"]["standardCoalSavings"] = coal
                body["data"]["equivalentTreePlanting"] = trees
            elif path.endswith("energy-balance"):
                raw = {"valid": "5 kWh", "malformed": "garbage", "zero": "--", "recovery": "4 kWh"}[name]
                lifetime = route["params"]["timeDim"] == "6"
                # Explicit synthetic station counters, not inferred from topology.
                body["data"]["chargePower"] = []
                body["data"]["dischargePower"] = []
                for key, value in body["data"].items():
                    if isinstance(value, list):
                        body["data"][key] = (
                            ["--", 10 if name == "valid" else 9] if lifetime and name in ("valid", "recovery")
                            else ["--"] if lifetime else [raw] * 31
                        )
                    else:
                        body["data"][key] = (
                            {"valid": 35, "malformed": "--", "zero": "--", "recovery": 34}[name]
                            if lifetime else raw
                        )
            else:
                continue
            responses.append({"route": index, "body": body})
        profile["frames"].append({"id": name, "responses": responses})
    return profile


async def run(report):
    from homeassistant import loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.const import __version__ as ha_version
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import entity_registry as er
    from custom_components.fusion_solar_app.mock_profile import load_profile
    from custom_components.fusion_solar_app.api.models import NUMERIC_DEVICE_UNITS
    from custom_components.fusion_solar_app.sensor import FusionSolarSensor

    for kind, unit in NUMERIC_DEVICE_UNITS.items():
        require(FusionSolarSensor.UNIT_MAP.get(kind, "") == unit, f"Parser/unit metadata mismatch: {kind}")
    require(ha_version == "2026.10.4", f"Unexpected HA: {ha_version}")
    require("pytest" not in sys.modules, "Must run without pytest/stubs")
    report["homeassistant"] = ha_version
    os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(ROOT / "tests/fixtures/runtime_profiles")
    profile = numeric_profile(load_profile)
    attempts = []

    def deny(*args, **kwargs):
        attempts.append(str(args))
        raise AssertionError("External network forbidden by disposable numeric checker")

    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def connect(sock, address):
        return deny(address) if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect(sock, address)

    def connect_ex(sock, address):
        return deny(address) if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect_ex(sock, address)

    with tempfile.TemporaryDirectory(prefix="fusionsolar-numeric-", dir="/tmp") as tmp:
        root = Path(tmp)
        (root / "profiles").mkdir()
        (root / "profiles" / f"{profile['id']}.json").write_text(json.dumps(profile))
        os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(root / "profiles")
        (root / "custom_components").symlink_to(ROOT / "custom_components", target_is_directory=True)
        hass = HomeAssistant(tmp)
        hass.config.skip_pip = True
        hass.config.time_zone = "UTC"
        hass.config.latitude = hass.config.longitude = 0
        loader.async_setup(hass)
        hass.config_entries = ConfigEntries(hass, {})
        try:
            with ExitStack() as guards:
                guards.enter_context(patch.object(socket.socket, "connect", connect))
                guards.enter_context(patch.object(socket.socket, "connect_ex", connect_ex))
                guards.enter_context(patch("socket.create_connection", deny))
                guards.enter_context(patch("socket.getaddrinfo", deny))
                guards.enter_context(patch("requests.sessions.Session.send", deny))
                require(await async_load_base_functionality(hass), "Base HA setup failed")
                await hass.async_start()
                result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "mock"})
                result = await hass.config_entries.flow.async_configure(result["flow_id"], {"mock_profile": profile["id"]})
                require(result["type"] == "create_entry", f"Mock flow failed: {result}")
                entry = result["result"]
                await hass.async_block_till_done()
                require(entry.state is ConfigEntryState.LOADED, f"Entry failed: {entry.reason}")
                coordinator = hass.data[DOMAIN][entry.entry_id].coordinator
                api = coordinator.api
                require(not api.session.adapters, "Offline session must have no network adapters")
                identities = policies = None
                targets = {
                    "panel_production_power": [0.6, None, 0, -0.6],
                    "power_sensor_active_power": [0.6, None, 0, -0.6],
                    "power_sensor_direction": ["exporting", None, "idle", "importing"],
                    "inverter_pv1_voltage": [400, None, 0, 400],
                    "inverter_pv1_current": [5, 5, 0, 5],
                    "inverter_pv1_power": [2, None, 0, 2],
                    "standard_coal_saved": [3, None, 0, 2.5],
                    "equivalent_trees_planted": [5, None, 0, 4],
                    "house_load_power": [0.6] * 4,
                    "panel_production_today": [5, None, 0, 4],
                    "panel_production_week": [5 * (datetime.now().weekday() + 1), None, 0, 4 * (datetime.now().weekday() + 1)],
                    "panel_production_month": [5, None, 0, 4],
                    "panel_production_year": [5, None, 0, 4],
                    "house_load_month": [5, None, 0, 4],
                    "grid_consumption_today": [5, None, 0, 4],
                    "grid_consumption_year": [5, None, 0, 4],
                    "battery_injection_month": [5 * datetime.now().day, None, 0, 4 * datetime.now().day],
                    "battery_injection_year": [5 * datetime.now().month, None, 0, 4 * datetime.now().month],
                    "panel_production_lifetime": [35, None, None, 34],
                    "battery_injection_lifetime": [10, None, None, 9],
                }
                for index, frame in enumerate(profile["frames"]):
                    before = len(api.session.calls)
                    if index:
                        api.queue_frame("advance")
                        await coordinator.async_refresh()
                        await hass.async_block_till_done()
                    require(api.frame_id == frame["id"], "HTTP frame not consumed by coordinator")
                    require(len(api.session.calls) > before if index else bool(api.session.calls), "No offline HTTP reads")
                    require(coordinator.last_update_success, "Malformed optional value failed whole poll")
                    require(not api.unexpected_requests, f"Unmatched offline routes: {api.unexpected_requests}")
                    registry = er.async_get(hass)
                    entities = er.async_entries_for_config_entry(registry, entry.entry_id)
                    current_ids = sorted((e.entity_id, e.unique_id, e.device_id) for e in entities)
                    current_policies = {e.entity_id: tuple(hass.states.get(e.entity_id).attributes.get(k)
                                        for k in ("unit_of_measurement", "device_class", "state_class")) for e in entities}
                    if identities is None:
                        identities, policies = current_ids, current_policies
                    require(current_ids == identities, "Registered entity/unique/device IDs changed")
                    require(current_policies == policies, "Units/classes changed")
                    observed = {}
                    for suffix, values in targets.items():
                        matches = [e for e in entities if e.unique_id.endswith(suffix)]
                        require(len(matches) == 1, f"Missing/duplicate numeric target {suffix}")
                        state = hass.states.get(matches[0].entity_id)
                        expected = values[index]
                        if expected is None:
                            require(state.state == "unavailable", f"Invalid telemetry not unavailable: {suffix}: {state.state}")
                        elif isinstance(expected, str):
                            require(state.state == expected, f"Wrong direction: {state.state}")
                        else:
                            require(state.state not in ("unavailable", "unknown"), f"Missing numeric state: {suffix}: {state.state} in {frame['id']}")
                            require(float(state.state) == expected, f"Wrong numeric state: {suffix}: {state.state}")
                        observed[suffix] = state.state
                    report["frames"].append({"frame": frame["id"], "states": observed,
                                             "registered_entities": len(entities), "ids_units_classes_stable": True,
                                             "http_requests": len(api.session.calls) - before if index else len(api.session.calls)})
                require(not attempts, f"Network attempts: {attempts}")
                report["network_attempts"] = attempts
                require(await hass.config_entries.async_unload(entry.entry_id), "Unload failed")
        finally:
            for entry in hass.config_entries.async_entries(DOMAIN):
                if entry.state is ConfigEntryState.LOADED:
                    await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_stop(force=True)
            await hass.async_block_till_done()


async def main():
    report = {"status": "running", "origin": "synthetic, not new Huawei evidence", "frames": []}
    try:
        await asyncio.wait_for(run(report), timeout=300)
    except Exception as err:
        report.update(status="failed", error=f"{type(err).__name__}: {err}")
        print(json.dumps(report, indent=2), flush=True)
        raise
    report["status"] = "passed"
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(main())
