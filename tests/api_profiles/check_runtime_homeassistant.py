#!/usr/bin/env python3
"""Validate real config flows, polling, platforms, registries and states offline.

Run (no pytest, stubs, live config mount, dependency downloads or HA HTTP server)::

    docker run --rm --pull never --network none --read-only --tmpfs /tmp \
      -v /tmp/opencode/fusionsolar-repo:/src:ro -w /src --entrypoint python \
      ghcr.io/home-assistant/home-assistant:2026.10.4 \
      tests/api_profiles/check_runtime_homeassistant.py

Only an isolated temporary config directory is written. Transport guards fail even
when an optional API reader catches the raised exception. Instrumentation observes
and delegates to the ORIGINAL production get_devices; it never supplies Device
objects or substitutes HA classes. JSON on stdout is the machine-readable report;
HA diagnostics and tracebacks go to stderr. Any failed assertion exits nonzero.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from contextlib import ExitStack
import json
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "fusion_solar_app"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


async def run(report):
    # These are installed HA modules, not tests/conftest.py's stand-ins.
    from homeassistant import loader
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.const import __version__ as ha_version
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import device_registry as dr, entity_registry as er

    report["homeassistant"] = ha_version
    require(ha_version == "2026.10.4", f"Expected actual HA 2026.10.4, got {ha_version}")
    require("pytest" not in sys.modules, "Run standalone, not under pytest/stubs")
    os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(ROOT / "tests/fixtures/runtime_profiles")
    network_attempts = []

    def deny_network(*args, **kwargs):
        network_attempts.append(repr(args[1:] if len(args) > 1 else args))
        raise AssertionError("Network access forbidden by offline runtime checker")

    # AF_UNIX sockets / asyncio's self-pipe remain usable. No TCP connection or
    # DNS lookup is needed by this minimal, non-HTTP HA runtime.
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def guard_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            return deny_network(sock, address)
        return original_connect(sock, address)

    def guard_connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            return deny_network(sock, address)
        return original_connect_ex(sock, address)

    with tempfile.TemporaryDirectory(prefix="fusionsolar-runtime-", dir="/tmp") as config_dir:
        Path(config_dir, "custom_components").symlink_to(ROOT / "custom_components", target_is_directory=True)
        hass = HomeAssistant(config_dir)
        hass.config.skip_pip = True
        hass.config.time_zone = "UTC"
        hass.config.latitude = 0
        hass.config.longitude = 0
        loader.async_setup(hass)
        hass.config_entries = ConfigEntries(hass, {})
        try:
            with ExitStack() as guards:
                guards.enter_context(patch.object(socket.socket, "connect", guard_connect))
                guards.enter_context(patch.object(socket.socket, "connect_ex", guard_connect_ex))
                guards.enter_context(patch("socket.create_connection", deny_network))
                guards.enter_context(patch("socket.getaddrinfo", deny_network))
                guards.enter_context(patch("requests.sessions.Session.send", deny_network))
                from homeassistant.bootstrap import async_load_base_functionality

                require(await async_load_base_functionality(hass), "HA base functionality failed")
                # Import via the same custom_components namespace used by HA's
                # loader. Never bypass integration __init__ with a fake package.
                from custom_components.fusion_solar_app.api import FusionSolarAPI
                from custom_components.fusion_solar_app.mock_api import MockFusionSolarAPI
                from custom_components.fusion_solar_app.mock_profile import list_profiles, load_profile
                from custom_components.fusion_solar_app.sensor import SUPPORTED_SENSOR_DEVICE_TYPES

                discoveries = Counter()
                logins = Counter()
                original_mock_login = MockFusionSolarAPI.login

                def observed_mock_login(api):
                    logins[id(api)] += 1
                    return original_mock_login(api)

                guards.enter_context(patch.object(MockFusionSolarAPI, "login", observed_mock_login))
                original_get_devices = FusionSolarAPI.get_devices

                def observed_get_devices(api, *args, **kwargs):
                    discoveries[id(api)] += 1
                    return original_get_devices(api, *args, **kwargs)

                guards.enter_context(patch.object(FusionSolarAPI, "get_devices", observed_get_devices))
                profiles = await hass.async_add_executor_job(list_profiles)
                require(profiles, "No valid runtime profiles found (backend/fixtures may not be ready)")
                report["profile_count"] = len(profiles)
                # Start core lifecycle without default_config, HTTP, recorder,
                # discovery or anything that might contact an existing HA.
                await hass.async_start()
                for profile_id in profiles:
                    profile = await hass.async_add_executor_job(load_profile, profile_id)
                    item = {"profile": profile_id, "title": profile["title"], "status": "running"}
                    report["entries"].append(item)
                    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "mock"})
                    require(result["type"] == "form" and result["step_id"] == "mock", f"Mock flow failed: {result}")
                    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"mock_profile": profile_id})
                    require(result["type"] == "create_entry", f"Mock entry creation failed: {result}")
                    entry = result["result"]
                    item["entry_id"] = entry.entry_id
                    await hass.async_block_till_done()
                    require(entry.state is ConfigEntryState.LOADED, f"{profile_id}: setup state {entry.state}; error={entry.reason}")
                    require(entry.data["mock_profile"] == profile_id, "Missing mock marker")
                    require(entry.data["username"].startswith("mock-"), "Nonfictional account")
                    require(entry.data["fusion_solar_host"] == "example.invalid", "Real login endpoint in mock entry")

                    def snapshot():
                        coordinator = hass.data[DOMAIN][entry.entry_id].coordinator
                        api = coordinator.api
                        require(isinstance(api, MockFusionSolarAPI), "Coordinator did not select mock API")
                        require(discoveries[id(api)] > 0, "Production FusionSolarAPI.get_devices was not executed")
                        require(coordinator.last_update_success, "Coordinator update failed")
                        require(not api.unexpected_requests, f"Unmatched requests: {api.unexpected_requests}")
                        require(api.session.calls, "No actual offline HTTP reader requests recorded")
                        registry = er.async_get(hass)
                        entities = er.async_entries_for_config_entry(registry, entry.entry_id)
                        devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
                        require(entities and devices, "No real registered entities/devices")
                        by_unique = {entity.unique_id: entity for entity in entities}
                        expected = {f"{DOMAIN}-{device.device_unique_id}" for device in coordinator.data.devices
                                    if device.device_type in SUPPORTED_SENSOR_DEVICE_TYPES}
                        require(expected, "Production discovery returned no supported sensors")
                        require(not (expected - by_unique.keys()), f"Missing sensors: {sorted(expected - by_unique.keys())}")
                        require(len(entities) == len(expected) + 2, f"Expected {len(expected)} API sensors + 2 forecast sensors, got {len(entities)}")
                        output = []
                        for entity in entities:
                            state = hass.states.get(entity.entity_id)
                            require(entity.device_id is not None, f"Unassociated entity: {entity.entity_id}")
                            require(state is not None, f"No actual HA state: {entity.entity_id}")
                            if profile_id != "isitepower-mains-import":
                                require(state.state != "unavailable", f"Unavailable entity: {entity.entity_id}")
                            # This sparse mixed profile intentionally omits telemetry.
                            # Existing sensor availability represents None as unavailable.
                            output.append({"entity_id": entity.entity_id, "unique_id": entity.unique_id,
                                           "device_id": entity.device_id, "name": entity.original_name,
                                           "state": state.state, "attributes": dict(state.attributes)})
                        device_by_identifier = {identifier: device for device in devices for domain, identifier in device.identifiers if domain == DOMAIN}
                        prefix = f"{api.controller_name}_{profile['station']['dn']}"
                        plant = device_by_identifier.get(prefix)
                        require(plant is not None, "Missing fictional plant registry device")
                        require(profile["station"]["dn"].startswith("MOCK_RUNTIME_"), "Nonfictional station")
                        expected_devices = {prefix}
                        topology = profile.get("topology", {})
                        for kind, singular in (("inverters", "inverter"), ("batteries", "battery")):
                            for node in topology.get(kind, []):
                                identifier = f"{prefix}_{singular}_{node['dn']}"
                                expected_devices.add(identifier)
                                device = device_by_identifier.get(identifier)
                                require(device is not None, f"Missing topology device {identifier}")
                                parent_identifier = f"{prefix}_inverter_{node['parentDn']}" if node.get("parentDn") else prefix
                                parent = device_by_identifier.get(parent_identifier)
                                require(parent is not None and device.via_device_id == parent.id,
                                        f"Incorrect {identifier} parent: {device.via_device_id}, expected {parent_identifier}")
                                require(any(entity.device_id == device.id for entity in entities), f"No sensors on {identifier}")
                        # Optimizer identities/parents are declared in HTTP bodies,
                        # independently of whatever devices the API returned.
                        optimizer_rows = []
                        for route in profile["routes"]:
                            if route["path"].endswith("/optimizer-info"):
                                optimizer_rows.extend(route["body"].get("data", []))
                        for node in optimizer_rows:
                            identifier = f"{prefix}_optimizer_{node['dn']}"
                            expected_devices.add(identifier)
                            device = device_by_identifier.get(identifier)
                            parent = device_by_identifier.get(f"{prefix}_inverter_{node['parentDn']}")
                            require(device is not None and parent is not None and device.via_device_id == parent.id,
                                    f"Missing/wrong optimizer topology {identifier}")
                        require(expected_devices <= device_by_identifier.keys(), "Missing expected device identities")
                        criteria = {"registered_discovered_sensors": len(expected), "expected_device_identities": sorted(expected_devices),
                                    "production_get_devices_calls": discoveries[id(api)], "offline_http_requests": len(api.session.calls),
                                    "unmatched_requests": list(api.unexpected_requests)}
                        # Retain real inspection results even if a later semantic
                        # assertion fails, making missing/incorrect fields visible.
                        item.update(entity_count=len(output), device_count=len(devices), entities=output,
                                    devices=[{"id": d.id, "identifiers": sorted(d.identifiers),
                                              "via_device_id": d.via_device_id, "name": d.name} for d in devices],
                                    expected_criteria=criteria)
                        if optimizer_rows:
                            # Rich observed-safe profile must not silently lose the
                            # corrected fields even if discovery filters them out.
                            for suffix, value, unit, name, icon in (
                                ("battery_forced_charge_power", 3.03, "kW", "Battery Forced Charge Power", None),
                                ("battery_forced_charge_discharge_period", 1440, "min", "Battery Forced Charge Discharge Period", "mdi:battery"),
                                ("battery_charged_energy", 1.75, "kWh", "Battery Forced Charge Energy", None),
                            ):
                                matches = [obj for obj in output if obj["unique_id"].endswith(suffix)]
                                require(matches, f"Missing corrected sensor {suffix}")
                                for obj in matches:
                                    require(float(obj["state"]) == value, f"Wrong value: {obj}")
                                    require(obj["attributes"].get("unit_of_measurement") == unit, f"Wrong unit: {obj}")
                                    require(obj["name"] == name, f"Wrong corrected name: {obj}")
                                    if icon:
                                        require(obj["attributes"].get("icon") == icon, f"Wrong duration icon: {obj}")
                            temperatures = [obj for obj in output if "optimizer_temperature" in obj["unique_id"]]
                            require(any(float(obj["state"]) == 15.1 and obj["attributes"].get("unit_of_measurement") == "°C" for obj in temperatures),
                                    "Missing actual registered optimizer 15.1°C state")
                            criteria["corrected_forced_charge_and_optimizer_values"] = True
                        if profile_id == "isitepower-mains-import":
                            for suffix, expected_state in (("grid_consumption_power", "0.64"),
                                                           ("grid_injection_power", "unavailable")):
                                matches = [obj for obj in output if obj["unique_id"].endswith(suffix)]
                                require(len(matches) == 1, f"Missing/duplicate iSitePower grid sensor {suffix}")
                                obj = matches[0]
                                require(obj["state"] == expected_state, f"Unproven/wrong grid state: {obj}")
                                require(obj["attributes"].get("unit_of_measurement") == "kW", f"Wrong grid unit: {obj}")
                            criteria["isitepower_import_0_64_kw_export_unknown"] = True
                        identities = sorted((obj["entity_id"], obj["unique_id"], obj["device_id"]) for obj in output)
                        return coordinator, identities, output, devices, criteria

                    coordinator, identities, entities, devices, criteria = snapshot()
                    previous_calls = discoveries[id(coordinator.api)]
                    await coordinator.async_request_refresh()
                    await hass.async_block_till_done()
                    require(discoveries[id(coordinator.api)] > previous_calls, "Forced refresh did not execute get_devices")
                    require(snapshot()[1] == identities, "Refresh changed entity/unique/device IDs")
                    if profile.get("frames"):
                        from homeassistant.exceptions import HomeAssistantError
                        import voluptuous as vol

                        api = coordinator.api
                        original_session = api.session
                        initial_logins = logins[id(api)]
                        frames_report = []
                        item["http_transitions"] = frames_report
                        energy = next(obj for obj in entities if obj["unique_id"].endswith("panel_production_lifetime"))
                        config = next(obj for obj in entities if obj["unique_id"].endswith("battery_forced_charge_power"))
                        live = next(obj for obj in entities if obj["unique_id"].endswith("panel_production_power"))
                        async def control(operation, entry_id=entry.entry_id):
                            await hass.services.async_call(DOMAIN, "mock_scenario", {
                                "config_entry_id": entry_id, "operation": operation,
                            }, blocking=True)
                            await hass.async_block_till_done()

                        for index, frame in enumerate(profile["frames"]):
                            before = len(api.session.calls)
                            if index:
                                await control("advance")
                            else:
                                await control("reset")
                            name = frame["id"]
                            required_failure = name in ("required-timeout", "required-http-500", "required-http-418", "required-connection")
                            require(api.frame_id == name, f"Frame not applied: {name}")
                            require(len(api.session.calls) > before, "Control did not poll actual HTTP readers")
                            require(coordinator.last_update_success != required_failure, f"Wrong coordinator success for {name}")
                            require(api.session is original_session and api.connected, "Transient/optional failure unnecessarily replaced session")
                            require(logins[id(api)] == initial_logins, "Transient/optional failure unnecessarily logged in again")
                            if required_failure:
                                require(len(api.session.calls) - before == 2, "Required failure retry was not bounded to two HTTP requests")
                            require(not api.unexpected_requests, "Unexpected route swallowed")
                            current = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
                            require(sorted((e.entity_id, e.unique_id, e.device_id) for e in current) == identities, "Transition changed registry IDs")
                            states = {obj["entity_id"]: hass.states.get(obj["entity_id"]) for obj in entities}
                            if required_failure:
                                # Forecast entities are independent projections; all API sensors fail closed.
                                for obj in entities:
                                    if obj["unique_id"] in {f"{DOMAIN}-{d.device_unique_id}" for d in coordinator.data.devices}:
                                        require(states[obj["entity_id"]].state == "unavailable", f"Required failure left stale API sensor: {obj['entity_id']}")
                            elif profile_id == "transitions-energy":
                                expected = ["35", "34", "unavailable", "unavailable", "unavailable", "0", "34"][index]
                                state = states[energy["entity_id"]]
                                require(state.state == expected or (expected != "unavailable" and float(state.state) == float(expected)), f"Wrong HTTP energy state: {name}: {state.state}")
                                require(state.attributes.get("state_class") == "total_increasing", "Energy policy changed")
                                require(state.attributes.get("unit_of_measurement") == "kWh", "Energy unit changed")
                                require(states[live["entity_id"]].state != "unavailable", "Invalid lifetime reading affected valid power")
                            else:
                                expected = "unavailable" if name in ("optional-config-403", "optional-config-418") else "3.03"
                                require(states[config["entity_id"]].state == expected, f"Optional config did not invalidate/recover: {name}")
                                require(states[live["entity_id"]].state != "unavailable", "Optional failure affected valid power")
                                expected_energy = "unavailable" if name == "historical-lifetime-418" else "100.0"
                                require(states[energy["entity_id"]].state == expected_energy, f"Historical failure did not isolate/recover: {name}")
                            frames_report.append({"frame": name, "coordinator_success": coordinator.last_update_success,
                                                  "energy": states[energy["entity_id"]].state,
                                                  "config": states[config["entity_id"]].state,
                                                  "http_requests": len(api.session.calls) - before})
                        try:
                            await control("advance")
                        except HomeAssistantError:
                            pass
                        else:
                            raise AssertionError("Advance beyond last frame accepted")
                        try:
                            await control("reset", "not-a-mock-entry")
                        except HomeAssistantError:
                            pass
                        else:
                            raise AssertionError("Non-mock service target accepted")
                        try:
                            await control("arbitrary-code")
                        except vol.Invalid:
                            pass
                        else:
                            raise AssertionError("Unknown operation accepted")
                        opt_in = os.environ.pop("FUSIONSOLAR_DEV_PROFILE_DIR")
                        try:
                            try:
                                await control("reset")
                            except HomeAssistantError:
                                pass
                            else:
                                raise AssertionError("Control accepted missing environment opt-in")
                        finally:
                            os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = opt_in
                        await control("reset")
                        require(snapshot()[1] == identities, "Reset changed identities")
                    require(await hass.config_entries.async_reload(entry.entry_id), "Reload failed")
                    await hass.async_block_till_done()
                    require(entry.state is ConfigEntryState.LOADED, f"Reload state: {entry.state}")
                    require(snapshot()[1] == identities, "Reload changed entity/unique/device IDs")
                    require(await hass.config_entries.async_unload(entry.entry_id), "Unload failed")
                    await hass.async_block_till_done()
                    require(entry.state is ConfigEntryState.NOT_LOADED, f"Unload state: {entry.state}")
                    require(entry.entry_id not in hass.data.get(DOMAIN, {}), "Coordinator leaked after unload")
                    require(not coordinator.api.unexpected_requests, "Unmatched request during teardown")
                    for entity_id, _, _ in identities:
                        state = hass.states.get(entity_id)
                        require(state is None or state.state == "unavailable", f"Live entity left after unload: {entity_id}")
                    require(await hass.config_entries.async_setup(entry.entry_id), "Clean setup after unload failed")
                    await hass.async_block_till_done()
                    coordinator, new_ids, entities, devices, criteria = snapshot()
                    require(new_ids == identities, "Unload/setup changed identities")
                    item.update(status="passed", entity_count=len(entities), device_count=len(devices),
                                entities=entities, devices=[{"id": d.id, "identifiers": sorted(d.identifiers),
                                                            "via_device_id": d.via_device_id, "name": d.name} for d in devices],
                                expected_criteria=criteria, refresh_reload_unload_setup="passed")
                    require(await hass.config_entries.async_unload(entry.entry_id), "Final entry unload failed")
                    require(not hass.services.has_service(DOMAIN, "mock_scenario"), "Mock control leaked after final transition unload")
                require(not network_attempts, f"External network attempts (possibly swallowed): {network_attempts}")
                report["network_attempts"] = network_attempts
        finally:
            # Also release the integration's polling/session resources on failed
            # semantic assertions, not just on the happy path.
            for entry in hass.config_entries.async_entries(DOMAIN):
                if entry.state is ConfigEntryState.LOADED:
                    await hass.config_entries.async_unload(entry.entry_id)
            await hass.async_stop(force=True)
            await hass.async_block_till_done()


async def main():
    report = {"status": "running", "coverage": "real HA config flow -> async_setup_entry -> coordinator -> production get_devices -> sensor platform -> device/entity registries and states", "entries": []}
    try:
        await asyncio.wait_for(run(report), timeout=600)
    except Exception as err:
        report.update(status="failed", error=f"{type(err).__name__}: {err}")
        for item in report["entries"]:
            if item["status"] == "running":
                item.update(status="failed", error=report["error"])
        print(json.dumps(report, indent=2, default=str), flush=True)
        raise
    report["status"] = "passed"
    print(json.dumps(report, indent=2, default=str), flush=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(main())
