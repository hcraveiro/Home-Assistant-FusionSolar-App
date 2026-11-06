#!/usr/bin/env python3
"""Disposable actual-HA lifecycle regressions; never import under pytest.

Run in HA 2026.10.4 with --network none, read-only source and tmpfs /tmp. See
 docs/lifecycle-validation.md. Registry/config entry persistence is exclusively
through HA APIs and normal stop/load, never direct internal storage edits.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import ExitStack, asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "fusion_solar_app"
DUAL = "two-inverters-two-batteries"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


@asynccontextmanager
async def home(config_dir):
    """Use actual loader, stores, registries, flow managers and sensor platform."""
    from homeassistant import loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.core import HomeAssistant

    link = Path(config_dir, "custom_components")
    if not link.exists():
        link.symlink_to(ROOT / "custom_components", target_is_directory=True)
    hass = HomeAssistant(config_dir)
    hass.config.skip_pip = True
    hass.config.time_zone = "UTC"
    hass.config.latitude = hass.config.longitude = 0
    loader.async_setup(hass)
    hass.config_entries = ConfigEntries(hass, {})
    require(await async_load_base_functionality(hass), "HA base functionality failed")
    await hass.async_start()
    try:
        yield hass
    finally:
        for entry in hass.config_entries.async_entries(DOMAIN):
            if entry.state is ConfigEntryState.LOADED:
                await hass.config_entries.async_unload(entry.entry_id)
        # HA flushes its own stores on stop. A second HomeAssistant loads those
        # stores using the normal bootstrap path above, not a fabricated fixture.
        await hass.async_stop(force=True)
        await hass.async_block_till_done()


def coordinator(hass, entry):
    return hass.data[DOMAIN][entry.entry_id].coordinator


def identities(hass, entry):
    from homeassistant.helpers import entity_registry as er
    return sorted((e.entity_id, e.unique_id, e.device_id, e.config_entry_id)
                  for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id))


def metadata(entity):
    return {key: getattr(entity, key) for key in (
        "id", "entity_id", "device_id", "config_entry_id", "name", "icon",
        "area_id", "labels", "disabled_by", "hidden_by", "created_at",
    )}


async def mock_entry(hass, profile_id):
    from homeassistant.config_entries import ConfigEntryState
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "mock"})
    require(result["type"] == "form", f"Mock form failed: {result}")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"mock_profile": profile_id})
    require(result["type"] == "create_entry", f"Mock creation failed: {result}")
    await hass.async_block_till_done()
    entry = result["result"]
    require(entry.state is ConfigEntryState.LOADED, f"Mock setup failed: {entry.state}, {entry.reason}")
    return entry


async def seeded_entry(hass, profile, ambiguous):
    """Official APIs create disabled entry first, so registry seeding precedes setup."""
    from homeassistant.config_entries import ConfigEntry, ConfigEntryDisabler
    from homeassistant.helpers import area_registry as ar, device_registry as dr, entity_registry as er, label_registry as lr

    station = profile["station"]["dn"]
    prefix = f"{DOMAIN}_{station}"
    unique = f"{DOMAIN}-{DOMAIN}_{station.lower()}"
    entry = ConfigEntry(
        version=1, minor_version=1, domain=DOMAIN, source="user",
        title="MOCK_RUNTIME legacy migration", unique_id="MOCK_RUNTIME_SEEDED",
        data={"mock_profile": DUAL, "username": "mock-seeded", "password": "unused",
              "fusion_solar_host": "example.invalid", "station_dn": station},
        options={}, disabled_by=ConfigEntryDisabler.USER,
        discovery_keys=MappingProxyType({}), subentries_data=[],
    )
    await hass.config_entries.async_add(entry)
    devices = dr.async_get(hass)
    # Deliberately register secondary A first, while legacy telemetry belongs to B.
    ids = {}
    for kind, dns in (("inverter", ["MOCK_RUNTIME_INV_A", "MOCK_RUNTIME_INV_B"]),
                      ("battery", ["MOCK_RUNTIME_BAT_A", "MOCK_RUNTIME_BAT_B"])):
        for dn in dns:
            device = devices.async_get_or_create(
                config_entry_id=entry.entry_id,
                identifiers={(DOMAIN, f"{prefix}_{kind}_{other}") for other in dns}
                if ambiguous == "conflicting-device" and kind == "inverter"
                else {(DOMAIN, f"{prefix}_{kind}_{dn}")}, name=f"MOCK_RUNTIME {dn}",
            )
            devices.async_update_device(device.id, name_by_user=f"Custom {dn}")
            ids[dn] = device.id
    area = ar.async_get(hass).async_create("MOCK_RUNTIME Custom area")
    label = lr.async_get(hass).async_create("MOCK_RUNTIME Custom label")
    registry = er.async_get(hass)
    selected = []
    for suffix, owner, disabled in (
        ("inverter_pv1_voltage", "MOCK_RUNTIME_INV_B", False),
        ("battery_soc", "MOCK_RUNTIME_BAT_B", True),
    ):
        entity = registry.async_get_or_create(
            "sensor", DOMAIN, f"{unique}_{suffix}", config_entry=entry,
            device_id=None if ambiguous is True or (ambiguous and suffix == "battery_soc") else ids[owner],
            suggested_object_id=f"mock_runtime_custom_{suffix}",
            disabled_by=er.RegistryEntryDisabler.USER if disabled else None,
        )
        entity = registry.async_update_entity(
            entity.entity_id, name=f"User {suffix}", icon="mdi:test-tube",
            area_id=area.id, labels={label.label_id}, hidden_by=er.RegistryEntryHider.USER,
        )
        selected.append((entity.entity_id, entity.unique_id, metadata(entity)))
    require(await hass.config_entries.async_set_disabled_by(entry.entry_id, None), "Enable/setup failed")
    await hass.async_block_till_done()
    return entry, selected, ids


async def check_registry(report, ambiguous=False):
    from homeassistant.config_entries import ConfigEntryState
    from homeassistant.helpers import device_registry as dr, entity_registry as er
    from custom_components.fusion_solar_app.mock_profile import load_profile

    profile = load_profile(DUAL)
    with tempfile.TemporaryDirectory(prefix="fusionsolar-registry-", dir="/tmp") as directory:
        saved = None
        for generation in range(2):
            async with home(directory) as hass:
                if not generation:
                    entry, selected, owners = await seeded_entry(hass, profile, ambiguous)
                    entry_id = entry.entry_id
                else:
                    entry = hass.config_entries.async_get_entry(entry_id)
                    require(entry is not None, "Config entry missing after fresh HA/storage load")
                    require(await hass.config_entries.async_setup(entry.entry_id), "Fresh HA setup failed")
                    await hass.async_block_till_done()
                require(entry.state is ConfigEntryState.LOADED, f"Seeded setup state {entry.state}: {entry.reason}")
                api = coordinator(hass, entry).api
                registry = er.async_get(hass)
                for entity_id, old_unique, before in selected:
                    current = registry.async_get(entity_id)
                    require(current is not None and metadata(current) == before,
                            f"Migration changed user metadata/ownership: {entity_id}: {metadata(current) if current else None}")
                    expected = old_unique
                    if not ambiguous and "_inverter_" in old_unique:
                        expected = old_unique.replace("_inverter_", "_inv_mock_runtime_inv_b_inverter_")
                    require(current.unique_id == expected, f"Wrong migration unique ID: {current.unique_id}")
                    if current.disabled_by:
                        require(hass.states.get(entity_id) is None, "User-disabled legacy entity became enabled")
                    elif not ambiguous:
                        state = hass.states.get(entity_id)
                        require(state is not None and state.state not in {"unavailable", "unknown"},
                                "Migrated legacy inverter did not reattach to live production-reader telemetry")
                for dn, device_id in owners.items():
                    device = dr.async_get(hass).async_get(device_id)
                    require(device is not None and device.config_entry_id == entry.entry_id, "Device owner changed")
                    expected_name = "MOCK_RUNTIME_INV_B" if ambiguous == "conflicting-device" and dn.startswith("MOCK_RUNTIME_INV_") else dn
                    require(device.name_by_user == f"Custom {expected_name}", "Device user name changed")
                if ambiguous:
                    require(api.battery_dn is None and api._battery_primary_ambiguous,
                            "Ambiguous legacy battery arbitrarily acquired a primary")
                    require("primary_battery_dn" not in entry.data, "Ambiguous primary was persisted")
                    require(any("_inv_mock_runtime_bat_a_battery_soc" in row[1] for row in identities(hass, entry)),
                            "Ambiguous case lost scoped battery telemetry")
                else:
                    require(api.battery_dn == "MOCK_RUNTIME_BAT_B", "Registry order overrode legacy primary B")
                    require(entry.data.get("primary_battery_dn") == "MOCK_RUNTIME_BAT_B", "Primary identity not persisted")
                current_ids = identities(hass, entry)
                if saved is None:
                    saved = current_ids
                require(current_ids == saved, "Fresh HA/storage lifecycle changed IDs/owners")
                require(not api.unexpected_requests, "Unmatched offline request")
                require(await hass.config_entries.async_unload(entry.entry_id), "Seeded unload failed")
                require(api._closed, "Seeded unload leaked API")
                require(await hass.config_entries.async_setup(entry.entry_id), "Seeded setup-after-unload failed")
                await hass.async_block_till_done()
                require(identities(hass, entry) == saved, "Unload/setup changed seeded IDs")
        report.update(status="passed", generations=2, entities=len(saved), seeded_entities=selected,
                      policy="legacy preserved; all batteries scoped" if ambiguous else "legacy inverter B migrated; primary battery B retained",
                      persistence="HA stop/store flush -> new HomeAssistant/base load -> setup")


@asynccontextmanager
async def offline_account_boundary(profile):
    """Replace API construction only. Real flow/coordinator/platforms stay intact.

    Authentication is SYNTHETIC, not a real Huawei login or CAPTCHA verification.
    The subclass uses production data readers and a network-incapable session.
    """
    from custom_components.fusion_solar_app import config_flow, coordinator as module
    from custom_components.fusion_solar_app.mock_api import MockFusionSolarAPI

    instances = []

    class OfflineAccountAPI(MockFusionSolarAPI):
        def __init__(self, user, pwd, login_host, captcha_input=None):
            require(user.startswith("MOCK_RUNTIME_"), "Nonfictional account in lifecycle test")
            super().__init__(profile)
            self.user, self.pwd = user, pwd
            self.captcha_input = captcha_input
            self.login_calls = 0
            self.close_calls = 0
            instances.append(self)

        def login(self):
            self.login_calls += 1
            return super().login()

        def close(self):
            self.close_calls += 1
            return super().close()

    with patch.object(config_flow, "FusionSolarAPI", OfflineAccountAPI), patch.object(module, "FusionSolarAPI", OfflineAccountAPI):
        yield instances


async def account_entry(hass, username="MOCK_RUNTIME_ACCOUNT_A"):
    from homeassistant.config_entries import ConfigEntryState
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "account"})
    require(result["type"] == "form", f"Account form failed: {result}")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {
        "username": username, "password": "MOCK_RUNTIME_UNUSED", "fusion_solar_host": "example.invalid",
    })
    require(result.get("step_id") == "select_station", f"Account validation failed: {result}")
    from custom_components.fusion_solar_app.mock_profile import load_profile
    station = load_profile(DUAL)["station"]["dn"]
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"station_dn": station})
    require(result["type"] == "create_entry", f"Account creation failed: {result}")
    await hass.async_block_till_done()
    entry = result["result"]
    require("mock_profile" not in entry.data, "Real-account branch was not exercised")
    require(entry.state is ConfigEntryState.LOADED, f"Offline-account setup state {entry.state}: {entry.reason}")
    return entry


async def check_options(report):
    from homeassistant.config_entries import ConfigEntryState
    from homeassistant.exceptions import HomeAssistantError
    from custom_components.fusion_solar_app.mock_profile import load_profile
    import voluptuous as vol

    async with offline_account_boundary(load_profile(DUAL)) as instances:
        with tempfile.TemporaryDirectory(prefix="fusionsolar-options-", dir="/tmp") as directory:
            async with home(directory) as hass:
                entry = await account_entry(hass)
                saved = identities(hass, entry)
                initial = coordinator(hass, entry)
                # State is fictional local input, not an installed/live Solcast API.
                hass.states.async_set("sensor.mock_runtime_solcast", "12", {"detailedHourly": [
                    {"period_start": datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat(), "pv_estimate": 1.25},
                ]})
                hass.states.async_set("sensor.mock_runtime_invalid", "12", {"detailedHourly": [{"pv_estimate": 1}]})
                result = await hass.config_entries.options.async_init(entry.entry_id)
                flow_id = result["flow_id"]
                # HA's actual SelectSelector rejects unknown provider values before
                # the integration's options handler can persist them.
                try:
                    await hass.config_entries.options.async_configure(flow_id, {
                        "scan_interval": 180, "forecast_provider": "MOCK_RUNTIME_INVALID",
                    })
                except (vol.Invalid, HomeAssistantError):
                    pass
                else:
                    raise AssertionError("Unknown forecast provider accepted")
                require(coordinator(hass, entry) is initial and not entry.options, "Invalid provider changed options/reloaded")
                result = await hass.config_entries.options.async_configure(flow_id, {
                    "scan_interval": 180, "forecast_provider": "solcast",
                })
                require(result.get("step_id") == "solcast", "Missing Solcast source step")
                for source in ("sensor.mock_runtime_missing", "sensor.mock_runtime_invalid"):
                    result = await hass.config_entries.options.async_configure(flow_id, {"solcast_forecast_today_entity": source})
                    require(result.get("errors") == {"base": "invalid_solcast_entity"}, f"Invalid source accepted: {result}")
                    require(coordinator(hass, entry) is initial and not entry.options, "Invalid source reloaded entry")
                result = await hass.config_entries.options.async_configure(flow_id, {"solcast_forecast_today_entity": "sensor.mock_runtime_solcast"})
                require(result["type"] == "create_entry", "Solcast options not saved")
                await hass.async_block_till_done()
                solcast = coordinator(hass, entry)
                require(solcast is not initial and initial.api._closed, "Options listener failed to reload/close old API")
                require(solcast.poll_interval == 180 and solcast._get_forecast_provider() == "solcast", "Solcast options not applied")
                require(solcast.data.forecast is not None and solcast.data.forecast.provider == "solcast", "Selected Solcast builder did not run")
                require(identities(hass, entry) == saved, "Solcast reload changed registry identities")
                result = await hass.config_entries.options.async_init(entry.entry_id)
                result = await hass.config_entries.options.async_configure(result["flow_id"], {"scan_interval": 240, "forecast_provider": "native"})
                require(result["type"] == "create_entry", "Native options not saved")
                await hass.async_block_till_done()
                native = coordinator(hass, entry)
                require(native is not solcast and solcast.api._closed, "Native options failed to reload/close")
                require(entry.state is ConfigEntryState.LOADED and native.poll_interval == 240, "Native interval not applied")
                require(native._get_forecast_provider() == "native" and "solcast_forecast_today_entity" not in entry.options, "Stale Solcast option retained")
                require(identities(hass, entry) == saved, "Native reload changed registry identities")
                require(all(not api.unexpected_requests for api in instances), "Unmatched offline account request")
                report.update(status="passed", entities=len(saved), scan_intervals=[180, 240],
                              reloads=2, rejected_sources=["missing", "missing period_start"],
                              authentication="synthetic OfflineAccountAPI only; NOT actual-auth verified")


async def check_authentication(report):
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from homeassistant.helpers.update_coordinator import UpdateFailed
    from custom_components.fusion_solar_app.api import APIAuthError
    from custom_components.fusion_solar_app.mock_profile import load_profile
    from custom_components.fusion_solar_app.mock_api import OfflineSession

    import requests
    from urllib.parse import urlsplit

    async with offline_account_boundary(load_profile(DUAL)) as instances:
        with tempfile.TemporaryDirectory(prefix="fusionsolar-auth-", dir="/tmp") as directory:
            async with home(directory) as hass:
                entry = await account_entry(hass)
                coord = coordinator(hass, entry)
                api = coord.api
                initial_logins = api.login_calls
                original_send = OfflineSession.send
                faults = []
                def expired(session, request, **kwargs):
                    if urlsplit(request.url).path.endswith("/overview/energy-flow"):
                        faults.append(request.url)
                        response = requests.Response()
                        response.status_code = 401
                        response._content = b'{"success": false}'
                        response.url = request.url
                        return response
                    return original_send(session, request, **kwargs)
                # Both the initial required fetch and the post-login required
                # fetch get 401 from the offline HTTP boundary.
                with patch.object(OfflineSession, "send", expired):
                    try:
                        await coord.async_update_data()
                    except (ConfigEntryAuthFailed, UpdateFailed) as err:
                        report["persistent_auth_classification"] = type(err).__name__
                        require(isinstance(err, ConfigEntryAuthFailed),
                                f"Persistent auth failure classified {type(err).__name__}, not ConfigEntryAuthFailed")
                    else:
                        raise AssertionError("Persistent auth failure was swallowed")
                require(api.login_calls - initial_logins == 1 and len(faults) == 2, "Persistent auth retry/login was not bounded")
                # Now exercise HA's actual DUC -> reauth flow path, not just the
                # integration method's exception class.
                with patch.object(OfflineSession, "send", expired):
                    await coord.async_refresh()
                await hass.async_block_till_done()
                flows = [flow for flow in hass.config_entries.flow.async_progress()
                         if flow["context"].get("source") == "reauth" and flow["context"].get("entry_id") == entry.entry_id]
                require(len(flows) == 1, "HA did not start exactly one reauth flow")
                require(isinstance(coord.last_exception, ConfigEntryAuthFailed), "DUC lost permanent-auth classification")
                require(coord._unsub_refresh is None, "HA kept polling after permanent authentication failure")
                result = await hass.config_entries.flow.async_configure(flows[0]["flow_id"], {
                    "username": "MOCK_RUNTIME_ACCOUNT_A", "password": "MOCK_RUNTIME_REPLACED", "fusion_solar_host": "example.invalid",
                })
                require(result["type"] == "abort" and result["reason"] == "reauth_successful", f"Synthetic non-CAPTCHA reauth failed: {result}")
                await hass.async_block_till_done()
                require(api._closed, "Reauth reload leaked old API")
                coord = coordinator(hass, entry)
                api = coord.api
                initial_logins = api.login_calls
                # Connection failure remains retryable; no reset/login/reauth.
                failures = []
                def unavailable(session, request, **kwargs):
                    if urlsplit(request.url).path.endswith("/overview/energy-flow"):
                        failures.append(request.url)
                        raise requests.Timeout("MOCK_RUNTIME offline transport timeout")
                    return original_send(session, request, **kwargs)
                with patch.object(OfflineSession, "send", unavailable):
                    await coord.async_refresh()
                require(isinstance(coord.last_exception, UpdateFailed) and not isinstance(coord.last_exception, ConfigEntryAuthFailed), "Transient connection failure triggered reauth")
                require(len(failures) == 2 and api.login_calls == initial_logins, "Connection failure caused retry/login flood")
                require(not hass.config_entries.flow.async_progress(), "Transient failure started reauth")
                await coord.async_refresh()
                require(coord.last_update_success, "Transient failure did not recover")
                # Login itself rejecting credentials must also retain auth class.
                with patch.object(api, "get_devices", side_effect=APIAuthError("MOCK_RUNTIME expired")), patch.object(api, "login", side_effect=APIAuthError("MOCK_RUNTIME rejected")):
                    try:
                        await coord.async_update_data()
                    except ConfigEntryAuthFailed:
                        pass
                    else:
                        raise AssertionError("Rejected retry login did not require reauth")
                require(all(not api.unexpected_requests for api in instances), "Unmatched offline request")
                report.update(status="passed", required_401_fetches=2, automatic_relogin_per_refresh=1,
                              ha_reauth_flows=1, transient_timeout_fetches=2,
                              transient_relogins=0, authentication="synthetic; no Huawei login/CAPTCHA verification")


async def wait_for_thread(event, name):
    require(await asyncio.to_thread(event.wait, 5), f"Timed out awaiting {name}")


async def check_concurrency(report):
    from homeassistant.auth import auth_manager_from_config
    from homeassistant.core import Context
    from homeassistant.exceptions import HomeAssistantError, Unauthorized
    from custom_components.fusion_solar_app import coordinator as module
    from custom_components.fusion_solar_app.mock_api import OfflineSession
    import requests
    from urllib.parse import urlsplit

    with tempfile.TemporaryDirectory(prefix="fusionsolar-race-", dir="/tmp") as directory:
        async with home(directory) as hass:
            entry = await mock_entry(hass, "transitions-energy")
            coord = coordinator(hass, entry)
            api = coord.api
            saved = identities(hass, entry)
            hass.auth = await auth_manager_from_config(hass, [], [])
            await hass.auth.async_create_user("MOCK_RUNTIME owner")
            user = await hass.auth.async_create_user("MOCK_RUNTIME nonadmin")
            require(not user.is_admin, "Nonadmin fixture accidentally became administrator")
            try:
                await hass.services.async_call(DOMAIN, "mock_scenario", {
                    "config_entry_id": entry.entry_id, "operation": "advance",
                }, blocking=True, context=Context(user_id=user.id))
            except Unauthorized:
                pass
            else:
                raise AssertionError("Actual HA admin service accepted nonadmin")
            require(api.frame_index == 0 and api._pending_frame is None, "Rejected nonadmin mutated scenario")

            async def control(operation):
                await hass.services.async_call(DOMAIN, "mock_scenario", {
                    "config_entry_id": entry.entry_id, "operation": operation,
                }, blocking=True)
            # Simultaneous direct refresh, debounced refresh, and ordered service
            # transitions all use real HA service/DUC locks and executor jobs.
            for _ in range(3):
                await asyncio.wait_for(asyncio.gather(
                    coord.async_refresh(), coord.async_request_refresh(), control("advance"), control("reset"),
                ), 60)
            await hass.async_block_till_done()
            require(identities(hass, entry) == saved, "Concurrent transitions changed registry identity")
            require(not api.unexpected_requests, "Concurrent transitions used undeclared HTTP")

            # Hold the actual coordinator's one-second connection retry gap.
            # The session RLock alone cannot protect this async gap from unload.
            paused, release, shutdown_started = threading.Event(), threading.Event(), asyncio.Event()
            original_send = OfflineSession.send
            injected = []
            def first_timeout(session, request, **kwargs):
                if not injected and urlsplit(request.url).path.endswith("/overview/energy-flow"):
                    injected.append(request.url)
                    raise requests.Timeout("MOCK_RUNTIME one-shot timeout")
                return original_send(session, request, **kwargs)
            def pause_retry(seconds):
                paused.set()
                require(release.wait(10), "Retry barrier was not released")
            old_shutdown = coord.async_shutdown
            async def observed_shutdown():
                shutdown_started.set()
                await old_shutdown()
            refresh = unload = None
            try:
                with patch.object(OfflineSession, "send", first_timeout), patch.object(module, "time", SimpleNamespace(monotonic=time.monotonic, sleep=pause_retry)), patch.object(coord, "async_shutdown", observed_shutdown):
                    refresh = asyncio.create_task(coord.async_refresh())
                    await wait_for_thread(paused, "retry pause")
                    unload = asyncio.create_task(hass.config_entries.async_unload(entry.entry_id))
                    await asyncio.wait_for(shutdown_started.wait(), 5)
                    # Let shutdown and its executor close proceed if incorrectly
                    # unprotected. Event-driven executor round trips, not a sleep.
                    for _ in range(5):
                        await hass.async_add_executor_job(lambda: None)
                    report["closed_during_retry_gap"] = api._closed
                    require(not api._closed and not unload.done(), "Unload closed API while a refresh retry was still in flight")
                    # The service still exists until the last runtime is removed,
                    # but an unloading entry must no longer accept transitions.
                    try:
                        await asyncio.wait_for(control("reset"), 5)
                    except HomeAssistantError:
                        report["transition_during_unload"] = "rejected"
                    else:
                        report["transition_during_unload"] = "accepted_without_poll"
                        raise AssertionError("Unloading mock entry accepted a transition without applying it")
                    release.set()
                    require(await asyncio.wait_for(unload, 10), "Concurrent unload failed")
                    await asyncio.wait_for(refresh, 10)
            finally:
                release.set()
                if refresh is not None:
                    await asyncio.wait_for(asyncio.gather(refresh, return_exceptions=True), 15)
                if unload is not None:
                    await asyncio.wait_for(asyncio.gather(unload, return_exceptions=True), 15)
            await hass.async_block_till_done()
            require(api._closed and not api.connected, "Concurrent unload leaked session")
            require(entry.entry_id not in hass.data.get(DOMAIN, {}), "Concurrent unload leaked runtime")
            require(not hass.services.has_service(DOMAIN, "mock_scenario"), "Final unload leaked scenario service")
            calls = len(api.session.calls)
            await coord.async_refresh()
            require(len(api.session.calls) == calls, "Shutdown coordinator performed new API I/O")
            require(await hass.config_entries.async_setup(entry.entry_id), "Fresh setup after race failed")
            await hass.async_block_till_done()
            require(identities(hass, entry) == saved, "Race/setup changed identities")
            report.update(status="passed", parallel_batches=3, nonadmin="Unauthorized before mutation",
                          retry_gap_unload="waited for active refresh", api_closed=True,
                          ids_retained=True, no_deadlocks=True)


async def check_same_station(report):
    from homeassistant.helpers import device_registry as dr, entity_registry as er
    from custom_components.fusion_solar_app.mock_profile import load_profile
    async with offline_account_boundary(load_profile(DUAL)):
        with tempfile.TemporaryDirectory(prefix="fusionsolar-collision-", dir="/tmp") as directory:
            async with home(directory) as hass:
                first = await account_entry(hass, "MOCK_RUNTIME_ACCOUNT_A")
                initial = identities(hass, first)
                second = await account_entry(hass, "MOCK_RUNTIME_ACCOUNT_B")
                first_after = identities(hass, first)
                second_after = identities(hass, second)
                api_a, api_b = coordinator(hass, first).api, coordinator(hass, second).api
                discovered_a = {f"{DOMAIN}-{d.device_unique_id}" for d in coordinator(hass, first).data.devices}
                discovered_b = {f"{DOMAIN}-{d.device_unique_id}" for d in coordinator(hass, second).data.devices}
                overlap = discovered_a & discovered_b
                require(overlap, "Same-station identity collision unexpectedly absent; revisit this characterization")
                registry = er.async_get(hass)
                owners = {uid: registry.async_get(registry.async_get_entity_id("sensor", DOMAIN, uid)).config_entry_id
                          for uid in overlap if registry.async_get_entity_id("sensor", DOMAIN, uid)}
                devices_a = dr.async_entries_for_config_entry(dr.async_get(hass), first.entry_id)
                devices_b = dr.async_entries_for_config_entry(dr.async_get(hass), second.entry_id)
                require(devices_a and devices_b and {d.id for d in devices_a}.isdisjoint(d.id for d in devices_b), "HA device-per-entry behavior changed")
                report.update(status="characterized_bug_decision_needed", admitted_entries=2,
                              first_entry=first.entry_id, second_entry=second.entry_id,
                              overlapping_discovered_unique_ids=len(overlap), first_initial_entities=len(initial),
                              first_entities_after=len(first_after), second_entities_after=len(second_after),
                              registered_owner_counts={owner: list(owners.values()).count(owner) for owner in set(owners.values())},
                              distinct_device_counts=[len(devices_a), len(devices_b)],
                              decision="No ID rewrite/admission policy added. Decide same-station account policy and migration separately.")
                require(not api_a.unexpected_requests and not api_b.unexpected_requests, "Collision characterization used undeclared HTTP")


async def main():
    from homeassistant.const import __version__
    require(__version__ == "2026.10.4" and "pytest" not in sys.modules, "Requires standalone actual HA 2026.10.4")
    parser = argparse.ArgumentParser(description=__doc__)
    checks = {"registry": check_registry, "ambiguous": lambda row: check_registry(row, True),
              "ambiguous-device": lambda row: check_registry(row, "conflicting-device"),
              "options": check_options, "authentication": check_authentication,
              "concurrency": check_concurrency, "same-station": check_same_station}
    parser.add_argument("--case", choices=checks, action="append")
    args = parser.parse_args()
    os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(ROOT / "tests/fixtures/runtime_profiles")
    report = {"status": "running", "homeassistant": __version__, "checks": {}, "network_attempts": []}
    def denied(*args, **kwargs):
        report["network_attempts"].append(repr(args))
        raise AssertionError("Lifecycle checker forbids network access")
    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex
    def connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            return denied(address)
        return original_connect(sock, address)
    def connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            return denied(address)
        return original_connect_ex(sock, address)
    try:
        with ExitStack() as guards:
            guards.enter_context(patch.object(socket.socket, "connect", connect))
            guards.enter_context(patch.object(socket.socket, "connect_ex", connect_ex))
            guards.enter_context(patch("socket.create_connection", denied))
            guards.enter_context(patch("socket.getaddrinfo", denied))
            guards.enter_context(patch("requests.sessions.Session.send", denied))
            for name in args.case or checks:
                row = report["checks"][name] = {"status": "running"}
                try:
                    await asyncio.wait_for(checks[name](row), 300)
                except Exception as err:
                    row.update(status="failed", error=f"{type(err).__name__}: {err}")
                    raise
            require(not report["network_attempts"], "Network attempt swallowed by an optional reader")
        report["status"] = "passed_with_known_collision" if "same-station" in report["checks"] else "passed"
    except Exception as err:
        report.update(status="failed", error=f"{type(err).__name__}: {err}")
        raise
    finally:
        print(json.dumps(report, indent=2, default=lambda obj: sorted(obj) if isinstance(obj, (set, frozenset)) else str(obj)), flush=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(main())
