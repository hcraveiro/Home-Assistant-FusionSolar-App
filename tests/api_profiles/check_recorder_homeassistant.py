#!/usr/bin/env python3
"""Characterize the unchanged energy policy with actual HA Recorder (no pytest).

Run in the network-disabled, read-only HA 2026.10.4 image; see
``docs/recorder-validation.md``. The temporary profile supplies fictional HTTP
responses to production readers/coordinator/platforms. Only wall-clock sources
are controlled; states, Recorder history, compilation and sums are not replaced.
A passing checker describes HA's behavior, NOT the correctness of an arbitrary
Huawei historical correction or a decision to change sensor classifications.
"""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

from check_runtime_homeassistant import DOMAIN, ROOT, require

UTC = timezone.utc
PERIODS = ("today", "week", "month", "year", "lifetime")
# Explicit expected observations, not a replacement implementation of Recorder.
# At Thursday's four-day week the panel week reading is 4 * the HTTP day value.
# The >10% dip is deliberately separate from the absolute 1 kWh correction.
FRAMES = (
    ("baseline", 30, 30, 0, 0),
    ("monotonic", 35, 35, 5, 5),
    ("correction-1-kwh", 34, 34, 4, 4),
    ("correction-001-kwh", 33.99, 33.99, 3.99, 3.99),
    ("correction-recovery", 35, 35, 5, 5),
    ("invalid-null", None, None, 5, 5),
    ("invalid-garbage", "garbage", "garbage", 5, 5),
    ("invalid-spaced-marker", " -- ", " -- ", 5, 5),
    ("literal-marker", "--", "--", 5, 5),
    ("marker-recovery", 35, 35, 5, 5),
    ("measured-zero", 0, 0, 5, 5),
    ("zero-recovery", 2, 2, 7, 7),
    ("second-monotonic", 35, 35, 40, 40),
    ("relative-drop-over-10pct", 30, 30, 70, 70),
    ("relative-drop-recovery", 35, 35, 75, 75),
)


def recorder_profile(load_profile):
    """Derive temporary HTTP frames; do not inject Device objects or HA states."""
    profile = load_profile("transitions-energy")
    profile.update(id="synthetic-recorder-disposable", title="MOCK disposable Recorder transitions", frames=[])
    december = next(route for route in profile["routes"] if route["path"].endswith("energy-balance") and route["params"]["timeDim"] == "4")
    january = deepcopy(december)
    december["params"]["dateStr"] = "2026-12-01 00:00:00"
    january["params"]["dateStr"] = "2027-01-01 00:00:00"
    profile["routes"].append(january)
    calendar_frames = (("calendar-jan1-reset", 0, 35), ("calendar-new-energy", 2, 37))
    for frame_index, (name, periodic, lifetime, *_) in enumerate((*FRAMES, *calendar_frames)):
        responses = []
        for index, route in enumerate(profile["routes"]):
            if not route["path"].endswith("energy-balance"):
                continue
            body = deepcopy(route["body"])
            raw = lifetime if route["params"]["timeDim"] == "6" else periodic
            if route is december and frame_index >= len(FRAMES):
                raw = 35  # Keep the elapsed December days, including yesterday.
            # Each production field keeps its original scalar/vector structure.
            for key, value in body["data"].items():
                if isinstance(value, list):
                    body["data"][key] = [raw] + [0] * 30 if route is january else [raw] * 31
                else:
                    body["data"][key] = raw
            responses.append({"route": index, "body": body})
        profile["frames"].append({"id": name, "responses": responses})
    return profile


class Clock:
    """Wall time only; asyncio/Recorder threading/monotonic time stay real."""

    def __init__(self, now):
        self.now = now

    def timestamp(self):
        return self.now.timestamp()

    def utcnow(self):
        return self.now

    def localnow(self, time_zone=None):
        return self.now.astimezone(time_zone or UTC)

    def datetime_class(self):
        clock = self

        class ControlledDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock.now.astimezone(tz) if tz else clock.now.replace(tzinfo=None)

        return ControlledDatetime


def close(actual, expected, message):
    require(math.isclose(actual, expected, rel_tol=0, abs_tol=1e-8), f"{message}: expected {expected}, got {actual}")


async def recording_barrier(recorder):
    """An unconditional Recorder FIFO/commit barrier, including in-flight tasks.

    async_block_till_done() may return early when a StatisticsTask has already
    been removed from the queue but has not completed. Always enqueue the real
    SynchronizeTask, as the HA test harness does, before inspecting results.
    """
    from homeassistant.components.recorder.tasks import SynchronizeTask

    future = recorder.hass.loop.create_future()
    recorder.queue_task(SynchronizeTask(future))
    await future


async def run(report):
    from homeassistant import loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.components.recorder import get_instance, history, statistics
    from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
    from homeassistant.components.recorder.tasks import StatisticsTask
    from homeassistant.config_entries import ConfigEntries, ConfigEntryState
    from homeassistant.const import __version__ as ha_version
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import device_registry as dr, entity as entity_helper, entity_registry as er
    from homeassistant.helpers.recorder import async_initialize_recorder
    from homeassistant.setup import async_setup_component
    from homeassistant.util import dt as dt_util
    from custom_components.fusion_solar_app.api import FusionSolarAPI
    from custom_components.fusion_solar_app.mock_profile import load_profile

    require(ha_version == "2026.10.4", f"Expected actual HA 2026.10.4, got {ha_version}")
    require("pytest" not in sys.modules, "Run standalone without test HA stubs")
    report["homeassistant"] = ha_version
    os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(ROOT / "tests/fixtures/runtime_profiles")
    profile = recorder_profile(load_profile)
    attempts, discovery_calls = [], []
    report["network_attempts"] = attempts
    start = datetime(2026, 12, 31, 22, tzinfo=UTC)
    clock = Clock(start)

    def deny(*args, **kwargs):
        attempts.append(repr(args))
        raise AssertionError("Network forbidden by disposable Recorder checker")

    original_connect, original_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def connect(sock, address):
        return deny(address) if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect(sock, address)

    def connect_ex(sock, address):
        return deny(address) if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect_ex(sock, address)

    original_get_devices = FusionSolarAPI.get_devices

    def observed_get_devices(api, *args, **kwargs):
        discovery_calls.append(api)
        return original_get_devices(api, *args, **kwargs)

    with tempfile.TemporaryDirectory(prefix="fusionsolar-recorder-", dir="/tmp") as tmp:
        root = Path(tmp)
        (root / "profiles").mkdir()
        (root / "profiles" / f"{profile['id']}.json").write_text(json.dumps(profile))
        os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(root / "profiles")
        (root / "custom_components").symlink_to(ROOT / "custom_components", target_is_directory=True)
        with ExitStack() as guards:
            guards.enter_context(patch.object(socket.socket, "connect", connect))
            guards.enter_context(patch.object(socket.socket, "connect_ex", connect_ex))
            guards.enter_context(patch("socket.create_connection", deny))
            guards.enter_context(patch("socket.getaddrinfo", deny))
            guards.enter_context(patch("requests.sessions.Session.send", deny))
            guards.enter_context(patch("time.time", clock.timestamp))
            guards.enter_context(patch.object(entity_helper, "timer", clock.timestamp))
            guards.enter_context(patch.object(statistics, "time_time", clock.timestamp))
            guards.enter_context(patch.object(dt_util, "utcnow", clock.utcnow))
            guards.enter_context(patch.object(dt_util, "now", clock.localnow))
            for module in ("api.energy_balance", "api.social", "api.auth", "mock_api"):
                guards.enter_context(patch(f"custom_components.{DOMAIN}.{module}.datetime", clock.datetime_class()))
            guards.enter_context(patch.object(FusionSolarAPI, "get_devices", observed_get_devices))
            hass = HomeAssistant(tmp)
            hass.config.skip_pip = True
            hass.config.time_zone = "UTC"
            hass.config.latitude = hass.config.longitude = 0
            loader.async_setup(hass)
            hass.config_entries = ConfigEntries(hass, {})
            try:
                require(await async_load_base_functionality(hass), "HA base setup failed")
                # Use the same supported initialization helper as HA bootstrap,
                # then normal component setup. No default_config or HTTP server.
                async_initialize_recorder(hass)
                config = {"recorder": {"db_url": f"sqlite:///{tmp}/recorder.sqlite",
                                       "auto_purge": False, "auto_repack": False,
                                       "commit_interval": 0}}
                require(await async_setup_component(hass, "recorder", config), "Recorder setup failed")
                await hass.async_start()
                recorder = get_instance(hass)
                await recording_barrier(recorder)
                result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "mock"})
                result = await hass.config_entries.flow.async_configure(result["flow_id"], {"mock_profile": profile["id"]})
                require(result["type"] == "create_entry", f"Mock flow failed: {result}")
                entry = result["result"]
                await hass.async_block_till_done()
                require(entry.state is ConfigEntryState.LOADED, f"Entry failed: {entry.reason}")
                coordinator = hass.data[DOMAIN][entry.entry_id].coordinator
                api = coordinator.api
                require(entry.data["fusion_solar_host"] == "example.invalid", "Nonfictional host")
                require(entry.data["username"].startswith("mock-"), "Nonfictional username")
                require(profile["station"]["dn"].startswith("MOCK_RUNTIME_"), "Nonfictional station")
                require(not api.session.adapters, "Offline adapter set must be empty")
                entities = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
                devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
                identities = sorted((e.entity_id, e.unique_id, e.device_id) for e in entities)
                targets = {}
                for period in PERIODS:
                    matches = [e for e in entities if e.unique_id.endswith(f"panel_production_{period}")]
                    require(len(matches) == 1, f"Missing/duplicate panel {period}")
                    targets[period] = matches[0].entity_id
                require(devices and all(e.device_id in {d.id for d in devices} for e in entities), "Unregistered device ownership")
                report["runtime"] = {"entities": len(entities), "devices": len(devices), "targets": targets,
                                     "db_location": "temporary /tmp directory; destroyed after run",
                                     "offline_adapters": len(api.session.adapters)}
                report["frames"] = []
                # Queue real compilation tasks after each interval's real entity
                # state events have committed. :55 tasks also compile hourly LTS.
                # Do not dispatch HA clock timers: background polls would introduce
                # extra input samples. All production reader pacing stays intact.
                for index in range(36):
                    interval = start + timedelta(minutes=5 * index)
                    clock.now = interval + timedelta(seconds=30)
                    input_index = index if index < len(FRAMES) else len(FRAMES) + index - 24 if index in (24, 25) else None
                    if input_index is not None and input_index > 0:
                        api.queue_frame("advance")
                        await coordinator.async_refresh()
                    await hass.async_block_till_done()
                    await recording_barrier(recorder)
                    if input_index is not None:
                        if index < len(FRAMES):
                            name, periodic, lifetime, *_ = FRAMES[index]
                        else:
                            name = profile["frames"][input_index]["id"]
                            periodic, lifetime = (0, 35) if index == 24 else (2, 37)
                        require(api.frame_id == name, "Wrong HTTP frame")
                        require(coordinator.last_update_success, "Invalid scalar failed whole poll")
                        current = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
                        require(sorted((e.entity_id, e.unique_id, e.device_id) for e in current) == identities, "Registry identity changed")
                        states = {}
                        for period, entity_id in targets.items():
                            state = hass.states.get(entity_id)
                            require(state is not None, f"Missing HA state: {entity_id}")
                            require(tuple(state.attributes.get(k) for k in ("unit_of_measurement", "device_class", "state_class")) ==
                                    ("kWh", SensorDeviceClass.ENERGY, SensorStateClass.TOTAL_INCREASING), "Energy classification changed")
                            raw = lifetime if period == "lifetime" else periodic
                            if raw is None or isinstance(raw, str):
                                expected = None
                            else:
                                expected = raw * (4 if period == "week" else 1)
                            if index >= 24 and period == "week":
                                expected = 140 if index == 24 else 142
                            if expected is None:
                                require(state.state == "unavailable", f"Invalid value fabricated: {period}: {state.state}")
                            else:
                                close(float(state.state), expected, f"Raw HA {period}/{name}")
                            require(start <= state.last_updated <= clock.now, "Entity timestamp escaped controlled timeline")
                            states[period] = {"state": state.state, "last_updated": state.last_updated.isoformat()}
                        report["frames"].append({"frame": name, "start": interval.isoformat(), "states": states})
                    clock.now = interval + timedelta(minutes=5)
                    recorder.queue_task(StatisticsTask(interval, False))
                    await recording_barrier(recorder)
                require(discovery_calls and all(obj is api for obj in discovery_calls), "Production discovery not exercised")
                require(api.session.calls and not api.unexpected_requests, f"Unmatched HTTP: {api.unexpected_requests}")
                report["runtime"].update(production_get_devices_calls=len(discovery_calls), offline_http_requests=len(api.session.calls))
                require("sensor" in hass.data["recorder"].recorder_platforms, "Real sensor statistics platform missing")
                require("http" not in hass.config.components, "Unexpected HTTP server setup")
                ids = set(targets.values())
                end = start + timedelta(hours=3)
                rows = await recorder.async_add_executor_job(statistics.statistics_during_period, hass, start, end,
                                                            ids, "5minute", None, {"state", "sum", "last_reset"})
                hourly = await recorder.async_add_executor_job(statistics.statistics_during_period, hass, start, end,
                                                              ids, "hour", None, {"state", "sum", "last_reset"})
                raw_history = await recorder.async_add_executor_job(history.get_significant_states, hass, start, end,
                                                                   list(ids), None, True, False)
                report["short_term"] = {period: rows.get(entity_id, []) for period, entity_id in targets.items()}
                report["long_term"] = {period: hourly.get(entity_id, []) for period, entity_id in targets.items()}
                report["history"] = {period: [{"state": s.state, "last_updated": s.last_updated.isoformat()} for s in raw_history.get(entity_id, [])]
                                     for period, entity_id in targets.items()}
                for period, entity_id in targets.items():
                    observed = rows.get(entity_id, [])
                    # After the first unavailable transition interval, a wholly
                    # unavailable interval has no float states, hence no row.
                    missing = {6, 7, 8}
                    by_interval = {round((row["start"] - start.timestamp()) / 300): row for row in observed}
                    require(set(by_interval) == set(range(36)) - missing,
                            f"Unexpected short-term intervals: {period}: {sorted(by_interval)}")
                    factor = 4 if period == "week" else 1
                    previous_sum = 0
                    expected_state = 30 * factor
                    for index, row in sorted(by_interval.items()):
                        frame = FRAMES[min(index, len(FRAMES) - 1)]
                        expected_sum = frame[4 if period == "lifetime" else 3] * factor
                        raw = frame[2 if period == "lifetime" else 1]
                        if isinstance(raw, (int, float)):
                            expected_state = raw * factor
                        if index >= 24:
                            if period == "week":
                                expected_state, expected_sum = (140, 300) if index == 24 else (142, 302)
                            elif period == "lifetime":
                                expected_state, expected_sum = (35, 75) if index == 24 else (37, 77)
                            else:
                                expected_state, expected_sum = (0, 75) if index == 24 else (2, 77)
                        close(row["state"], expected_state, f"Compiled state {period}/{index}")
                        close(row["sum"], expected_sum, f"Compiled sum {period}/{index}")
                        close(row["start"], (start + timedelta(minutes=5 * index)).timestamp(), "Statistics interval timestamp")
                        row["observed_delta_sum"] = row["sum"] - previous_sum
                        previous_sum = row["sum"]
                        require(row["last_reset"] is None, "TOTAL_INCREASING should not publish last_reset")
                    lts = hourly.get(entity_id, [])
                    require(len(lts) == 3, f"Missing hourly long-term rows: {period}: {len(lts)}")
                    expected_hourly = (7, 75, 77) if period == "lifetime" else (28, 300, 302) if period == "week" else (7, 75, 77)
                    for index, expected_sum in enumerate(expected_hourly):
                        close(lts[index]["sum"], expected_sum, f"Hourly sum {period}/{index}")
                        close(lts[index]["state"], by_interval[(index + 1) * 12 - 1]["state"], f"Hourly state {period}/{index}")
                    require(any(s["state"] == "unavailable" for s in report["history"][period]), "No real invalid state history")
                    require(any(s["state"] == "0.0" or s["state"] == "0" for s in report["history"][period]), "No real measured-zero history")
                require(not attempts, f"Attempted network: {attempts}")
                report["network_attempts"] = attempts
                require(await hass.config_entries.async_unload(entry.entry_id), "Unload failed")
            finally:
                for entry in hass.config_entries.async_entries(DOMAIN):
                    if entry.state is ConfigEntryState.LOADED:
                        await hass.config_entries.async_unload(entry.entry_id)
                await hass.async_stop(force=True)
                await hass.async_block_till_done()
            require(not attempts, f"Network attempted during teardown: {attempts}")


async def main():
    report = {"status": "running", "origin": "synthetic fictional HTTP responses, not Huawei hardware evidence",
              "meaning": "Characterization of unchanged total_increasing, not approval of correction/placeholder policy"}
    try:
        await asyncio.wait_for(run(report), timeout=600)
    except Exception as err:
        report.update(status="failed", error=f"{type(err).__name__}: {err}")
        print(json.dumps(report, indent=2, default=str), flush=True)
        raise
    report["status"] = "passed"
    print(json.dumps(report, indent=2, default=str), flush=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    asyncio.run(main())
