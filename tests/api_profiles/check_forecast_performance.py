#!/usr/bin/env python3
"""Offline actual-HA forecast cost/equivalence and polling-policy checker.

Requires --baseline pointing to b17's unmodified forecast/native.py. See
``docs/performance-validation.md`` for the network-disabled container command.
All history and API inputs are explicitly synthetic. The Recorder query seam
models bounds and include_start_time_state; this is NOT a database benchmark.
No live HA, authentication, HTTP server, database, or configuration is accessed.
"""
from __future__ import annotations

import argparse
import asyncio
from bisect import bisect_left, bisect_right
from collections import Counter
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
from time import perf_counter
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 6, 12, 2, 30, tzinfo=timezone.utc)
DAY = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
ENTITY = "sensor.synthetic_panel_production_today"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class MemoryStore:
    """Storage seam: assert all persistence remains on-loop, never on a worker."""

    def __init__(self, loop_thread, initial=None):
        self.loop_thread = loop_thread
        self.initial = deepcopy(initial)
        self.loads = 0
        self.saved = []

    async def async_load(self):
        require(threading.get_ident() == self.loop_thread, "off-loop Store load")
        self.loads += 1
        return deepcopy(self.initial)

    async def async_save(self, value):
        require(threading.get_ident() == self.loop_thread, "off-loop Store save")
        self.saved.append(deepcopy(value))


class SyntheticHistory:
    """Sorted fictional Recorder samples, with Recorder-like start-state bounds."""

    def __init__(self, samples):
        self.samples = samples
        self.times = [sample.last_changed for sample in samples]
        self.calls = []

    def query(self, hass, start, end, entities, **kwargs):
        require(kwargs == {"include_start_time_state": True,
                           "significant_changes_only": False}, "query flags changed")
        lo = bisect_left(self.times, start)
        # Recorder includes the prior state when no state is exactly at start.
        if lo and (lo == len(self.times) or self.times[lo] != start):
            lo -= 1
        hi = bisect_right(self.times, end)
        rows = self.samples[lo:hi]
        self.calls.append({"start": start.isoformat(), "end": end.isoformat(),
                           "rows": len(rows), "entity": entities[0],
                           "thread": threading.get_ident()})
        return {entities[0]: rows}


def dense_samples():
    """Five-second synthetic readings, including unknowns and daily resets."""
    start = DAY - timedelta(days=8)
    result = []
    for offset in range(0, 9 * 86400 + 1, 5):
        when = start + timedelta(seconds=offset)
        daylight = max(0.0, min(1.0, (when.hour + when.minute / 60 + when.second / 3600 - 6) / 12))
        value = daylight ** 2 * (20 + (when.date().toordinal() % 7))
        state = "unknown" if offset % 25015 == 0 else str(value)
        result.append(SimpleNamespace(state=state, last_changed=when))
    return result


class Case:
    def __init__(self, module, hass, samples, initial_cache=None, step=5, days=7):
        self.module, self.hass = module, hass
        self.loop_thread = threading.get_ident()
        self.history = SyntheticHistory(samples)
        self.store = MemoryStore(self.loop_thread, initial_cache)
        self.cpu = []
        self.now = NOW
        self.entity = ENTITY
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(module, "Store", lambda *a: self.store))
        self.stack.enter_context(patch.object(module.dt_util, "now", lambda: self.now))
        self.stack.enter_context(patch.object(module, "get_instance", lambda h: SimpleNamespace(
            async_add_executor_job=h.async_add_executor_job)))
        self.stack.enter_context(patch.object(module, "get_significant_states", self.history.query))
        self.builder = module.NativeForecastBuilder(hass, "synthetic-performance", step, days)
        original_resolve = self.builder._resolve_sensor_entity_id

        def resolve(device):
            require(threading.get_ident() == self.loop_thread, "registry resolved off-loop")
            require(original_resolve(device) == ENTITY, "actual entity registry resolution failed")
            return self.entity

        self.builder._resolve_sensor_entity_id = resolve
        for name in ("_build_history_index", "_build_forecast_delta_cache"):
            original = getattr(self.builder, name)

            def observed(*args, original=original, name=name):
                start = perf_counter()
                try:
                    return original(*args)
                finally:
                    self.cpu.append({"method": name, "samples": len(args[0]),
                                     "on_loop": threading.get_ident() == self.loop_thread,
                                     "seconds": perf_counter() - start})

            setattr(self.builder, name, observed)

    async def build(self, value="12"):
        from custom_components.fusion_solar_app.api import Device, DeviceType
        device = Device("Panel Production Today", "synthetic-performance-source",
                        DeviceType.SENSOR_KWH, "Fictional", value, "mdi:solar-power")
        return await self.builder.build([device])

    def close(self):
        self.stack.close()


async def measurements(module, hass, samples):
    case = Case(module, hass, samples)
    try:
        outputs, elapsed = [], []
        for index in range(5):
            case.now = NOW + timedelta(minutes=index)
            start = perf_counter()
            outputs.append(asdict(await case.build(str(12 + index / 4))))
            elapsed.append(perf_counter() - start)
        return {"outputs": outputs, "cache": deepcopy(case.builder._forecast_cache),
                "query_calls": case.history.calls, "cpu": case.cpu,
                "store_loads": case.store.loads, "store_saves": len(case.store.saved),
                "elapsed_seconds": elapsed, "loop_thread": case.loop_thread}
    finally:
        case.close()


async def equivalence_cases(candidate, baseline, hass, samples, cache):
    """Every comparison calls the real old/new build, not an AST replica."""
    cases = []

    async def compare(name, history, initial=None, setup=None):
        results = []
        costs = []
        for module in (baseline, candidate):
            case = Case(module, hass, history, initial)
            try:
                if setup:
                    setup(case)
                results.append(asdict(await case.build()))
                costs.append(len(case.history.calls))
            finally:
                case.close()
        require(results[0] == results[1], f"prediction/curve/debug changed: {name}")
        cases.append({"name": name, "sha256": digest(results[1]), "queries_old_new": costs})

    await compare("persisted_cache_hit", samples, cache)
    await compare("small_history_inline", samples[::180])
    await compare("empty_history", [], cache)
    await compare("sparse_old_numeric_only", [SimpleNamespace(
        state="3", last_changed=DAY - timedelta(days=2))], cache)
    await compare("non_numeric_recent_only", [SimpleNamespace(
        state="unavailable", last_changed=NOW)], cache)
    await compare("sparse_history_falls_back_to_full_query", [
        SimpleNamespace(state="3", last_changed=DAY - timedelta(days=2)),
        SimpleNamespace(state="unavailable", last_changed=DAY - timedelta(hours=7)),
        SimpleNamespace(state="unknown", last_changed=NOW),
    ], cache)
    await compare("empty_history_no_actual", [], None,
                  lambda c: setattr(c, "build", lambda value="invalid": Case.build(c, "invalid")))
    await compare("no_actual_with_history", samples, cache,
                  lambda c: setattr(c, "build", lambda value="invalid": Case.build(c, "invalid")))
    await compare("source_change", samples, cache, lambda c: setattr(c, "entity", "sensor.other"))
    await compare("midnight", samples, cache,
                  lambda c: setattr(c, "now", DAY + timedelta(days=1, minutes=5)))
    await compare("step_change", samples, cache, lambda c: setattr(c.builder, "step_minutes", 10))
    await compare("history_basis_days_change", samples, cache, lambda c: setattr(c.builder, "days", 3))
    obsolete = deepcopy(cache)
    obsolete["algorithm_version"] = -1
    await compare("algorithm_change", samples, obsolete)
    malformed = deepcopy(cache)
    malformed["delta_curve"] = []
    await compare("incomplete_profile", samples, malformed)
    with patch.object(candidate, "FORECAST_DEBUG_ENABLED", True), patch.object(baseline, "FORECAST_DEBUG_ENABLED", True):
        await compare("debug_full_history", samples, cache)

    # A provider pause must NOT cache an adaptive current-now result. The native
    # builder is idle while Solcast is selected; on return it queries fresh actuals.
    sequences = []
    for module in (baseline, candidate):
        case = Case(module, hass, samples, cache)
        try:
            before = asdict(await case.build("12"))
            unchanged_profile = deepcopy(case.builder._forecast_cache)
            case.now = NOW + timedelta(hours=2)
            after = asdict(await case.build("16"))
            require(after["actual_now_value"] == 16, "fresh production not used after provider pause")
            require(before != after, "whole adaptive forecast incorrectly cached")
            require(case.builder._forecast_cache == unchanged_profile, "daily smoothing/profile changed")
            require(len(case.history.calls) == 2, "fresh history must be read on both polls")
            sequences.append([before, after])
        finally:
            case.close()
    require(sequences[0] == sequences[1], "provider return changed native prediction/smoothing")
    cases.append({"name": "fresh_measurements_and_provider_pause", "sha256": digest(sequences[1])})
    return cases


async def missing_recorder(candidate, hass):
    """Absent/not-yet-set-up is unavailable; corruption/outage still raises."""
    from homeassistant.components.recorder import DATA_INSTANCE
    from homeassistant.components.recorder import get_instance

    store = MemoryStore(threading.get_ident())
    get_instance.cache_clear()
    with patch.object(candidate, "Store", lambda *a: store):
        builder = candidate.NativeForecastBuilder(hass, "missing-recorder")
    builder._resolve_sensor_entity_id = lambda device: ENTITY
    from custom_components.fusion_solar_app.api import Device, DeviceType
    source = Device("Panel Production Today", "synthetic", DeviceType.SENSOR_KWH,
                    "Fictional", "12", "mdi:solar-power")
    require(DATA_INSTANCE not in hass.data, "unexpected real Recorder instance")
    warnings = []

    class Capture(logging.Handler):
        def emit(self, record):
            if record.levelno >= logging.WARNING:
                warnings.append(record.getMessage())

    logger = logging.getLogger(candidate.__name__)
    capture = Capture()
    logger.addHandler(capture)
    try:
        for _ in range(3):
            result = await builder.build([source])
            require(result.forecasted_today is None and result.remaining_today is None
                    and result.curve == [], "missing Recorder fabricated a forecast")
        require(not warnings, "absent Recorder generated repeated warnings")
    finally:
        logger.removeHandler(capture)
    hass.config.components.add("recorder")
    try:
        try:
            await builder.build([source])
        except KeyError:
            pass
        else:
            raise AssertionError("unexpected missing configured Recorder was masked")
    finally:
        hass.config.components.remove("recorder")
        get_instance.cache_clear()
    for failure in (RuntimeError("synthetic Recorder outage"), KeyError("unrelated")):
        with patch.object(candidate, "get_instance", side_effect=failure):
            try:
                await builder.build([source])
            except type(failure):
                pass
            else:
                raise AssertionError("unexpected Recorder exception was masked")
    # A present but broken/incomplete instance is not treated as a clean absence.
    with patch.object(candidate, "get_instance", return_value=object()):
        try:
            await builder.build([source])
        except AttributeError:
            pass
        else:
            raise AssertionError("broken Recorder instance was masked")
    case = Case(candidate, hass, [])
    try:
        with patch.object(candidate, "get_significant_states", side_effect=RuntimeError("query outage")):
            try:
                await case.build()
            except RuntimeError:
                pass
            else:
                raise AssertionError("Recorder query failure was masked")
    finally:
        case.close()
    return {"absent_polls": 3, "warnings": len(warnings), "forecast": None,
            "unexpected_failures_propagated": 5}


async def cancellation(candidate, hass, samples, target):
    """Real HA executor keeps running, but cancelled build cannot publish/save."""
    case = Case(candidate, hass, samples)
    entered, release = threading.Event(), threading.Event()
    finished = asyncio.Event()
    original = getattr(case.builder, target)
    loop = asyncio.get_running_loop()

    def paused(*args):
        entered.set()
        require(release.wait(timeout=30), "cancellation checker did not release worker")
        try:
            return original(*args)
        finally:
            loop.call_soon_threadsafe(finished.set)

    setattr(case.builder, target, paused)
    task = asyncio.create_task(case.build())
    try:
        deadline = loop.time() + 30
        while not entered.is_set():
            require(loop.time() < deadline and not task.done(), "executor was not entered")
            await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("build cancellation did not propagate")
        release.set()
        await asyncio.wait_for(finished.wait(), 30)
        require(case.builder._forecast_cache is None and not case.store.saved,
                "cancelled worker published/persisted a late cache")
        return {"stage": target, "cancelled": True, "worker_finished": True, "late_cache_writes": 0}
    finally:
        release.set()
        if not task.done():
            task.cancel()
        case.close()


async def polling_policy(hass, clock):
    """Real API readers, fictional offline HTTP, virtual (not removed) sleeps."""
    from custom_components.fusion_solar_app.api import energy_balance, social
    from custom_components.fusion_solar_app.mock_api import MockFusionSolarAPI
    from custom_components.fusion_solar_app.mock_profile import load_profile

    os.environ["FUSIONSOLAR_DEV_PROFILE_DIR"] = str(ROOT / "tests/fixtures/runtime_profiles")
    api = MockFusionSolarAPI(load_profile("single-battery-config-denied"))
    trace, per_poll, sleeps = [], [], []
    original_request = api.session.request

    def request(method, url, **kwargs):
        from urllib.parse import parse_qsl, urlsplit
        parsed = urlsplit(url)
        require(parsed.netloc == "example.invalid", "nonfictional origin")
        params = parse_qsl(parsed.query) + list((kwargs.get("params") or {}).items())
        # Ignore only the existing portal cache-buster, just like strict replay.
        stable_params = sorted((key, str(value)) for key, value in params if key != "_")
        trace.append([method, parsed.path, stable_params, kwargs.get("json"), kwargs.get("data")])
        return original_request(method, url, **kwargs)

    def sleep(seconds):
        sleeps.append(seconds)
        trace.append(["sleep", seconds])

    class SocialClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock.astimezone(tz) if tz is not None else clock

    api.session.request = request
    try:
        with patch.object(energy_balance.time, "sleep", sleep), patch.object(social, "datetime", SocialClock):
            for _ in range(2):
                start, sleep_start = len(trace), len(sleeps)
                devices = await hass.async_add_executor_job(api.get_devices)
                require(devices, "offline API returned no devices")
                per_poll.append({"calls": len(trace) - start - len(sleeps) + sleep_start,
                                 "daily_spacing_seconds": sleeps[sleep_start:],
                                 "devices": len(devices)})
        require(not api.unexpected_requests, "unexpected fictional request was swallowed")
        require(all(item["daily_spacing_seconds"] and
                    all(seconds == 1 for seconds in item["daily_spacing_seconds"])
                    for item in per_poll), "established daily spacing changed")
        paths = Counter(item[1] for item in trace if item[0] != "sleep")
        return {"origin": "synthetic", "polls": per_poll,
                "paths": dict(paths), "trace_sha256": digest(trace), "trace": trace,
                "daily_spacing_calls": len(sleeps), "network_requests": 0,
                "note": "API/coordinator/energy code unchanged; virtualized waits are test-only"}
    finally:
        api.close()


async def run(args):
    from homeassistant import loader
    from homeassistant.bootstrap import async_load_base_functionality
    from homeassistant.config_entries import ConfigEntries
    from homeassistant.const import __version__ as ha_version
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import entity_registry as er
    from custom_components.fusion_solar_app.forecast import native
    from custom_components.fusion_solar_app.const import DOMAIN

    require(ha_version == "2026.10.4", f"expected actual HA 2026.10.4, got {ha_version}")
    spec = importlib.util.spec_from_file_location(
        "custom_components.fusion_solar_app.forecast._performance_baseline", args.baseline)
    baseline = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = baseline
    spec.loader.exec_module(baseline)
    samples = dense_samples()
    with tempfile.TemporaryDirectory(prefix="forecast-performance-", dir="/tmp") as config:
        hass = HomeAssistant(config)
        hass.config.time_zone = "UTC"
        hass.config.skip_pip = True
        loader.async_setup(hass)
        hass.config_entries = ConfigEntries(hass, {})
        require(await async_load_base_functionality(hass), "HA base setup failed")
        registry = er.async_get(hass)
        source = registry.async_get_or_create(
            "sensor", DOMAIN, f"{DOMAIN}-synthetic-performance-source",
            suggested_object_id="synthetic_panel_production_today")
        require(source.entity_id == ENTITY, "unexpected synthetic registry ID")
        try:
            polling_clock = datetime.now()
            polling_before = await polling_policy(hass, polling_clock)
            before = await measurements(baseline, hass, samples)
            after = await measurements(native, hass, samples)
            require(before["outputs"] == after["outputs"], "golden full-output mismatch")
            require(before["cache"] == after["cache"], "persisted delta/smoothing changed")
            require(len(before["query_calls"]) == len(after["query_calls"]) == 5,
                    "dense cache hits must still refresh actual history once per poll")
            require(after["store_loads"] == after["store_saves"] == 1, "cache persistence changed")
            require(all(not item["on_loop"] for item in after["cpu"]), "material CPU stayed on-loop")
            require(all(item["on_loop"] for item in before["cpu"]), "baseline CPU instrumentation failed")
            require(all(call["thread"] != after["loop_thread"] for call in after["query_calls"]),
                    "Recorder query ran on-loop")
            cases = await equivalence_cases(native, baseline, hass, samples, before["cache"])
            missing = await missing_recorder(native, hass)
            cancelled = [await cancellation(native, hass, samples, target) for target in (
                "_build_history_index", "_build_forecast_delta_cache")]
            polling = await polling_policy(hass, polling_clock)
            require(polling_before == polling, "offline request order/count/pacing changed around forecasts: " +
                    json.dumps({key: [polling_before[key], polling[key]] for key in polling
                                if polling_before[key] != polling[key]}))
            polling["identical_before_after_forecasts"] = True
            for label, result in (("before", before), ("after", after)):
                result["output_sha256"] = digest(result.pop("outputs"))
                result["cache_sha256"] = digest(result.pop("cache"))
                result["rows_total"] = sum(c["rows"] for c in result["query_calls"])
                result["on_loop_cpu_samples"] = sum(c["samples"] for c in result["cpu"] if c["on_loop"])
            return {"status": "passed", "homeassistant": ha_version,
                    "inputs": "synthetic five-second cumulative history; no live Recorder/database",
                    "baseline_file_sha256": hashlib.sha256(Path(args.baseline).read_bytes()).hexdigest(),
                    "before": before, "after": after, "equivalence_cases": cases,
                    "missing_recorder": missing, "cancellation": cancelled, "polling": polling}
        finally:
            await hass.async_stop(force=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    args = parser.parse_args()
    attempts = []
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def deny(*args, **kwargs):
        attempts.append("network attempt")
        raise AssertionError("network forbidden by forecast checker")

    def connect(sock, address):
        return deny() if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect(sock, address)

    def connect_ex(sock, address):
        return deny() if sock.family in (socket.AF_INET, socket.AF_INET6) else original_connect_ex(sock, address)

    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    with patch.object(socket.socket, "connect", connect), patch.object(socket.socket, "connect_ex", connect_ex), \
            patch("socket.create_connection", deny), patch("socket.getaddrinfo", deny), \
            patch("requests.sessions.Session.send", deny):
        result = asyncio.run(run(args))
    require(not attempts, "network attempt was swallowed")
    result["network_attempts"] = len(attempts)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
