"""Native forecast cache, rollover, and historical-sample regression tests.

Uses the real native forecast builder while mocking HA recorder and storage.
"""

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import AsyncMock, Mock
import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusionsolar_native_behavior"


@pytest.fixture(scope="module")
def forecast_module():
    saved = {}
    def register(name, **attrs):
        saved[name] = sys.modules.get(name)
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m
    def package(name, location=None):
        m = register(name)
        m.__path__ = [str(location)] if location else []
        return m
    package("homeassistant")
    package("homeassistant.components")
    package("homeassistant.components.recorder")
    register("homeassistant.components.recorder", get_instance=lambda hass: Mock())
    register("homeassistant.components.recorder.history", get_significant_states=Mock(return_value={}))
    register("homeassistant.core", HomeAssistant=object)
    package("homeassistant.helpers")
    register("homeassistant.helpers.entity_registry", async_get=lambda hass: Mock())
    class Store:
        def __init__(self, *args):
            self.async_load = AsyncMock(return_value=None)
            self.async_save = AsyncMock()
    register("homeassistant.helpers.storage", Store=Store)
    package("homeassistant.util")
    register("homeassistant.util.dt",
             now=lambda: datetime(2026, 10, 25, 12, tzinfo=timezone.utc),
             parse_datetime=lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
             as_local=lambda d: d.replace(tzinfo=timezone.utc))
    package(PREFIX, ROOT)
    package(f"{PREFIX}.forecast", ROOT / "forecast")
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.const", ROOT / "const.py")
    m = importlib.util.module_from_spec(spec)
    saved[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    from enum import StrEnum
    class DeviceType(StrEnum):
        SENSOR_KWH = "sensor_kwh"
        SENSOR_KW = "sensor"
    class Device:
        def __init__(self, device_id, device_type, state, unique="unique"):
            self.device_id, self.device_type = device_id, device_type
            self.state, self.device_unique_id = state, unique
    register(f"{PREFIX}.api", Device=Device, DeviceType=DeviceType)
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.forecast.models", ROOT / "forecast/models.py")
    m = importlib.util.module_from_spec(spec)
    saved[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.forecast.native", ROOT / "forecast/native.py")
    m = importlib.util.module_from_spec(spec)
    saved[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    yield m, Device, DeviceType
    for name, old in reversed(list(saved.items())):
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old


@pytest.fixture
def builder(forecast_module):
    m, _, _ = forecast_module
    return m.NativeForecastBuilder(hass=Mock(), entry_id="fixture", step_minutes=60, days=3)


def test_history_rejects_unavailable_non_numeric(builder):
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    items = [types.SimpleNamespace(state=s, last_changed=now) for s in (
        "unknown", "unavailable", "bad", "0.5", "1.2")]
    timestamps, values = builder._build_history_index(items)
    assert values == [0.5, 1.2]
    assert len(timestamps) == 2


def test_daily_samples_are_monotonic_after_counter_glitch(builder):
    start = datetime(2026, 10, 24, tzinfo=timezone.utc)
    times = [start + timedelta(hours=i) for i in range(5)]
    t, values = builder._extract_day_samples(times, [0, 1, 0.2, -5, 3], start, start + timedelta(days=1))
    assert values == [0, 1, 1, 3]
    assert len(t) == len(values)


def test_interpolation_respects_day_boundaries(builder):
    start = datetime(2026, 10, 24, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    times = [start + timedelta(hours=8), start + timedelta(hours=10)]
    values = [2.0, 4.0]
    assert builder._interpolate_daily_value(times, values, start, start, end, 4) == 0
    assert builder._interpolate_daily_value(times, values, end, start, end, 4) == 4
    assert builder._interpolate_daily_value(times, values, start + timedelta(hours=9), start, end, 4) == 3
    assert builder._interpolate_daily_value([], [], start, start, end, 4) is None


def test_historical_curve_never_generates_negative_production(builder):
    start = datetime(2026, 10, 24, tzinfo=timezone.utc)
    points = [start + timedelta(hours=h) for h in (0, 6, 12, 18)]
    deltas = builder._build_historical_day_delta_curve(
        points, [0, 2, 1.5, 7], start, start + timedelta(days=1))
    assert deltas is not None
    assert all(d >= 0 for d in deltas)
    assert sum(deltas) > 0


@pytest.mark.parametrize("deltas,expected", [
    ([], 0.0), ([1], 1), ([1, 3], 2), ([1, 2, 3], 2),
])
def test_median_delta(builder, deltas, expected):
    assert builder._calculate_median_delta(deltas) == expected


def test_robust_delta_filters_extreme_outlier(builder):
    values = [(0.1, 1), (0.11, 1), (0.12, 1), (5, 1)]
    result = builder._calculate_robust_weighted_delta(values)
    assert 0.1 <= result <= 0.12


def test_forecast_smoothing_preserves_total_energy(builder):
    raw = [0] * 12 + [6] + [0] * 12
    smoothed = builder._smooth_delta_values(raw)
    assert sum(smoothed) == pytest.approx(6.0)
    assert all(x >= 0 for x in smoothed)
    assert max(smoothed) < 6
    assert builder._smooth_delta_values([]) == []
    assert builder._smooth_delta_values([0, 0]) == [0, 0]


def test_forecast_cache_invalid_after_midnight(builder, forecast_module):
    module = forecast_module[0]
    cache = {
        "date": "2026-10-24", "source_entity_id": "sensor.solar",
        "step_minutes": 60, "days": 3,
        "algorithm_version": module.FORECAST_CACHE_ALGORITHM_VERSION,
        "delta_curve": [{"delta_kwh": 0.2}],
    }
    assert not builder._is_forecast_cache_valid(cache, "2026-10-25", "sensor.solar")
    cache["date"] = "2026-10-25"
    assert builder._is_forecast_cache_valid(cache, "2026-10-25", "sensor.solar")
    cache["algorithm_version"] = -1
    assert not builder._is_forecast_cache_valid(cache, "2026-10-25", "sensor.solar")


@pytest.mark.asyncio
async def test_forecast_build_without_source_is_none(builder):
    assert await builder.build([]) is None


@pytest.mark.asyncio
async def test_forecast_build_without_entity_id_fails_safe(builder, forecast_module):
    _, Device, DeviceType = forecast_module
    builder._resolve_sensor_entity_id = Mock(return_value=None)
    result = await builder.build([Device("Panel Production Today", DeviceType.SENSOR_KWH, 5)])
    assert result.actual_now_value == 5
    assert result.forecasted_today is None


@pytest.mark.asyncio
async def test_forecast_without_recorder_history_uses_current_value(builder, forecast_module):
    _, Device, DeviceType = forecast_module
    builder._resolve_sensor_entity_id = Mock(return_value="sensor.panel")
    builder._get_history_states = AsyncMock(return_value=[])
    result = await builder.build([Device("Panel Production Today", DeviceType.SENSOR_KWH, 5.234)])
    assert result.forecasted_today == 5.234
    assert result.remaining_today == 0
    assert len(result.curve) == 1


@pytest.mark.asyncio
async def test_forecast_valid_cache_is_not_rebuilt(builder):
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    start = now.replace(hour=0)
    builder._forecast_cache_loaded = True
    cache = {"date": "2026-10-25", "source_entity_id": "sensor.solar",
             "step_minutes": 60, "days": 3, "algorithm_version": 5,
             "delta_curve": [{"delta_kwh": 0.1}]}
    builder._forecast_cache = cache
    builder._build_forecast_delta_cache = Mock(side_effect=AssertionError("Rebuild attempted"))
    result = await builder._async_ensure_forecast_cache(
        "sensor.solar", now, start, start + timedelta(days=1), [], [])
    assert result is cache


@pytest.mark.asyncio
async def test_empty_delta_cache_is_not_persisted(builder):
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    start = now.replace(hour=0)
    builder._forecast_cache_loaded = True
    builder._build_forecast_delta_cache = Mock(return_value=[{"delta_kwh": 0}])
    result = await builder._async_ensure_forecast_cache(
        "sensor.solar", now, start, start + timedelta(days=1), [], [])
    assert result is None
    builder._forecast_store.async_save.assert_not_called()


@pytest.mark.asyncio
async def test_native_forecast_generates_future_from_cached_profile(builder, forecast_module):
    """A complete forecast with recorder history must never predict decreasing production."""
    _, Device, DeviceType = forecast_module
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    builder._resolve_sensor_entity_id = Mock(return_value="sensor.solar")
    builder._get_history_states = AsyncMock(return_value=[
        types.SimpleNamespace(state="0", last_changed=start),
        types.SimpleNamespace(state="3", last_changed=start + timedelta(hours=6)),
        types.SimpleNamespace(state="5", last_changed=now),
    ])
    builder._async_ensure_forecast_cache = AsyncMock(return_value={
        "date": "2026-10-25",
        "delta_curve": [{"delta_kwh": 0.1, "power_w": 100}] * 25,
    })
    result = await builder.build([
        Device("Panel Production Today", DeviceType.SENSOR_KWH, "5.0")
    ])
    assert result.forecasted_today >= 5.0
    assert result.remaining_today >= 0
    assert any(item.get("source") == "forecast" for item in result.curve)
    values = [item["value"] for item in result.curve]
    assert values == sorted(values)


def test_real_historical_delta_profile_is_nonnegative(builder):
    start = datetime(2026, 10, 25, tzinfo=timezone.utc)
    previous = start - timedelta(days=1)
    times = [previous + timedelta(hours=h) for h in (0, 6, 12, 18)]
    output = builder._build_forecast_delta_cache(
        times, [0, 1, 4, 6], start, start + timedelta(days=1))
    assert output
    assert all(item["delta_kwh"] >= 0 for item in output)
    assert sum(item["delta_kwh"] for item in output) > 0


@pytest.mark.asyncio
async def test_cache_is_persisted_when_historical_profile_is_usable(builder):
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    start = now.replace(hour=0)
    builder._forecast_cache_loaded = True
    builder._build_forecast_delta_cache = Mock(return_value=[
        {"delta_kwh": 0.0}, {"delta_kwh": 0.5}, {"delta_kwh": 0.1}
    ])
    result = await builder._async_ensure_forecast_cache(
        "sensor.solar", now, start, start + timedelta(days=1), [], [])
    assert result["date"] == "2026-10-25"
    assert result["delta_curve"][1]["delta_kwh"] == 0.5
    builder._forecast_store.async_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_cross_midnight_cache_is_rebuilt_for_new_date(builder, forecast_module):
    """An old daily cache must never leak yesterday's forecast into today's curve."""
    module, _, _ = forecast_module
    now = datetime(2026, 10, 26, 0, 5, tzinfo=timezone.utc)
    start = now.replace(hour=0, minute=0)
    builder._forecast_cache_loaded = True
    builder._forecast_cache = {
        "date": "2026-10-25", "source_entity_id": "sensor.solar",
        "step_minutes": builder.step_minutes, "days": builder.days,
        "algorithm_version": module.FORECAST_CACHE_ALGORITHM_VERSION,
        "delta_curve": [{"delta_kwh": 99}],
    }
    builder._build_forecast_delta_cache = Mock(return_value=[
        {"delta_kwh": 0.0}, {"delta_kwh": 0.5},
    ])
    result = await builder._async_ensure_forecast_cache(
        "sensor.solar", now, start, start + timedelta(days=1), [], [])
    assert result["date"] == "2026-10-26"
    assert result["delta_curve"][1]["delta_kwh"] == 0.5
    assert result["delta_curve"][0]["delta_kwh"] != 99
    builder._forecast_store.async_save.assert_awaited_once()


@pytest.mark.asyncio
async def test_cache_changes_when_forecast_source_changes(builder, forecast_module):
    module, _, _ = forecast_module
    now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)
    start = now.replace(hour=0)
    builder._forecast_cache_loaded = True
    builder._forecast_cache = {
        "date": "2026-10-25", "source_entity_id": "sensor.previous",
        "step_minutes": builder.step_minutes, "days": builder.days,
        "algorithm_version": module.FORECAST_CACHE_ALGORITHM_VERSION,
        "delta_curve": [{"delta_kwh": 1}],
    }
    builder._build_forecast_delta_cache = Mock(return_value=[
        {"delta_kwh": 0}, {"delta_kwh": 0.2},
    ])
    result = await builder._async_ensure_forecast_cache(
        "sensor.current", now, start, start + timedelta(days=1), [], [])
    assert result["source_entity_id"] == "sensor.current"


@pytest.mark.asyncio
async def test_empty_history_after_midnight_uses_new_day_reading(builder, forecast_module):
    """A new-day production reading should not be combined with yesterday's accumulated total."""
    _, Device, DeviceType = forecast_module
    builder._resolve_sensor_entity_id = Mock(return_value="sensor.solar")
    builder._get_history_states = AsyncMock(return_value=[])
    result = await builder.build([
        Device("Panel Production Today", DeviceType.SENSOR_KWH, "0.06")
    ])
    assert result.forecasted_today == pytest.approx(0.06)
    assert result.remaining_today == 0
