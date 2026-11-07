"""Fixture/clock checks only; real statistical assertions live in the HA checker.

These unit tests do not replace the standalone actual-Recorder run and make no
claim about sums computed by test doubles.
"""
from datetime import datetime, timezone
import importlib
from pathlib import Path

import pytest

from test_api_lifecycle_behavior import api_module  # dependency of shared fixture
from test_runtime_mock_api import runtime


@pytest.fixture
def checker(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "api_profiles"))
    return importlib.import_module("check_recorder_homeassistant")


def energy_bodies(profile, frame_id):
    frame = next(frame for frame in profile["frames"] if frame["id"] == frame_id)
    return [(profile["routes"][response["route"]], response["body"]["data"]) for response in frame["responses"]]


def test_profile_is_valid_fictional_and_does_not_mutate_source(checker, runtime):
    loader, _ = runtime
    original = loader.load_profile("transitions-energy")
    profile = checker.recorder_profile(loader.load_profile)
    assert loader.validate_profile(profile) == profile
    assert loader.load_profile("transitions-energy") == original
    assert profile["id"] == "synthetic-recorder-disposable"
    assert profile["station"]["dn"].startswith("MOCK_RUNTIME_")
    assert len(profile["frames"]) == len(checker.FRAMES) + 2
    assert "relative-drop-over-10pct" in {frame["id"] for frame in profile["frames"]}


@pytest.mark.parametrize("frame,raw", [
    ("literal-marker", "--"),
    ("invalid-spaced-marker", " -- "),
    ("invalid-null", None),
    ("invalid-garbage", "garbage"),
    ("measured-zero", 0),
    ("correction-001-kwh", 33.99),
])
def test_raw_http_inputs_remain_distinct(checker, runtime, frame, raw):
    loader, _ = runtime
    profile = checker.recorder_profile(loader.load_profile)
    bodies = energy_bodies(profile, frame)
    # Dec/current month and lifetime carry the raw values, never pre-parsed states.
    for route, body in bodies:
        if route["params"].get("dateStr") == "2027-01-01 00:00:00":
            continue  # Unrequested future-month route has zero-filled future slots.
        assert body["totalProductPower"] == raw
        assert body["productPower"] == [raw] * 31


def test_calendar_keeps_prior_month_week_samples(checker, runtime):
    loader, _ = runtime
    profile = checker.recorder_profile(loader.load_profile)
    for frame_id, raw in (("calendar-jan1-reset", 0), ("calendar-new-energy", 2)):
        months = {route["params"]["dateStr"]: body for route, body in energy_bodies(profile, frame_id)
                  if route["params"]["timeDim"] == "4"}
        assert set(months) == {"2026-12-01 00:00:00", "2027-01-01 00:00:00"}
        assert months["2026-12-01 00:00:00"]["productPower"] == [35] * 31
        assert months["2027-01-01 00:00:00"]["productPower"] == [raw] + [0] * 30


def test_clock_controls_only_explicit_wall_sources(checker):
    now = datetime(2027, 1, 1, tzinfo=timezone.utc)
    clock = checker.Clock(now)
    controlled = clock.datetime_class()
    assert controlled.now() == now.replace(tzinfo=None)
    assert controlled.now(timezone.utc) == now
    assert clock.utcnow() == now
    assert clock.timestamp() == now.timestamp()
    clock.now = now.replace(minute=5)
    assert controlled.now().minute == 5
