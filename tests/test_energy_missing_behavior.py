"""Exercise real energy parsing rather than generic numeric fallbacks."""
from unittest.mock import Mock

import pytest

from test_energy_balance_full_behavior import module, make_api, complete_data


@pytest.mark.parametrize("raw", [None, "--", "null", "", "broken", "12 garbage", float("nan"), float("inf"), True, {}, []])
def test_missing_energy_is_not_zero(module, raw):
    api = make_api(module)
    data = complete_data()
    for key in data["data"]:
        data["data"][key] = [raw] * 31 if isinstance(data["data"][key], list) else raw
    api.call_energy_balance = Mock(return_value=data)
    api.get_week_data = Mock(return_value=[data])
    output = {"panel_production_today": 35}
    api.update_output_with_energy_balance(output)
    assert all(value is None for value in output.values())


@pytest.mark.parametrize("zero", [0, 0.0, "0", "0.0", "0 kWh", "0 Wh"])
def test_true_zero_and_partial_vectors(module, zero):
    api = make_api(module)
    assert api._optional_grid_energy({"v": zero}, "v") == 0
    assert api._energy_sum([zero, zero]) == 0
    assert api._energy_sum([zero, None]) is None
    assert api._energy_sum([35, "--", 34]) is None
    assert api._energy_sum([]) is None


@pytest.mark.parametrize("isitepower", [False, True])
@pytest.mark.parametrize("gap", [None, "--", "null", "malformed", float("nan")])
def test_calendar_vectors_ignore_only_future_slots(module, monkeypatch, isitepower, gap):
    """Future placeholders are not missing measurements; elapsed gaps are."""
    from datetime import datetime

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 11, 5, 12)

    energy = module[0]
    monkeypatch.setattr(energy, "datetime", FrozenDatetime)
    api = make_api(module)
    api._is_isitepower_m = isitepower
    month, year, lifetime = complete_data(), complete_data(), complete_data()
    for field in ("chargePower", "dischargePower"):
        month["data"][field] = ["2"] * 5 + [gap] * 25
        year["data"][field] = ["3"] * 11 + [gap]
        lifetime["data"][field] = ["4", gap]
    periods = {energy.ENERGY_BALANCE_CALL_TYPE.MONTH: month,
               energy.ENERGY_BALANCE_CALL_TYPE.YEAR: year,
               energy.ENERGY_BALANCE_CALL_TYPE.LIFETIME: lifetime}
    api.call_energy_balance = Mock(side_effect=lambda kind: periods[kind])
    api.get_week_data = Mock(return_value=[complete_data()] * 4)
    output = {}
    api.update_output_with_energy_balance(output)
    for category in ("battery_injection", "battery_consumption"):
        assert output[f"{category}_month"] == 10
        assert output[f"{category}_year"] == 33
        # No undocumented lifetime year indexing or removal of gaps.
        assert output[f"{category}_lifetime"] is None
    for field in ("chargePower", "dischargePower"):
        month["data"][field][3] = gap
        year["data"][field][9] = gap
    api.update_output_with_energy_balance(output)
    for category in ("battery_injection", "battery_consumption"):
        assert output[f"{category}_month"] is None
        assert output[f"{category}_year"] is None
    # Short arrays also omit elapsed observations, not just future slots.
    assert api._period_energy_sum([0] * 4, "month") is None
    assert api._period_energy_sum([0] * 10, "year") is None
    assert api._period_energy_sum([0] * 5, "month") == 0
    assert api._period_energy_sum([0] * 11, "year") == 0


def test_repeated_poll_correction_missing_and_recovery(module):
    api = make_api(module)
    data = complete_data()
    api.call_energy_balance = Mock(return_value=data)
    api.get_week_data = Mock(return_value=[data])
    output = {}
    for raw, expected in [(35, 35), (34, 34), (None, None), ("--", None), (0, 0), ("34", 34)]:
        data["data"]["totalProductPower"] = raw
        api.update_output_with_energy_balance(output)
        assert output["panel_production_lifetime"] == expected
        assert output["panel_production_month"] == expected
