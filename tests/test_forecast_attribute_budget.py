"""Regression tests for large forecast attributes without a Home Assistant runtime."""

import ast
from pathlib import Path
import json
from typing import Any

SENSOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components" / "fusion_solar_app" / "sensor.py"
)


def _load_attribute_budget_helper():
    """Compile the real helper in isolation, without HA dependency stubs."""
    tree = ast.parse(SENSOR_PATH.read_text(encoding="utf-8"))
    helper = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_bounded_forecast_attributes"
    )
    module = ast.fix_missing_locations(ast.Module(body=[helper], type_ignores=[]))
    scope = {"json": json, "Any": Any}
    exec(compile(module, str(SENSOR_PATH), "exec"), scope)
    return scope["_bounded_forecast_attributes"]


def test_small_forecast_attributes_remain_intact():
    limit = _load_attribute_budget_helper()
    attributes = {
        "curve": [{"time": 1, "value": 3}],
        "forecast_power_chart": [[1, 2]],
        "debug": {"source": "native"},
    }
    assert limit(attributes.copy()) == attributes


def test_large_forecast_attributes_fit_recorder_with_chart_endpoints():
    limit = _load_attribute_budget_helper()
    charts = [[i * 60000, i / 10] for i in range(2000)]
    attributes = {
        "curve": [{"index": i, "details": "x" * 100} for i in range(2000)],
        "debug": {"details": "x" * 5000},
        "forecast_power_chart": charts.copy(),
        "forecast_cumulative_chart": charts.copy(),
        "provider": "native",
    }
    result = limit(attributes)
    encoded = json.dumps(result, default=str, ensure_ascii=False).encode("utf-8")
    assert len(encoded) <= 15000
    assert result["provider"] == "native"
    assert result["forecast_power_chart"][0] == charts[0]
    assert result["forecast_power_chart"][-1] == charts[-1]
    assert result["forecast_cumulative_chart"][0] == charts[0]
    assert result["forecast_cumulative_chart"][-1] == charts[-1]


def test_large_debug_only_does_not_discard_chart():
    limit = _load_attribute_budget_helper()
    result = limit({
        "debug": {"payload": "x" * 20000},
        "forecast_power_chart": [[1, 1], [2, 2]],
    })
    assert "debug" not in result
    assert result["forecast_power_chart"] == [[1, 1], [2, 2]]
