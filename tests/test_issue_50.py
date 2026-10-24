"""Regression tests for monthly production spikes near midnight (issue #50)."""

import ast
from datetime import datetime
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Optional
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/api/energy_balance.py"


def load_validator():
    """Compile the production validator without importing Home Assistant."""
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    node = next(
        item for item in ast.walk(tree)
        if isinstance(item, ast.FunctionDef)
        and item.name == "_validate_monthly_production_at_midnight"
    )
    node.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    namespace = {"Dict": Dict, "Optional": Optional, "datetime": datetime, "_LOGGER": logging.getLogger(__name__), "extract_numeric": lambda value: float(value)}
    exec(compile(module, str(SOURCE), "exec"), namespace)
    return namespace[node.name], namespace


class MonthlyProductionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        validator, cls.namespace = load_validator()
        cls.validator = staticmethod(validator)

    def setUp(self):
        self.api = SimpleNamespace()

    def update(self, at, monthly, yearly, lifetime, daily_production=None):
        output = {
            "panel_production_month": monthly,
            "panel_production_year": yearly,
            "panel_production_lifetime": lifetime,
        }
        class Clock:
            @staticmethod
            def now():
                return at
        with patch.dict(self.namespace, {"datetime": Clock}):
            self.validator(self.api, output, daily_production)
        return output["panel_production_month"]

    def test_real_midnight_spike_and_recovery(self):
        self.update(datetime(2026, 10, 23, 23, 57), 281.08, 5667.92, 25046.17)
        self.assertAlmostEqual(self.update(datetime(2026, 10, 24, 0, 0), 290.86, 5668.02, 25046.27), 281.08)
        self.assertAlmostEqual(self.update(datetime(2026, 10, 24, 0, 1), 281.19, 5668.03, 25046.28), 281.19)

    def test_legitimate_simultaneous_increase_is_accepted(self):
        self.update(datetime(2026, 10, 23, 23, 59), 280, 5660, 25040)
        self.assertEqual(self.update(datetime(2026, 10, 24, 0, 1), 282, 5662, 25042), 282)

    def test_large_increase_outside_midnight_window_is_accepted(self):
        self.update(datetime(2026, 10, 24, 12, 0), 280, 5660, 25040)
        self.assertEqual(self.update(datetime(2026, 10, 24, 12, 5), 290, 5660, 25040), 290)

    def test_month_rollover_is_not_blocked(self):
        self.update(datetime(2026, 10, 31, 23, 59), 300, 5680, 25060)
        self.assertEqual(self.update(datetime(2026, 11, 1, 0, 1), 0, 5680, 25060), 0)

    def test_cold_start_midnight_spike_uses_daily_breakdown(self):
        # No previous poll exists: individual days provide independent evidence.
        daily_values = ["10.00"] * 23 + ["0.00"]
        self.assertEqual(
            self.update(datetime(2026, 10, 24, 0, 0), 239.78, 5668.02, 25046.27, daily_values),
            230.0,
        )

    def test_cold_start_valid_total_unchanged(self):
        daily_values = ["10.00"] * 23 + ["0.00"]
        self.assertEqual(
            self.update(datetime(2026, 10, 24, 0, 0), 230.0, 5668.02, 25046.27, daily_values),
            230.0,
        )

    def test_cold_start_incomplete_breakdown_does_not_override(self):
        self.assertEqual(
            self.update(datetime(2026, 10, 24, 0, 0), 239.78, 5668.02, 25046.27, ["10.0"]),
            239.78,
        )

    def test_missing_values_are_not_modified(self):
        self.assertIsNone(self.update(datetime(2026, 10, 24, 0, 1), None, 5680, 25060))


if __name__ == "__main__":
    unittest.main()
