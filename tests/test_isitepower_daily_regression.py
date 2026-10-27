"""Regression tests for iSitePower-M daily values and battery capacity units."""

import ast
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app/api"


class ISitePowerEnergyRegressions(unittest.TestCase):
    def test_battery_capacity_uses_kwh_not_kw(self):
        source = (ROOT / "signal_maps.py").read_text(encoding="utf-8")
        self.assertIn(
            '{"id": "Battery Capacity", "type": DeviceType.SENSOR_KWH,',
            source,
        )

    def test_daily_arrays_are_parsed_without_inventing_grid_totals(self):
        source = (ROOT / "energy_balance.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "FusionSolarEnergyBalanceMixin")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                      and node.name == "_update_isitepower_energy_balance")
        # Isolate the production method so no HA installation is needed.
        standalone = ast.FunctionDef(
            name=method.name, args=method.args, body=method.body,
            decorator_list=[], returns=None, type_comment=None,
            type_params=[],
        )
        module = ast.fix_missing_locations(ast.Module(body=[standalone], type_ignores=[]))
        kinds = SimpleNamespace(MONTH="month", YEAR="year", LIFETIME="lifetime")
        namespace = {
            "datetime": datetime,
            "ENERGY_BALANCE_CALL_TYPE": kinds,
            "_LOGGER": SimpleNamespace(warning=lambda *args: None),
            "APIConnectionError": RuntimeError,
            "APIDataStructureError": ValueError,
        }
        exec(compile(module, str(ROOT / "energy_balance.py"), "exec"), namespace)
        day = datetime.now().day - 1
        def array(value):
            samples = ["--"] * 31
            samples[day] = value
            return samples
        calls = []
        class Fake:
            def call_energy_balance(self, kind):
                calls.append(kind)
                if kind == "month":
                    return {"success": True, "data": {
                        "totalBuyPower": None, "totalOnGridPower": None,
                        "totalProductPower": None, "totalUsePower": None,
                        "productPower": array("23.37"),
                        "usePower": array("15.50"),
                        "selfUsePower": array("--"),
                    }}
                return {"success": True, "data": {}}
            def get_week_data(self):
                return []
            def _optional_grid_energy(self, payload, key):
                if not isinstance(payload, dict):
                    return None
                try:
                    return float(payload[key])
                except (KeyError, ValueError, TypeError):
                    return None
            def _update_output_with_self_consumption_ratios(self, output):
                pass
        out = {}
        namespace["_update_isitepower_energy_balance"](Fake(), out)
        self.assertEqual(out["panel_production_today"], 23.37)
        self.assertEqual(out["house_load_today"], 15.5)
        self.assertIsNone(out.get("panel_production_consumption_today"))
        self.assertIsNone(out["grid_consumption_month"])
        self.assertIsNone(out["grid_injection_month"])
        self.assertEqual(calls, ["month", "year", "lifetime"])


if __name__ == "__main__":
    unittest.main()
