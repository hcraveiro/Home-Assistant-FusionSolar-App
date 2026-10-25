"""Regression tests for FusionSolar and EnergyOrb login-host normalization (#46)."""

import ast
from pathlib import Path
import re
import unittest


AUTH_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "fusion_solar_app"
    / "api"
    / "auth.py"
)


def load_normalize_host():
    """Compile the production helper without importing Home Assistant."""
    tree = ast.parse(AUTH_SOURCE.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "normalize_fusionsolar_host"
    )
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = {"re": re}
    exec(compile(module, str(AUTH_SOURCE), "exec"), namespace)
    return namespace["normalize_fusionsolar_host"]


class HostNormalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.normalize = staticmethod(load_normalize_host())

    def test_energyorb_host_preserved(self):
        for host in (
            "monitor.energyorb.com",
            "https://monitor.energyorb.com/pvmswebsite/login/build/index.html",
            "HTTPS://MONITOR.ENERGYORB.COM/",
        ):
            with self.subTest(host=host):
                self.assertEqual(self.normalize(host), "monitor.energyorb.com")

    def test_legacy_fusionsolar_behavior_unchanged(self):
        self.assertEqual(
            self.normalize("uni004eu5.fusionsolar.huawei.com"),
            "eu5.fusionsolar.huawei.com",
        )
        self.assertEqual(
            self.normalize("https://eu5.fusionsolar.huawei.com/path"),
            "eu5.fusionsolar.huawei.com",
        )
        self.assertEqual(self.normalize(None), "eu5.fusionsolar.huawei.com")

    def test_unknown_host_not_misrepresented_as_energyorb(self):
        self.assertNotEqual(
            self.normalize("some-other-server.example"),
            "monitor.energyorb.com",
        )


if __name__ == "__main__":
    unittest.main()
