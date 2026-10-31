"""Regression tests for independent battery discovery and entity scoping."""

from types import SimpleNamespace
from unittest.mock import Mock

import ast
import logging
from pathlib import Path

# Extract only the two pure discovery/build methods. The CI test environment
# deliberately does not install the Home Assistant runtime.
source_path = (
    Path(__file__).resolve().parents[1]
    / "custom_components/fusion_solar_app/api/installation.py"
)
module_ast = ast.parse(source_path.read_text(encoding="utf-8"))
class_ast = next(
    node for node in module_ast.body
    if isinstance(node, ast.ClassDef) and node.name == "FusionSolarInstallationMixin"
)
methods = [
    node for node in class_ast.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {
        "_discover_battery_dn_from_flow_nodes",
        "_build_battery_devices",
    }
]
test_ast = ast.Module(
    body=[ast.ClassDef(
        name="FusionSolarInstallationMixin",
        bases=[],
        keywords=[],
        body=methods,
        decorator_list=[],
    )],
    type_ignores=[],
)
namespace = {"Any": object, "Device": object, "_LOGGER": logging.getLogger(__name__)}
exec(compile(ast.fix_missing_locations(test_ast), str(source_path), "exec"), namespace)
FusionSolarInstallationMixin = namespace["FusionSolarInstallationMixin"]


def _fake_api():
    api = SimpleNamespace(
        battery_dn=None,
        battery_dns=[],
        battery_model="primary",
        battery_serial_number="serial-primary",
        battery_software_version="1",
        _battery_entity_dn=None,
    )
    api._discover_battery_dn_from_flow_nodes = (
        lambda nodes: FusionSolarInstallationMixin._discover_battery_dn_from_flow_nodes(api, nodes)
    )
    api._build_battery_devices = (
        lambda: FusionSolarInstallationMixin._build_battery_devices(api)
    )
    return api


def test_discovers_all_batteries_and_deduplicates():
    api = _fake_api()
    api._discover_battery_dn_from_flow_nodes([
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devIds": ["BAT_A", "BAT_B", "BAT_A"]},
        {"name": "neteco.pvms.devTypeLangKey.energy_store", "devDn": "BAT_C"},
    ])
    assert api.battery_dns == ["BAT_A", "BAT_B", "BAT_C"]
    assert api.battery_dn == "BAT_A"


def test_single_battery_keeps_unscoped_entities():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn))
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A"]
    assert seen == [("BAT_A", None)]
    assert api.battery_dn == "BAT_A"


def test_secondary_battery_is_scoped_and_metadata_restored():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]
    seen = []

    def fetch():
        seen.append((api.battery_dn, api._battery_entity_dn, api.battery_model))
        api.battery_model = "model-" + api.battery_dn
        return [api.battery_dn]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["BAT_A", "BAT_B"]
    assert seen == [("BAT_A", None, "primary"), ("BAT_B", "BAT_B", None)]
    assert api.battery_dn == "BAT_A"
    assert api.battery_model == "model-BAT_A"
    assert api._battery_entity_dn is None


def test_secondary_failure_does_not_remove_primary():
    api = _fake_api()
    api.battery_dn = "BAT_A"
    api.battery_dns = ["BAT_A", "BAT_B"]

    def fetch():
        if api.battery_dn == "BAT_B":
            raise RuntimeError("HTTP 500")
        return ["primary"]

    api.get_battery_devices = fetch
    assert api._build_battery_devices() == ["primary"]
    assert api.battery_dn == "BAT_A"
