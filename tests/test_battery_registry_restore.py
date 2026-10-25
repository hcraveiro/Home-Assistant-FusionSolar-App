"""Regression tests for restoring a known battery from Home Assistant registry."""

import ast
from pathlib import Path
from types import SimpleNamespace

COORDINATOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components" / "fusion_solar_app" / "coordinator.py"
)


def _restore_method():
    source = ast.parse(COORDINATOR_PATH.read_text(encoding="utf-8"))
    cls = next(node for node in source.body if isinstance(node, ast.ClassDef)
               and node.name == "FusionSolarCoordinator")
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                  and node.name == "_restore_known_battery_dn")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {"DOMAIN": "fusion_solar_app"}
    exec(compile(module, str(COORDINATOR_PATH), "exec"), namespace)
    return namespace["_restore_known_battery_dn"]


def _coordinator(registry_devices, battery_dn=None, station="plant-1"):
    api = SimpleNamespace(battery_dn=battery_dn, station=station)
    coordinator = SimpleNamespace(
        api=api, config_entry=SimpleNamespace(entry_id="entry-A"), hass=object(),
    )
    return coordinator, SimpleNamespace(devices=registry_devices)


def _device(identifier, entry="entry-A", domain="fusion_solar_app"):
    return SimpleNamespace(
        config_entries={entry},
        identifiers={(domain, identifier)},
    )


def test_restore_battery_from_same_entry_and_station():
    restore = _restore_method()
    expected = "battery-dn-123"
    coordinator, registry = _coordinator({
        "one": _device("fusion_solar_app_plant-1_battery_" + expected)
    })
    restore.__globals__["dr"] = SimpleNamespace(async_get=lambda hass: registry)
    restore.__globals__["_LOGGER"] = SimpleNamespace(debug=lambda *args: None)
    restore(coordinator)
    assert coordinator.api.battery_dn == expected


def test_do_not_restore_from_different_entry_or_station():
    restore = _restore_method()
    coordinator, registry = _coordinator({
        "one": _device("fusion_solar_app_plant-1_battery_other", entry="entry-B"),
        "two": _device("fusion_solar_app_plant-2_battery_other"),
        "three": _device("fusion_solar_app_plant-1_battery_unknown_battery"),
    })
    restore.__globals__["dr"] = SimpleNamespace(async_get=lambda hass: registry)
    restore(coordinator)
    assert coordinator.api.battery_dn is None


def test_existing_battery_identity_is_never_overwritten():
    restore = _restore_method()
    coordinator, registry = _coordinator({
        "one": _device("fusion_solar_app_plant-1_battery_other")
    }, battery_dn="already-known")
    restore.__globals__["dr"] = SimpleNamespace(async_get=lambda hass: registry)
    restore(coordinator)
    assert coordinator.api.battery_dn == "already-known"
