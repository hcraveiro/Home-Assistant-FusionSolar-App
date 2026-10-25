"""Regression tests for safe legacy inverter entity migration."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "custom_components/fusion_solar_app/__init__.py"


def _migration_function(entries, devices):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    fn = next(node for node in tree.body
              if isinstance(node, ast.AsyncFunctionDef)
              and node.name == "_async_migrate_inverter_unique_ids")
    registry = SimpleNamespace(
        async_get_entity_id=lambda *args: None,
    )
    changes = {}

    async def migrate(hass, entry_id, callback):
        for entry in entries:
            result = callback(entry)
            if result is not None:
                changes[entry.entity_id] = result["new_unique_id"]

    namespace = {
        "DOMAIN": "fusion_solar_app",
        "HomeAssistant": object,
        "ConfigEntry": object,
        "FusionSolarCoordinator": object,
        "er": SimpleNamespace(async_get=lambda hass: registry, async_migrate_entries=migrate),
        "dr": SimpleNamespace(async_get=lambda hass: SimpleNamespace(
            async_get=lambda device_id: devices.get(device_id))),
        "callback": lambda f: f,
        "_LOGGER": SimpleNamespace(warning=lambda *args: None),
    }
    exec(compile(ast.fix_missing_locations(
        ast.Module(body=[fn], type_ignores=[])), str(SOURCE), "exec"), namespace)
    return namespace["_async_migrate_inverter_unique_ids"], changes


def _make_context(inverter_dns):
    api = SimpleNamespace(
        inverters={dn: SimpleNamespace(canonical_dn=dn) for dn in inverter_dns},
        station="plant-1",
        controller_name="fusion",
        sanitize_id_segment=lambda value: str(value).lower(),
    )
    return SimpleNamespace(api=api), SimpleNamespace(entry_id="entry-1")


def _entity(entity_id, device_id):
    return SimpleNamespace(
        entity_id=entity_id,
        device_id=device_id,
        unique_id="fusion_solar_app-fusion_plant-1_inverter_internal_temperature",
        domain="sensor",
        platform="fusion_solar_app",
    )


def _device(dn, entry_id="entry-1"):
    return SimpleNamespace(
        identifiers={("fusion_solar_app", f"fusion_plant-1_inverter_{dn}")},
        config_entries={entry_id},
    )


def test_migrate_legacy_entity_using_registered_device_not_flow_order():
    """The original inverter may not be first in a multi-inverter flow."""
    coordinator, config_entry = _make_context(["new-inverter", "old-inverter"])
    migrate, changes = _migration_function(
        [_entity("sensor.original", "device-old")],
        {"device-old": _device("old-inverter")},
    )
    asyncio.run(migrate(object(), config_entry, coordinator))
    assert changes["sensor.original"] == (
        "fusion_solar_app-fusion_plant-1_inv_old-inverter_inverter_internal_temperature"
    )


def test_ambiguous_multi_inverter_migration_is_skipped():
    coordinator, config_entry = _make_context(["inverter-one", "inverter-two"])
    migrate, changes = _migration_function(
        [_entity("sensor.original", None)], {},
    )
    asyncio.run(migrate(object(), config_entry, coordinator))
    assert changes == {}


def test_single_inverter_migration_allows_unregistered_device():
    coordinator, config_entry = _make_context(["only-inverter"])
    migrate, changes = _migration_function(
        [_entity("sensor.original", None)], {},
    )
    asyncio.run(migrate(object(), config_entry, coordinator))
    assert changes["sensor.original"].startswith(
        "fusion_solar_app-fusion_plant-1_inv_only-inverter_"
    )
