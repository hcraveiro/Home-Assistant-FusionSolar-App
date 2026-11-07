"""Primary battery migration using HA-shaped device/entity registry fakes.

HA is intentionally absent in this offline suite. Extract only the coordinator
identity methods, but model the registry APIs/fields rather than inventing a
single config_entry_id on device entries (HA devices use config_entries).
"""

import ast
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_multi_battery_discovery import _fake_api

DOMAIN = "fusion_solar_app"
COORDINATOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components" / DOMAIN / "coordinator.py"
)


class FakeDeviceRegistry:
    def __init__(self, devices):
        self.devices = {device.id: device for device in devices}

    def async_get(self, device_id):
        return self.devices.get(device_id)


class FakeEntityRegistry:
    def __init__(self, entities):
        self.entities = {entity.entity_id: entity for entity in entities}


class FakeConfigEntries:
    def __init__(self):
        self.updates = []

    def async_update_entry(self, entry, *, data):
        self.updates.append(data)
        entry.data = data
        return True


def _identity_class():
    source = ast.parse(COORDINATOR_PATH.read_text(encoding="utf-8"))
    cls = next(node for node in source.body if isinstance(node, ast.ClassDef)
               and node.name == "FusionSolarCoordinator")
    methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)
               and node.name in {"_restore_known_battery_dn", "_persist_primary_battery_dn"}]
    module = ast.fix_missing_locations(ast.Module(body=[ast.ClassDef(
        name="Coordinator", bases=[], keywords=[], body=methods, decorator_list=[]
    )], type_ignores=[]))
    from identity_test_support import identity_module

    namespace = {
        **vars(identity_module()),
        "DOMAIN": DOMAIN,
        "_LOGGER": logging.getLogger(__name__),
        "dr": SimpleNamespace(
            async_get=lambda hass: hass.device_registry,
            async_entries_for_config_entry=lambda registry, entry_id: [
                device for device in registry.devices.values()
                if entry_id in device.config_entries
            ],
        ),
        "er": SimpleNamespace(
            async_get=lambda hass: hass.entity_registry,
            # HA includes disabled entities by default; no state lookup needed.
            async_entries_for_config_entry=lambda registry, entry_id: [
                entity for entity in registry.entities.values()
                if entity.config_entry_id == entry_id
            ],
        ),
    }
    exec(compile(module, str(COORDINATOR_PATH), "exec"), namespace)
    return namespace["Coordinator"]


def _coordinator(devices=(), entities=(), *, data=None, battery_dn=None, station="plant-1"):
    coordinator = _identity_class()()
    coordinator.api = _fake_api()
    coordinator.api.battery_dn = battery_dn
    coordinator.api.station = station
    coordinator.api.sanitize_id_segment = lambda value: (
        str(value).lower().replace(" ", "_").replace(":", "_").replace("/", "_")
    )
    coordinator.config_entry = SimpleNamespace(
        entry_id="entry-A", data={"username": "keep-me", **(data or {})}
    )
    coordinator.hass = SimpleNamespace(
        device_registry=FakeDeviceRegistry(devices),
        entity_registry=FakeEntityRegistry(entities),
        config_entries=FakeConfigEntries(),
    )
    return coordinator


def _device(dn, *, entry="entry-A", station="plant-1", domain=DOMAIN, device_id=None):
    return SimpleNamespace(
        id=device_id or "device-" + dn,
        config_entries={entry},
        identifiers={(domain, f"{DOMAIN}_{station}_battery_{dn}")},
    )


def _entity(dn="BAT_A", *, scoped=False, device_id=None, entry="entry-A", platform=DOMAIN,
            station="plant-1", legacy_no_station=False, disabled=False):
    scope = "" if legacy_no_station else "_" + station
    if scoped:
        scope += "_inv_" + dn.lower()
    return SimpleNamespace(
        entity_id="sensor.custom_" + dn.lower() + ("_scoped" if scoped else ""),
        unique_id=f"{DOMAIN}-{DOMAIN}{scope}_battery_soc",
        platform=platform,
        config_entry_id=entry,
        device_id=device_id if device_id is not None else "device-" + dn,
        disabled_by="user" if disabled else None,
    )


def test_restore_battery_from_namespaced_registry_without_persisted_primary():
    device = _device("BAT_A")
    device.identifiers = {(domain, identifier + "__entry_entry-A")
                          for domain, identifier in device.identifiers}
    entity = _entity("BAT_A")
    entity.unique_id += "__entry_entry-A"
    coordinator = _coordinator([device], [entity], data={
        "ha_identity": {"namespace": "__entry_entry-A", "entities": {}},
    })
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn == "BAT_A"


def test_restore_battery_from_same_entry_and_station():
    coordinator = _coordinator([_device("BAT_A")])
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn == "BAT_A"
    coordinator._persist_primary_battery_dn()
    assert coordinator.config_entry.data["primary_battery_dn"] == "BAT_A"
    assert coordinator.config_entry.data["primary_battery_station_dn"] == "plant-1"
    assert coordinator.config_entry.data["username"] == "keep-me"


def test_do_not_restore_from_different_entry_or_station():
    coordinator = _coordinator([
        _device("OTHER", entry="entry-B"),
        _device("OTHER", station="plant-2", device_id="different-station"),
        _device("unknown_battery"),
        _device("wrong-domain", domain="other"),
    ])
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert not coordinator.api._battery_primary_ambiguous


@pytest.mark.parametrize("suffix", ["percentage", "capacity", "consumption_power", "injection_today"])
@pytest.mark.parametrize("with_registered_battery", [False, True])
def test_installation_aggregate_entities_do_not_block_primary_discovery(suffix, with_registered_battery):
    aggregate = _entity(device_id="plant-device")
    aggregate.unique_id = f"{DOMAIN}-{DOMAIN}_plant-1_battery_{suffix}"
    coordinator = _coordinator(
        [_device("BAT_A")] if with_registered_battery else [], [aggregate],
    )
    coordinator._restore_known_battery_dn()
    assert not coordinator.api._battery_primary_ambiguous
    coordinator.api._discover_battery_dn_from_flow_nodes([
        {"name": "energy_store", "devIds": ["BAT_A"]},
    ])
    assert coordinator.api.battery_dn == "BAT_A"


def test_existing_battery_identity_is_never_overwritten():
    coordinator = _coordinator([_device("OTHER")], battery_dn="already-known")
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn == "already-known"


@pytest.mark.parametrize("order", [("BAT_B", "BAT_A"), ("BAT_A", "BAT_B")])
@pytest.mark.parametrize("legacy_no_station", [False, True])
def test_legacy_entity_association_not_registry_order_selects_primary(order, legacy_no_station):
    entities = [
        _entity("BAT_B", scoped=True),
        _entity("BAT_A", legacy_no_station=legacy_no_station, disabled=True),
    ]
    coordinator = _coordinator([_device(dn) for dn in order], entities)
    original_ids = [(entity.entity_id, entity.unique_id) for entity in entities]
    coordinator._restore_known_battery_dn()
    coordinator._persist_primary_battery_dn()
    assert coordinator.api.battery_dn == "BAT_A"
    assert coordinator.config_entry.data["primary_battery_dn"] == "BAT_A"
    assert [(entity.entity_id, entity.unique_id) for entity in entities] == original_ids


def test_persisted_primary_restores_when_only_secondary_registered():
    coordinator = _coordinator(
        [_device("BAT_B")], [_entity("BAT_B", scoped=True)],
        data={"primary_battery_dn": "BAT_A", "primary_battery_station_dn": "plant-1"},
    )
    coordinator._restore_known_battery_dn()
    coordinator.api._discover_battery_dn_from_flow_nodes([
        {"name": "energy_store", "devIds": ["BAT_B", "BAT_A"]},
    ])
    seen = []

    def fetch():
        seen.append((coordinator.api.battery_dn, coordinator.api._battery_entity_dn))
        return []

    coordinator.api.get_battery_devices = fetch
    coordinator.api._build_battery_devices()
    assert seen == [("BAT_A", None), ("BAT_B", "BAT_B")]
    assert coordinator.api.battery_dn == "BAT_A"
    coordinator._persist_primary_battery_dn()
    assert coordinator.hass.config_entries.updates == []


def test_first_poll_primary_failure_persists_before_secondary_registers_and_restart():
    first = _coordinator()
    first._restore_known_battery_dn()
    first.api._discover_battery_dn_from_flow_nodes([
        {"name": "energy_store", "devIds": ["BAT_A", "BAT_B"]},
    ])

    def fetch():
        if first.api.battery_dn == "BAT_A":
            raise RuntimeError("primary temporarily offline")
        return ["secondary only"]

    first.api.get_battery_devices = fetch
    assert first.api._build_battery_devices() == ["secondary only"]
    first._persist_primary_battery_dn()
    restarted = _coordinator(
        [_device("BAT_B")], [_entity("BAT_B", scoped=True)], data=first.config_entry.data,
    )
    restarted._restore_known_battery_dn()
    assert restarted.api.battery_dn == "BAT_A"


@pytest.mark.parametrize("entities", [[], [_entity("BAT_A", device_id="removed")]])
def test_ambiguous_multiple_devices_do_not_reassign_legacy_ids(entities):
    coordinator = _coordinator([_device("BAT_B"), _device("BAT_A")], entities)
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert coordinator.api._battery_primary_ambiguous
    coordinator.api._discover_battery_dn_from_flow_nodes([
        {"name": "energy_store", "devIds": ["BAT_B", "BAT_A"]},
    ])
    seen = []
    coordinator.api.get_battery_devices = lambda: seen.append(
        (coordinator.api.battery_dn, coordinator.api._battery_entity_dn)
    ) or []
    coordinator.api._build_battery_devices()
    assert seen == [("BAT_B", "BAT_B"), ("BAT_A", "BAT_A")]
    assert coordinator.api.battery_dn is None
    coordinator._persist_primary_battery_dn()
    assert coordinator.hass.config_entries.updates == []


def test_lone_secondary_without_persisted_primary_is_not_promoted():
    coordinator = _coordinator([_device("BAT_B")], [_entity("BAT_B", scoped=True)])
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert coordinator.api._battery_primary_ambiguous


def test_orphan_legacy_entity_without_devices_blocks_flow_reassignment():
    coordinator = _coordinator(entities=[_entity(device_id="deleted-device")])
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert coordinator.api._battery_primary_ambiguous


def test_conflicting_legacy_associations_are_not_arbitrarily_resolved():
    coordinator = _coordinator(
        [_device("BAT_A"), _device("BAT_B")], [_entity("BAT_A"), _entity("BAT_B")],
    )
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert coordinator.api._battery_primary_ambiguous


def test_foreign_entity_association_cannot_select_primary():
    coordinator = _coordinator(
        [_device("BAT_A"), _device("BAT_B")],
        [_entity(entry="entry-B"), _entity("BAT_B", platform="other")],
    )
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn is None
    assert coordinator.api._battery_primary_ambiguous


@pytest.mark.parametrize("data", [
    {"primary_battery_dn": "OLD", "primary_battery_station_dn": "plant-2"},
    {"primary_battery_dn": "OLD"},
    {"primary_battery_dn": "", "primary_battery_station_dn": "plant-1"},
    {"primary_battery_dn": "unknown_battery", "primary_battery_station_dn": "plant-1"},
    {"primary_battery_dn": 123, "primary_battery_station_dn": "plant-1"},
])
def test_invalid_or_other_station_persistence_uses_safe_legacy_migration(data):
    coordinator = _coordinator([_device("BAT_A")], [_entity()], data=data)
    coordinator._restore_known_battery_dn()
    assert coordinator.api.battery_dn == "BAT_A"
    coordinator._persist_primary_battery_dn()
    assert coordinator.config_entry.data["primary_battery_dn"] == "BAT_A"


def test_successful_refresh_persists_identity_before_returning_devices():
    """Exercise the real refresh method with only API/forecast work faked out."""
    source = ast.parse(COORDINATOR_PATH.read_text(encoding="utf-8"))
    cls = next(node for node in source.body if isinstance(node, ast.ClassDef)
               and node.name == "FusionSolarCoordinator")
    update = next(node for node in cls.body if isinstance(node, ast.AsyncFunctionDef)
                  and node.name == "async_update_data")
    import asyncio
    import time

    namespace = {
        "FusionSolarAPIData": lambda controller_name, devices, forecast: SimpleNamespace(
            controller_name=controller_name, devices=devices, forecast=forecast
        ),
        "_LOGGER": logging.getLogger(__name__),
        "time": time,
    }
    exec(compile(ast.fix_missing_locations(ast.Module(body=[update], type_ignores=[])),
                 str(COORDINATOR_PATH), "exec"), namespace)
    coordinator = _coordinator()
    coordinator.api.connected = True
    coordinator.api.controller_name = DOMAIN

    async def ensure_station():
        pass

    async def fetch():
        coordinator.api.battery_dn = "BAT_A"
        return ["secondary only"]

    async def forecast(devices):
        assert coordinator.config_entry.data["primary_battery_dn"] == "BAT_A"
        return None

    coordinator._ensure_station_dn = ensure_station
    coordinator._fetch_devices_with_connection_retry = fetch
    coordinator._build_panel_production_forecast = forecast
    result = asyncio.run(namespace["async_update_data"](coordinator))
    assert result.devices == ["secondary only"]
