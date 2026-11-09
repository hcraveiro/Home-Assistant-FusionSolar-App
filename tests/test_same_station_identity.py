"""Pure identity-contract tests; actual-HA persistence coverage lives separately."""
from copy import deepcopy
import sys
from types import ModuleType, SimpleNamespace as NS

import pytest

from identity_test_support import identity_module

DOMAIN = "fusion_solar_app"


@pytest.fixture
def env(monkeypatch):
    identity = identity_module()
    entities, devices, updates = [], [], []
    entries = []
    def update(entry, *, data):
        updates.append((entry.entry_id, deepcopy(data)))
        entry.data = data
    def update_device(device_id, *, new_identifiers):
        device = next(device for device in devices if device.id == device_id)
        device.identifiers = new_identifiers
        return device
    helper = ModuleType("homeassistant.helpers")
    helper.entity_registry = NS(
        async_get=lambda hass: entities,
        async_entries_for_config_entry=lambda registry, entry_id: [e for e in registry if e.config_entry_id == entry_id],
    )
    helper.device_registry = NS(
        async_get=lambda hass: NS(devices=devices, async_update_device=update_device),
        async_entries_for_config_entry=lambda registry, entry_id: [d for d in registry.devices if d.config_entry_id == entry_id],
    )
    monkeypatch.setitem(sys.modules, "homeassistant.helpers", helper)
    hass = NS(config_entries=NS(async_entries=lambda domain: entries, async_update_entry=update))
    def entry(name, created=0, station="STATION"):
        item = NS(entry_id=name, created_at=created, data={"station_dn": station, "username": name}, options={})
        entries.append(item)
        return item
    def entity(owner, uid, created=0):
        item = NS(unique_id=uid, platform=DOMAIN, config_entry_id=owner.entry_id, created_at=created)
        entities.append(item)
        return item
    def device(owner, identifier, created=0):
        item = NS(id=f"device-{len(devices)}", config_entry_id=owner.entry_id,
                  identifiers={(DOMAIN, identifier)}, created_at=created,
                  name_by_user="User name", via_device_id="parent-kept")
        devices.append(item)
        return item
    return NS(identity=identity, hass=hass, entries=entries, entities=entities, devices=devices,
              updates=updates, entry=entry, entity=entity, device=device)


def test_same_station_defaults_are_frozen_independent_of_setup_order(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.identity.prepare_identities(env.hass, b)
    assert env.identity.entity_unique_id(a, "sensor") == "sensor"
    assert env.identity.entity_unique_id(b, "sensor") == "sensor__entry_B"
    assert env.identity.device_identifier(b, "plant") == "plant__entry_B"
    saved = deepcopy([entry.data for entry in env.entries])
    env.identity.prepare_identities(env.hass, a)
    assert [entry.data for entry in env.entries] == saved
    assert len(env.updates) == 2


def test_different_station_unchanged(env):
    for entry in (env.entry("A", station="ONE"), env.entry("B", station="TWO")):
        env.identity.prepare_identities(env.hass, entry)
        assert env.identity.entity_unique_id(entry, "sensor") == "sensor"
        assert env.identity.device_identifier(entry, "plant") == "plant"
    assert not env.updates


def test_registry_owner_not_older_disabled_entry_keeps_legacy_namespace(env):
    disabled = env.entry("disabled", 0)
    actual = env.entry("actual", 1)
    env.entity(actual, "old_sensor", 10)
    env.identity.prepare_identities(env.hass, disabled)
    assert env.identity.device_identifier(actual, "plant") == "plant"
    assert env.identity.entity_unique_id(actual, "old_sensor") == "old_sensor"
    assert env.identity.entity_unique_id(disabled, "old_sensor") == "old_sensor__entry_disabled"


def test_mixed_owners_preserve_both_and_scope_counterparts_permanently(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.entity(a, "reading_a", 10)
    env.entity(b, "reading_b", 11)
    old_device = env.device(b, "inverter")
    device_id = old_device.id
    env.identity.prepare_identities(env.hass, b)
    assert env.identity.entity_unique_id(a, "reading_a") == "reading_a"
    assert env.identity.entity_unique_id(b, "reading_b") == "reading_b"
    assert env.identity.entity_unique_id(a, "reading_b") == "reading_b__entry_A"
    assert env.identity.entity_unique_id(b, "reading_a") == "reading_a__entry_B"
    assert old_device.id == device_id and old_device.name_by_user == "User name"
    assert old_device.via_device_id == "parent-kept"
    assert old_device.identifiers == {(DOMAIN, "inverter__entry_B")}
    # Remove B (including its registries). A may not reuse B's now-free raw ID.
    env.entries.remove(b)
    env.entities[:] = [row for row in env.entities if row.config_entry_id != b.entry_id]
    env.devices.clear()
    env.identity.prepare_identities(env.hass, a)
    assert env.identity.entity_unique_id(a, "reading_b") == "reading_b__entry_A"


def test_secondary_never_promotes_after_primary_removal(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.identity.prepare_identities(env.hass, a)
    env.entries.remove(a)
    env.identity.prepare_identities(env.hass, b)
    assert env.identity.entity_unique_id(b, "reading") == "reading__entry_B"
    assert env.identity.device_identifier(b, "plant") == "plant__entry_B"


def test_device_migration_is_idempotent_and_finishes_partial_update(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.device(a, "primary", created=-1)
    one, two = env.device(b, "one"), env.device(b, "two")
    env.identity.prepare_identities(env.hass, a)
    two.identifiers = {(DOMAIN, "two")}  # Simulate interrupted device migration.
    before = len(env.updates)
    env.identity.prepare_identities(env.hass, b)
    assert len(env.updates) == before
    assert one.identifiers == {(DOMAIN, "one__entry_B")}
    assert two.identifiers == {(DOMAIN, "two__entry_B")}


def test_legacy_alias_is_persistent_and_inverse_is_shared_with_consumers(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.identity.prepare_identities(env.hass, a)
    env.identity.preserve_entity_id(env.hass, b, "new_inverter_signal", "legacy_inverter_signal")
    assert env.identity.entity_unique_id(b, "new_inverter_signal") == "legacy_inverter_signal"
    assert env.identity.legacy_entity_unique_id(b, "legacy_inverter_signal") == "new_inverter_signal"
    assert env.identity.legacy_device_identifier(b, "battery_DN__entry_B") == "battery_DN"
    saved = deepcopy(b.data)
    env.identity.prepare_identities(env.hass, b)
    assert b.data == saved


@pytest.mark.parametrize("identifier", ["plant", "inverter_master", "inverter_slave", "meter",
                                        "battery", "battery_module", "cluster", "optimizer"])
def test_all_device_kinds_share_one_scope_without_altering_api_ids(env, identifier):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.identity.prepare_identities(env.hass, a)
    assert env.identity.device_identifier(a, identifier) == identifier
    assert env.identity.device_identifier(b, identifier) == identifier + "__entry_B"
    assert env.identity.legacy_device_identifier(b, env.identity.device_identifier(b, identifier)) == identifier


def test_reauth_does_not_rederive_namespace_from_credentials(env):
    a, b = env.entry("A", 1), env.entry("B", 2)
    env.identity.prepare_identities(env.hass, b)
    saved = deepcopy(b.data[env.identity.IDENTITY_KEY])
    b.data = {**b.data, "username": "changed", "password": "changed", "fusion_solar_host": "changed.invalid"}
    env.identity.prepare_identities(env.hass, b)
    assert b.data[env.identity.IDENTITY_KEY] == saved
