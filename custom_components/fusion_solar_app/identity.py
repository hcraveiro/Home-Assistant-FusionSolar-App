"""Persistent HA identities, independent of FusionSolar telemetry lookup keys.

All registry/config-entry operations here run synchronously on HA's event loop.
Assignment is frozen for the whole station (including unloaded/disabled entries)
without yielding, before any platform registration. No internal stores are edited.
"""
from __future__ import annotations

from .const import DOMAIN

IDENTITY_KEY = "ha_identity"


def _record(entry):
    data = getattr(entry, "data", {})
    if not isinstance(data, dict) and not hasattr(data, "get"):
        return {}
    record = data.get(IDENTITY_KEY, {})
    return record if isinstance(record, dict) else {}


def identity_signature(entry) -> tuple[str, dict[str, str]]:
    """Snapshot the effective resolver settings for update-listener decisions."""
    record = _record(entry)
    return record.get("namespace") or "", dict(record.get("entities", {}))


def _suffix(entry) -> str:
    return f"__entry_{entry.entry_id}"


def entity_unique_id(entry, legacy_id: str) -> str:
    """Resolve a HA unique ID, retaining explicit historical registry owners."""
    record = _record(entry)
    return record.get("entities", {}).get(
        legacy_id, legacy_id + (record.get("namespace") or "")
    )


def legacy_entity_unique_id(entry, unique_id: str) -> str:
    """Recover the API-era key for registry consumers (not runtime API lookups)."""
    for legacy, registered in _record(entry).get("entities", {}).items():
        if registered == unique_id:
            return legacy
    return unique_id.removesuffix(_suffix(entry))


def device_identifier(entry, legacy_id: str) -> str:
    """Scope physical device identifiers, independently of entity exceptions."""
    return legacy_id + (_record(entry).get("namespace") or "")


def legacy_device_identifier(entry, identifier: str) -> str:
    return identifier.removesuffix(_suffix(entry))


def preserve_entity_id(hass, entry, legacy_id: str, registered_id: str) -> None:
    """Persist a runtime-key alias instead of renaming a historical entity."""
    record = _record(entry)
    if record.get("entities", {}).get(legacy_id) == registered_id:
        return
    entities = {**record.get("entities", {}), legacy_id: registered_id}
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, IDENTITY_KEY: {**record, "entities": entities}}
    )


def prepare_identities(hass, entry) -> None:
    """Freeze defaults and exceptions from registry ownership, never load order.

    An existing primary keeps raw IDs. Every other entry gets its immutable
    config-entry suffix. Existing raw entities remain with *their own* entry,
    even when old partial discovery split legacy ownership across accounts.
    Explicit mappings are monotonic: removing an account never frees/promotes
    another account's scoped counterpart back to a raw unique ID.
    """
    from homeassistant.helpers import device_registry as dr, entity_registry as er

    station = entry.data.get("station_dn")
    if not isinstance(station, str) or not station:
        return
    entries = hass.config_entries.async_entries(DOMAIN)
    # Identity is station based: usernames/hosts may change during reauth.
    entries = [candidate for candidate in entries if candidate.data.get("station_dn") == station]
    if len(entries) < 2 and not _record(entry):
        return  # Single/different-station installations remain byte-for-byte legacy.
    entries.sort(key=lambda candidate: (candidate.created_at, candidate.entry_id))
    records = {candidate.entry_id: _record(candidate) for candidate in entries}
    frozen_primary = next((candidate for candidate in entries
                           if records[candidate.entry_id].get("namespace") == ""), None)
    registry = er.async_get(hass)
    devices = dr.async_get(hass)
    owned = {}
    historical_owners = []
    for candidate in entries:
        entities = [entity for entity in er.async_entries_for_config_entry(registry, candidate.entry_id)
                    if entity.platform == DOMAIN]
        owned[candidate.entry_id] = {
            entity.unique_id.removesuffix(_suffix(candidate)): entity.unique_id
            for entity in entities
        }
        for entity in entities:
            historical_owners.append((entity.created_at, candidate.entry_id, candidate))
    if not historical_owners:
        for candidate in entries:
            for device in dr.async_entries_for_config_entry(devices, candidate.entry_id):
                historical_owners.append((device.created_at, candidate.entry_id, candidate))
    # A disabled older config entry must not displace an actual registry owner.
    primary = frozen_primary or (min(historical_owners, key=lambda row: row[:2])[2]
                                 if historical_owners else entries[0])
    # Persist all entries before registration, using fresh data each time and no
    # await points. async_update_entry owns durability and listener notification.
    for candidate in entries:
        record = records[candidate.entry_id]
        namespace = record.get("namespace", "" if candidate is primary else _suffix(candidate))
        mappings = dict(record.get("entities", {}))
        for legacy, registered in owned[candidate.entry_id].items():
            if registered != legacy + namespace:
                mappings.setdefault(legacy, registered)
        if not namespace:
            for other in entries:
                if other is candidate:
                    continue
                for legacy, registered in owned[other.entry_id].items():
                    if legacy == registered and legacy not in owned[candidate.entry_id]:
                        mappings.setdefault(legacy, legacy + _suffix(candidate))
        updated = {"version": 1, "station": station, "namespace": namespace, "entities": mappings}
        if updated != record:
            hass.config_entries.async_update_entry(
                candidate, data={**candidate.data, IDENTITY_KEY: updated}
            )
    # Device registry IDs and all user metadata/parent references stay intact.
    # This also finishes an interrupted migration after metadata was persisted.
    for candidate in entries:
        namespace = _record(candidate).get("namespace")
        if not namespace:
            continue
        for device in dr.async_entries_for_config_entry(devices, candidate.entry_id):
            identifiers = {
                (domain, identifier if identifier.endswith(namespace) else identifier + namespace)
                if domain == DOMAIN else (domain, identifier)
                for domain, identifier in device.identifiers
            }
            if identifiers != device.identifiers:
                devices.async_update_device(device.id, new_identifiers=identifiers)
