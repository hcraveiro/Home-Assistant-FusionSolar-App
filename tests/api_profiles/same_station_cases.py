"""Same-station regression cases, imported only by the actual-HA checker."""
import tempfile
from unittest.mock import patch


def require(condition, message):
    if not condition:
        raise AssertionError(message)


async def setup(hass, entry):
    from homeassistant.config_entries import ConfigEntryState
    if entry.state is not ConfigEntryState.LOADED:
        require(await hass.config_entries.async_setup(entry.entry_id), "Setup failed")
    await hass.async_block_till_done()


def device_snapshot(hass, entry):
    from homeassistant.helpers import device_registry as dr
    return {device.id: (device.identifiers, device.via_device_id, device.name_by_user,
                        device.area_id, device.disabled_by, device.labels)
            for device in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)}


def validate_pair(hass, entries):
    from homeassistant.helpers import device_registry as dr, entity_registry as er
    from custom_components.fusion_solar_app.identity import legacy_device_identifier
    import check_lifecycle_homeassistant as check
    all_uids, all_identifiers = set(), set()
    result = []
    for entry in entries:
        coord = check.coordinator(hass, entry)
        entities = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
        devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
        require(len(entities) == 144 and len(devices) == 7,
                f"Coexistence counts: {len(entities)} entities / {len(devices)} devices")
        uids = {entity.unique_id for entity in entities}
        identifiers = {identifier for device in devices for identifier in device.identifiers}
        require(all_uids.isdisjoint(uids), "Entity unique IDs overlap")
        require(all_identifiers.isdisjoint(identifiers), "Device identifiers overlap")
        all_uids.update(uids)
        all_identifiers.update(identifiers)
        owned = {device.id for device in devices}
        require(all(entity.device_id in owned for entity in entities), "Entity device belongs to other entry")
        require(all(hass.states.get(entity.entity_id) is not None for entity in entities), "Entity not loaded")
        by_legacy = {legacy_device_identifier(entry, identifier): device
                     for device in devices for domain, identifier in device.identifiers
                     if domain == check.DOMAIN}
        prefix = f"{coord.api.controller_name}_{coord.api.station}"
        plant = by_legacy[prefix]
        for device in devices:
            if device.id != plant.id:
                require(device.via_device_id in owned, "Parent crosses account boundary or is missing")
        for battery, parent in coord.api._battery_parent_dns.items():
            child = by_legacy[f"{prefix}_battery_{battery}"]
            canonical = coord.api.inverters[parent].canonical_dn or parent
            require(child.via_device_id == by_legacy[f"{prefix}_inverter_{canonical}"].id,
                    "Battery attached to wrong physical inverter")
        for dn, meta in coord.api._optimizers.items():
            if f"{prefix}_optimizer_{dn}" not in by_legacy:
                continue
            parent = meta.get("parent_dn")
            canonical = coord.api.inverters[parent].canonical_dn or parent
            require(by_legacy[f"{prefix}_optimizer_{dn}"].via_device_id ==
                    by_legacy[f"{prefix}_inverter_{canonical}"].id, "Optimizer parent wrong")
        source = next(device for device in coord.data.devices if device.device_id == "Panel Production Today")
        entity_id = coord.native_forecast_builder._resolve_sensor_entity_id(source)
        registered = er.async_get(hass).async_get(entity_id) if entity_id else None
        require(registered is not None and registered.config_entry_id == entry.entry_id,
                "Recorder source lookup borrowed another account")
        require(not coord.api.unexpected_requests, "Undeclared offline HTTP")
        result.append({"entities": len(entities), "devices": len(devices), "recorder_source": entity_id})
    return result


async def check_same_station(report):
    import check_lifecycle_homeassistant as check
    from custom_components.fusion_solar_app.mock_profile import load_profile
    from homeassistant.helpers import device_registry as dr, entity_registry as er
    async with check.offline_account_boundary(load_profile(check.DUAL)):
        with tempfile.TemporaryDirectory(prefix="fusionsolar-two-accounts-", dir="/tmp") as directory:
            async with check.home(directory) as hass:
                first = await check.account_entry(hass, "MOCK_RUNTIME_ACCOUNT_A")
                initial = check.identities(hass, first)
                devices_before = device_snapshot(hass, first)
                second = await check.account_entry(hass, "MOCK_RUNTIME_ACCOUNT_B")
                require(check.identities(hass, first) == initial, "Adding B changed A's historic identities")
                require(device_snapshot(hass, first) == devices_before, "Adding B changed A's devices")
                rows = validate_pair(hass, (first, second))
                saved = [check.identities(hass, entry) for entry in (first, second)]
                devices_saved = [device_snapshot(hass, entry) for entry in (first, second)]
                entry_ids = [first.entry_id, second.entry_id]
                for entry in (second, first):
                    require(await hass.config_entries.async_reload(entry.entry_id), "Reverse reload failed")
                    await hass.async_block_till_done()
                require([check.identities(hass, entry) for entry in (first, second)] == saved,
                        "Reverse reload changed identities")
                # Actual options flow and synthetic reauth, including username change.
                result = await hass.config_entries.options.async_init(second.entry_id)
                result = await hass.config_entries.options.async_configure(result["flow_id"], {
                    "scan_interval": 180, "forecast_provider": "native",
                })
                require(result["type"] == "create_entry", "Options did not save")
                await hass.async_block_till_done()
                result = await hass.config_entries.flow.async_init(check.DOMAIN, context={
                    "source": "reauth", "entry_id": second.entry_id,
                }, data=dict(second.data))
                result = await hass.config_entries.flow.async_configure(result["flow_id"], {
                    "username": "MOCK_RUNTIME_ACCOUNT_B_REAUTH", "password": "MOCK_RUNTIME_REPLACED",
                    "fusion_solar_host": "example.invalid",
                })
                require(result["type"] == "abort" and result["reason"] == "reauth_successful", "Reauth failed")
                await hass.async_block_till_done()
                require([check.identities(hass, entry) for entry in (first, second)] == saved,
                        "Options/reauth changed identities")
                validate_pair(hass, (first, second))
                # A corrupted/stale mapping must fail closed rather than borrow history.
                coord = check.coordinator(hass, second)
                source = next(device for device in coord.data.devices if device.device_id == "Panel Production Today")
                original = coord.native_forecast_builder._resolve_sensor_entity_id(source)
                wrong = next(entity_id for entity_id, _, _, _ in saved[0] if entity_id.endswith("panel_production_today"))
                with patch.object(er.async_get(hass), "async_get_entity_id", return_value=wrong):
                    require(coord.native_forecast_builder._resolve_sensor_entity_id(source) is None,
                            "Recorder accepted wrong config-entry owner")
                require(original is not None, "Valid Recorder source missing")
            # Normal HA shutdown/store flush -> new HA, reverse setup order.
            async with check.home(directory) as hass:
                entries = [hass.config_entries.async_get_entry(entry_id) for entry_id in entry_ids]
                for entry in reversed(entries):
                    await setup(hass, entry)
                    await hass.async_block_till_done()
                validate_pair(hass, entries)
                require([check.identities(hass, entry) for entry in entries] == saved, "Restart changed IDs")
                require([device_snapshot(hass, entry) for entry in entries] == devices_saved, "Restart changed devices")
                # Remove primary. Secondary must never promote to newly-free raw IDs.
                require(await hass.config_entries.async_remove(entries[0].entry_id), "Remove A failed")
                await hass.async_block_till_done()
                require(await hass.config_entries.async_reload(entries[1].entry_id), "Reload surviving B failed")
                await hass.async_block_till_done()
                require(check.identities(hass, entries[1]) == saved[1], "Removing A changed B identities")
                require(device_snapshot(hass, entries[1]) == devices_saved[1], "Removing A changed B devices")
            async with check.home(directory) as hass:
                survivor = hass.config_entries.async_get_entry(entry_ids[1])
                require(await hass.config_entries.async_setup(survivor.entry_id), "Survivor restart failed")
                await hass.async_block_till_done()
                require(check.identities(hass, survivor) == saved[1], "Restart promoted surviving B")
        # Remove secondary separately and preserve primary, too.
        with tempfile.TemporaryDirectory(prefix="fusionsolar-remove-secondary-", dir="/tmp") as directory:
            async with check.home(directory) as hass:
                first = await check.account_entry(hass)
                second = await check.account_entry(hass, "MOCK_RUNTIME_ACCOUNT_B")
                saved_first = check.identities(hass, first)
                saved_devices = device_snapshot(hass, first)
                require(await hass.config_entries.async_remove(second.entry_id), "Remove B failed")
                require(await hass.config_entries.async_reload(first.entry_id), "Reload surviving A failed")
                await hass.async_block_till_done()
                require(check.identities(hass, first) == saved_first and
                        device_snapshot(hass, first) == saved_devices, "Removing B changed A")
        # A disabled/unloaded entry also reserves its assignment before B registers.
        from homeassistant.config_entries import ConfigEntry, ConfigEntryDisabler
        from types import MappingProxyType
        with tempfile.TemporaryDirectory(prefix="fusionsolar-disabled-owner-", dir="/tmp") as directory:
            async with check.home(directory) as hass:
                first = ConfigEntry(
                    version=1, minor_version=1, domain=check.DOMAIN, source="user",
                    title="MOCK_RUNTIME disabled A", unique_id="MOCK_RUNTIME_DISABLED_A",
                    data={"username": "MOCK_RUNTIME_ACCOUNT_A", "password": "unused",
                          "fusion_solar_host": "example.invalid",
                          "station_dn": load_profile(check.DUAL)["station"]["dn"]},
                    options={}, disabled_by=ConfigEntryDisabler.USER,
                    discovery_keys=MappingProxyType({}), subentries_data=[],
                )
                await hass.config_entries.async_add(first)
                second = await check.account_entry(hass, "MOCK_RUNTIME_ACCOUNT_B")
                require("ha_identity" in first.data, "Disabled entry was not assigned")
                saved_second = check.identities(hass, second)
                require(await hass.config_entries.async_set_disabled_by(first.entry_id, None), "Enable A failed")
                await hass.async_block_till_done()
                validate_pair(hass, (first, second))
                require(check.identities(hass, second) == saved_second, "Enabling A changed B")
        report.update(status="passed", accounts=2, counts=rows, unique_ids=288,
                      disabled_unloaded_entries_frozen=True,
                      reverse_reload=True, reauth_username_change=True, options=True,
                      fresh_ha_generations=3, remove_either_preserves_other=True,
                      recorder_entry_ownership=True, physical_topology=True)


async def check_mixed_owners(report):
    import check_lifecycle_homeassistant as check
    from custom_components.fusion_solar_app import identity, mock_api
    from custom_components import fusion_solar_app as integration
    from custom_components.fusion_solar_app.mock_profile import load_profile
    from homeassistant.helpers import device_registry as dr, entity_registry as er
    omitted = set()
    get_devices = mock_api.MockFusionSolarAPI.get_devices
    def partial(api):
        devices = get_devices(api)
        if api.user == "MOCK_RUNTIME_ACCOUNT_A":
            selected = [device for device in devices if device.device_id.startswith("Inverter ")][-1]
            omitted.add(selected.device_unique_id)
            return [device for device in devices if device.device_unique_id not in omitted]
        return devices
    async with check.offline_account_boundary(load_profile(check.DUAL)):
        with tempfile.TemporaryDirectory(prefix="fusionsolar-mixed-owners-", dir="/tmp") as directory:
            async with check.home(directory) as hass:
                # Reproduce a *pre-fix* partial-discovery registry using ordinary
                # HA flows/platform registration, not internal storage edits.
                with patch.object(integration, "prepare_identities", lambda *args: None), \
                     patch.object(mock_api.MockFusionSolarAPI, "get_devices", partial):
                    first = await check.account_entry(hass)
                    second = await check.account_entry(hass, "MOCK_RUNTIME_ACCOUNT_B")
                entries = (first, second)
                before = [check.identities(hass, entry) for entry in entries]
                require([len(rows) for rows in before] == [143, 1], "Mixed legacy fixture did not reproduce")
                registry = er.async_get(hass)
                child = registry.async_get(before[1][0][0])
                registry.async_update_entity(child.entity_id, name="User-owned secondary reading", icon="mdi:test-tube")
                dr.async_get(hass).async_update_device(child.device_id, name_by_user="User-owned secondary inverter")
                metadata_before = {entity.entity_id: check.metadata(entity)
                                   for entry in entries for entity in er.async_entries_for_config_entry(registry, entry.entry_id)}
                devices_before = [device_snapshot(hass, entry) for entry in entries]
                # Recover A's missing reading under the old identity layout: it
                # is still ignored because B owns that legacy ID. Keep A loaded
                # while B reloads, so changed resolver settings must reattach A's
                # formerly ignored counterpart rather than wait for a restart.
                await check.coordinator(hass, first).async_refresh()
                await hass.async_block_till_done()
                require(await hass.config_entries.async_unload(second.entry_id), "Legacy B unload failed")
                await setup(hass, second)
                await hass.async_block_till_done()
                rows = validate_pair(hass, entries)
                for entry, old_rows in zip(entries, before):
                    current = set(check.identities(hass, entry))
                    require(set(old_rows) <= current, "Migration renamed/reassigned/orphaned a historic entity")
                for entity_id, expected in metadata_before.items():
                    require(check.metadata(registry.async_get(entity_id)) == expected, "Migration changed entity metadata")
                for entry, old_devices in zip(entries, devices_before):
                    current = device_snapshot(hass, entry)
                    require(set(old_devices) <= set(current), "Migration recreated a device")
                    for device_id, old in old_devices.items():
                        require(current[device_id][1:] == old[1:], "Migration changed parent/user device metadata")
                saved = [check.identities(hass, entry) for entry in entries]
                for entry in reversed(entries):
                    require(await hass.config_entries.async_reload(entry.entry_id), "Mixed reverse reload failed")
                    await hass.async_block_till_done()
                require([check.identities(hass, entry) for entry in entries] == saved,
                        "Mixed reverse reload changed identities")
                entry_ids = [entry.entry_id for entry in entries]
                # Verify the primary counterpart of B's raw legacy ID is scoped.
                raw = before[1][0][1]
                require(identity.entity_unique_id(first, raw) != raw and
                        identity.entity_unique_id(second, raw) == raw, "Mixed legacy exception lost")
            async with check.home(directory) as hass:
                entries = [hass.config_entries.async_get_entry(entry_id) for entry_id in entry_ids]
                for entry in reversed(entries):
                    await setup(hass, entry)
                    await hass.async_block_till_done()
                validate_pair(hass, entries)
                require([check.identities(hass, entry) for entry in entries] == saved, "Mixed restart changed IDs")
                require(await hass.config_entries.async_remove(entries[1].entry_id), "Mixed remove B failed")
                require(await hass.config_entries.async_reload(entries[0].entry_id), "Mixed survivor reload failed")
                await hass.async_block_till_done()
                require(check.identities(hass, entries[0]) == saved[0], "Freed legacy ID promoted A counterpart")
        report.update(status="passed", before_counts=[143, 1], after_counts=rows,
                      historic_entities_preserved=144, device_ids_preserved=True,
                      user_metadata_preserved=True, reverse_reload=True, fresh_ha=True,
                      removal_does_not_promote_legacy_id=True)
