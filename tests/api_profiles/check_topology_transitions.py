"""Semantic assertions shared by isolated and actual development HA validation."""
from __future__ import annotations


async def check_topology_transitions(hass, entry, profile):
    from homeassistant.helpers import device_registry as dr, entity_registry as er

    domain = "fusion_solar_app"
    coordinator = hass.data[domain][entry.entry_id].coordinator
    api = coordinator.api
    registry = er.async_get(hass)
    previous = {}
    previous_devices = {}
    policies = {}
    report = []
    initial = None
    late_ids = set()
    pv_only = profile["id"] == "transitions-pv-meter"

    def require(ok, message):
        if not ok:
            raise AssertionError(message)

    def snapshot():
        entities = er.async_entries_for_config_entry(registry, entry.entry_id)
        devices = dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
        identities = {e.unique_id: (e.entity_id, e.device_id) for e in entities}
        owners = {tuple(sorted(d.identifiers)): (d.id, d.via_device_id) for d in devices}
        require(all(identities.get(k) == v for k, v in previous.items()), "Existing entity ID/owner changed")
        require(all(owners.get(k) == v for k, v in previous_devices.items()), "Existing device ID/parent changed")
        previous.update(identities)
        previous_devices.update(owners)
        return entities, devices

    for index, frame in enumerate(profile["frames"]):
        before = len(api.session.calls)
        await hass.services.async_call(domain, "mock_scenario", {
            "config_entry_id": entry.entry_id, "operation": "advance" if index else "reset",
        }, blocking=True)
        await hass.async_block_till_done()
        require(coordinator.last_update_success, "Partial topology must not fail whole coordinator")
        require(not api.unexpected_requests, f"Unmatched HTTP requests: {api.unexpected_requests}")
        require(len(api.session.calls) > before and api.frame_id == frame["id"], "No source HTTP transition")
        entities, devices = snapshot()
        if initial is None:
            require(len(entities) == (77 if pv_only else 144), "Unexpected initial entity topology")
            require(len(devices) == (3 if pv_only else 7), "Unexpected initial hardware count")
            initial = set(previous)
        states = {e.unique_id: hass.states.get(e.entity_id) for e in entities}
        require(all(s is not None for s in states.values()), "Missing HA state")
        for key, state in states.items():
            policy = tuple(state.attributes.get(k) for k in ("device_class", "state_class", "unit_of_measurement", "icon"))
            require(key not in policies or policies[key] == policy, f"Sensor policy changed: {key}")
            policies[key] = policy
        prefix = f"{api.controller_name}_{profile['station']['dn']}"
        by_identifier = {ident: d for d in devices for dom, ident in d.identifiers if dom == domain}
        plant = by_identifier[prefix]
        # Every runtime API sensor must be owned by its production Device metadata,
        # not by a guessed topological shape or the most recently visited inverter.
        for device in coordinator.data.devices:
            key = f"{domain}-{device.device_unique_id}"
            if key not in states:
                continue
            entity = registry.async_get(previous[key][0])
            require(entity.device_id in {d.id for d in devices}, f"Missing owner: {key}")
        source = {f"{domain}-{d.device_unique_id}": d for d in coordinator.data.devices}
        for key, state in states.items():
            if key.endswith(("-forecasted_today", "-remaining_today")):
                continue
            if key not in source or source[key].state is None:
                require(state.state == "unavailable", f"Absent/invalid HTTP source left stale telemetry: {key}")
        if pv_only:
            require(len(devices) == 3, f"Unexpected battery/optimizer registry: {len(devices)}")
            require(api.battery_dn is None and not api.battery_dns and api.battery_capacity == 0, "Fictitious storage metadata")
            meter = by_identifier[f"{prefix}_power_sensor_MOCK_RUNTIME_PV_METER_METER"]
            require(meter.via_device_id == plant.id and meter.model == "MOCK meter type", "Wrong meter metadata/plant parent")
            for suffix, expected in (("panel_production_power", [0, .4, 0][index]), ("power_sensor_active_power", [-.6, -.2, -.6][index])):
                matches = [(k, s) for k, s in states.items() if k.endswith(suffix)]
                require(len(matches) == 1 and float(matches[0][1].state) == expected, f"Wrong source value {suffix}: {matches}")
                require(matches[0][1].attributes.get("unit_of_measurement") == "kW", "Power units changed")
                if suffix.startswith("power_sensor"):
                    require(previous[matches[0][0]][1] == meter.id, "Meter reading wrongly owned")
            if index == 1:
                late_ids = set(previous) - initial
                require(late_ids, "Dawn did not discover late PV input sensors")
            if index == 2:
                for key in late_ids:
                    require(float(states[key].state) == 0, f"Night real zero lost: {key}")
        else:
            require(api.battery_dn == "MOCK_RUNTIME_TOPO_BAT_A", "Legacy primary changed on reordering")
            for dn in api.battery_dns:
                battery = by_identifier[f"{prefix}_battery_{dn}"]
                owner = by_identifier[f"{prefix}_inverter_MOCK_RUNTIME_TOPO_INV_A"]
                require(battery.via_device_id == owner.id, f"Wrong battery owner {dn}")
            for number, parent in ((1, "A"), (2, "B")):
                optimizer = by_identifier[f"{prefix}_optimizer_MOCK_RUNTIME_TOPO_OPT_{number}"]
                require(optimizer.via_device_id == by_identifier[f"{prefix}_inverter_MOCK_RUNTIME_TOPO_INV_{parent}"].id, "Optimizer owner changed")
            # Select all affected realtime/module/inverter/optimizer entities from
            # their true owner and sensor name, excluding legitimate cached config.
            affected = [e for e in entities if (
                ("mock_runtime_topo_bat_b" in e.unique_id and any(x in e.unique_id for x in ("battery_soc", "battery_module", "battery_state", "battery_charge_discharge_power")))
                or ("mock_runtime_topo_inv_b" in e.unique_id and any(x in e.unique_id for x in ("inverter_input", "inverter_output", "inverter_pv")))
                or ("mock_runtime_topo_opt_2" in e.unique_id and "optimizer" in e.unique_id)
            )]
            require(affected, "No partial-telemetry targets")
            for marker in ("mock_runtime_topo_bat_b", "mock_runtime_topo_inv_b", "mock_runtime_topo_opt_2"):
                require(any(marker in e.unique_id for e in affected), f"Missing partial coverage: {marker}")
            if index == 1:
                require(any(states[e.unique_id].state == "unavailable" for e in affected), "Partial snapshot left stale readings")
                for e in affected:
                    require(states[e.unique_id].state == "unavailable", f"Stale partial reading {e.unique_id}: {states[e.unique_id].state}")
            if index == 2:
                require(all(states[e.unique_id].state != "unavailable" for e in affected), "Recovery did not restore readings")
            if index == 3:
                late_ids = set(previous) - initial
                require(late_ids and len(devices) == 8, "Late third battery was not registered")
                require(all("mock_runtime_topo_bat_c" in k for k in late_ids), "Late battery duplicated old entities")
            if index == 4:
                require(set(previous) == initial | late_ids, "Reordering created duplicate entities")
        report.append({"frame": frame["id"], "entities": len(entities), "devices": len(devices),
                       "unavailable": sum(s.state == "unavailable" for s in states.values()),
                       "http_requests": len(api.session.calls) - before,
                       "existing_ids_and_owners_stable": True})
    await hass.services.async_call(domain, "mock_scenario", {
        "config_entry_id": entry.entry_id, "operation": "reset",
    }, blocking=True)
    await hass.async_block_till_done()
    snapshot()
    require(api.frame_index == 0 and coordinator.last_update_success, "Reset failed")
    # Registry persistence is intentional: do not delete transiently absent nodes.
    require(set(previous) == initial | late_ids, "Reset removed late-discovered identities")
    return report
