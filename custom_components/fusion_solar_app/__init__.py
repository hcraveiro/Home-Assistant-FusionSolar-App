"""Fusion Solar WebApp integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN
from .coordinator import FusionSolarCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


@dataclass
class RuntimeData:
    """Class to hold your data."""

    coordinator: DataUpdateCoordinator
    cancel_update_listener: Callable


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up Fusion Solar WebApp Integration from a config entry."""

    hass.data.setdefault(DOMAIN, {})

    # Initialise the coordinator that manages data updates from your api.
    # This is defined in coordinator.py
    coordinator = FusionSolarCoordinator(hass, config_entry)

    # Perform an initial data load from api.
    # async_config_entry_first_refresh() is special in that it does not log errors if it fails.
    # ConfigEntryAuthFailed will propagate up and trigger HA's reauth flow.
    await coordinator.async_config_entry_first_refresh()

    # Test to see if api initialised correctly, else raise ConfigNotReady to make HA retry setup
    if not coordinator.api.connected:
        raise ConfigEntryNotReady

    # Session is now live in memory — clear stale token from persistent storage
    if "dp_session" in config_entry.data:
        hass.config_entries.async_update_entry(
            config_entry,
            data={k: v for k, v in config_entry.data.items() if k not in ("dp_session", "data_host")},
        )

    # Migrate legacy station-scoped inverter entity unique IDs to DN-scoped
    # ones now that the inverter DNs are known. Must run before the sensor
    # platform is set up so existing entities keep their history.
    try:
        await _async_migrate_inverter_unique_ids(hass, config_entry, coordinator)
    except Exception as ex:  # migration must never block setup
        _LOGGER.warning("Inverter unique ID migration failed: %s", ex)

    # Initialise a listener for config flow options changes.
    # See config_flow for defining an options setting that shows up as configure on the integration.
    cancel_update_listener = config_entry.add_update_listener(_async_update_listener)

    # Add the coordinator and update listener to hass data to make
    # accessible throughout your integration
    # Note: this will change on HA2024.6 to save on the config entry.
    hass.data[DOMAIN][config_entry.entry_id] = RuntimeData(
        coordinator, cancel_update_listener
    )

    # Setup platforms (based on the list of entity types in PLATFORMS defined above)
    # This calls the async_setup method in each of your entity type files.
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    # Return true to denote a successful setup.
    return True


async def _async_migrate_inverter_unique_ids(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    coordinator: FusionSolarCoordinator,
) -> None:
    """Migrate legacy inverter entity unique IDs to DN-scoped unique IDs.

    Before multi-inverter support, inverter entities were keyed on the station
    only (``…_<station>_inverter_<signal>``). They now carry the inverter DN
    (``…_<station>_inv_<dn>_inverter_<signal>``). Existing entities belong to
    its registered Home Assistant device. Ambiguous multi-inverter identities
    are left untouched to protect dashboards and history.
    """
    api = coordinator.api
    inverter_dns = list(getattr(api, "inverters", {}))
    if not inverter_dns:
        return

    station_suffix = ""
    if api.station:
        station_suffix = f"_{api.sanitize_id_segment(api.station)}"

    old_prefix = f"{DOMAIN}-{api.controller_name}{station_suffix}_inverter_"
    registry = er.async_get(hass)
    devices = dr.async_get(hass)
    known_dns: dict[str, str] = {}
    identifier_prefix = f"{api.controller_name}_{api.station}_inverter_"

    for dn, info in api.inverters.items():
        known_dns[api.sanitize_id_segment(dn)] = dn
        canonical_dn = getattr(info, "canonical_dn", None)
        if canonical_dn:
            known_dns[api.sanitize_id_segment(canonical_dn)] = dn

    @callback
    def _legacy_inverter_dn(entity_entry: er.RegistryEntry) -> str | None:
        if entity_entry.device_id:
            device_entry = devices.async_get(entity_entry.device_id)
            if device_entry and config_entry.entry_id in device_entry.config_entries:
                for domain, identifier in device_entry.identifiers:
                    if domain != DOMAIN or not identifier.startswith(identifier_prefix):
                        continue
                    stored_dn = api.sanitize_id_segment(identifier[len(identifier_prefix):])
                    if stored_dn in known_dns:
                        return known_dns[stored_dn]

        # Safe fallback: there is no other inverter to accidentally claim
        # these entities, so a one-inverter plant can still migrate.
        if len(inverter_dns) == 1:
            return inverter_dns[0]

        return None

    @callback
    def _migrate(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
        if not entity_entry.unique_id.startswith(old_prefix):
            return None

        existing_dn = _legacy_inverter_dn(entity_entry)
        if existing_dn is None:
            _LOGGER.warning(
                "Skipping migration of %s: original inverter identity is ambiguous",
                entity_entry.entity_id,
            )
            return None

        registry = er.async_get(hass)
    devices = dr.async_get(hass)
    valid_dns = {api.sanitize_id_segment(dn): dn for dn in inverter_dns}

    @callback
    def _migrate(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
        if not entity_entry.unique_id.startswith(old_prefix):
            return None

        # Match the existing HA device to the inverter it represented before
        # multi-inverter discovery. The first flow node is not stable.
        matched_dn = None
        if entity_entry.device_id:
            device = devices.async_get(entity_entry.device_id)
            if device:
                for identifier_domain, identifier in device.identifiers:
                    if identifier_domain != DOMAIN:
                        continue
                    for safe_dn, original_dn in valid_dns.items():
                        if identifier.endswith(f"_inverter_{original_dn}"):
                            matched_dn = original_dn
                            break
                    if matched_dn:
                        break

        if matched_dn is None and len(inverter_dns) == 1:
            matched_dn = inverter_dns[0]

        if matched_dn is None:
            _LOGGER.warning(
                "Skipping ambiguous inverter migration for %s: no matching "
                "registered device DN; preserved original unique ID",
                entity_entry.entity_id,
            )
            return None

        new_prefix = (
            f"{DOMAIN}-{api.controller_name}{station_suffix}"
            f"_inv_{api.sanitize_id_segment(matched_dn)}_inverter_"
        )
        new_unique_id = new_prefix + entity_entry.unique_id[len(old_prefix):]
        if registry.async_get_entity_id(
            entity_entry.domain, entity_entry.platform, new_unique_id
        ):
            _LOGGER.warning(
                "Skipping migration of %s: unique ID %s is already registered",
                entity_entry.entity_id,
                new_unique_id,
            )
            return None

        return {"new_unique_id": new_unique_id}

    await er.async_migrate_entries(hass, config_entry.entry_id, _migrate)


async def _async_update_listener(hass: HomeAssistant, config_entry):
    """Handle config options update."""
    # Reload the integration when the options change.
    await hass.config_entries.async_reload(config_entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: ConfigEntry, device_entry: DeviceEntry
) -> bool:
    """Delete device if selected from UI."""
    # Adding this function shows the delete device option in the UI.
    # Remove this function if you do not want that option.
    # You may need to do some checks here before allowing devices to be removed.
    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # This is called when you remove your integration or shutdown HA.
    # If you have created any custom services, they need to be removed here too.

    # Remove the config options update listener
    hass.data[DOMAIN][config_entry.entry_id].cancel_update_listener()

    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(
        config_entry, PLATFORMS
    )

    # Remove the config entry from the hass data object.
    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    # Return that unloading was successful.
    return unload_ok
