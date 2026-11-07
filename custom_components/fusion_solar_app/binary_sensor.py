"""Verified read-only iSitePower-M mains connectivity."""
from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .identity import device_identifier, entity_unique_id
from .sensor import _parent_device_link


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id].coordinator
    added = False

    @callback
    def discover():
        nonlocal added
        if (not added and getattr(coordinator.api, "_mains_verified", False)
                and type(getattr(coordinator.api, "_mains_state", None)) is bool):
            added = True
            async_add_entities([FusionSolarMains(coordinator)])

    entry.async_on_unload(coordinator.async_add_listener(discover))
    discover()


class FusionSolarMains(CoordinatorEntity, BinarySensorEntity):
    """On is Mains On, Off is explicit Mains Off; failures are unavailable."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_has_entity_name = True
    _attr_name = "Mains State"

    def __init__(self, coordinator):
        super().__init__(coordinator)
        api = coordinator.api
        station = api.station
        controller = api.controller_name
        entry = coordinator.config_entry
        self._attr_unique_id = entity_unique_id(entry, f"{controller}_{station}_mains_state")
        plant = (DOMAIN, device_identifier(entry, f"{controller}_{station}"))
        self._attr_device_info = {
            "name": "iSitePower-M Mains", "manufacturer": "Huawei", "model": "iSitePower-M Mains",
            "identifiers": {(DOMAIN, device_identifier(entry, f"{controller}_{station}_mains"))},
            **_parent_device_link(getattr(coordinator, "_plant_device_registry_id", None), plant),
        }

    @property
    def available(self):
        api = self.coordinator.api
        return (super().available and getattr(api, "_mains_verified", False)
                and type(getattr(api, "_mains_state", None)) is bool)

    @property
    def is_on(self):
        return getattr(self.coordinator.api, "_mains_state", None)
