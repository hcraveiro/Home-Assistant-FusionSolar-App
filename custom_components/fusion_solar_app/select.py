"""Select entities for Fusion Solar App (charger working mode)."""

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api.charger import WORKING_MODES
from .const import DOMAIN
from .coordinator import FusionSolarCoordinator
from .sensor import _build_device_info

_LOGGER = logging.getLogger(__name__)

# live "Charger Working Mode" text -> config value
LIVE_TO_MODE = {"PV Power": "1", "PV Power Preferred": "1", "Normal Charge": "0", "Normal charge": "0"}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up the charger working mode select (only if a charger was found)."""
    coordinator: FusionSolarCoordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator
    if getattr(coordinator.api, "charger_connector_dn", None):
        async_add_entities([FusionSolarChargerWorkingModeSelect(coordinator)])


class FusionSolarChargerWorkingModeSelect(CoordinatorEntity, SelectEntity):
    """Charger working mode: Normal charge / PV Power Preferred."""

    _attr_icon = "mdi:leaf"
    _attr_options = list(WORKING_MODES.values())

    def __init__(self, coordinator: FusionSolarCoordinator) -> None:
        super().__init__(coordinator)
        self._pending: str | None = None
        self._device_stub = next(
            (d for d in coordinator.data.devices if d.device_id.startswith("Charger ")), None
        )

    @property
    def name(self) -> str:
        return "Charger Working Mode Setting"

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}-{self.coordinator.api.get_device_unique_id('Charger Working Mode Setting', 'select')}"

    @property
    def device_info(self):
        return _build_device_info(self.coordinator, self._device_stub)

    @property
    def current_option(self) -> str | None:
        if self._pending is not None:
            return WORKING_MODES[self._pending]
        live = self.coordinator.get_device_by_id("sensor_text", "Charger Working Mode")
        mode = LIVE_TO_MODE.get(str(getattr(live, "state", "")))
        return WORKING_MODES.get(mode) if mode is not None else None

    async def async_select_option(self, option: str) -> None:
        mode = next(k for k, v in WORKING_MODES.items() if v == option)
        ok = await self.hass.async_add_executor_job(self.coordinator.api.set_charger_working_mode, mode)
        if ok:
            self._pending = mode
            self.async_write_ha_state()
            await self.coordinator.async_request_refresh()

    def _handle_coordinator_update(self) -> None:
        live = self.coordinator.get_device_by_id("sensor_text", "Charger Working Mode")
        if self._pending is not None and LIVE_TO_MODE.get(str(getattr(live, "state", ""))) == self._pending:
            self._pending = None
        super()._handle_coordinator_update()
