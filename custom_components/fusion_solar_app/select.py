"""Select entities for Fusion Solar App (charger working mode)."""

import time

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api.charger import WORKING_MODES
from .const import DOMAIN
from .coordinator import FusionSolarCoordinator
from .sensor import build_charger_device_info

PENDING_TIMEOUT_SECONDS = 180


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
):
    """Set up the charger working mode select as soon as a charging connector is known."""
    coordinator: FusionSolarCoordinator = hass.data[DOMAIN][config_entry.entry_id].coordinator
    added = False

    @callback
    def _add_select() -> None:
        nonlocal added
        if not added and getattr(coordinator.api, "charger_connector_dn", None):
            added = True
            async_add_entities([FusionSolarChargerWorkingModeSelect(coordinator)])

    _add_select()
    config_entry.async_on_unload(coordinator.async_add_listener(_add_select))


class FusionSolarChargerWorkingModeSelect(CoordinatorEntity, SelectEntity):
    """Charger working mode: Normal charge / PV Power Preferred (connector config signal 20002)."""

    _attr_icon = "mdi:leaf"
    _attr_options = list(WORKING_MODES.values())
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: FusionSolarCoordinator) -> None:
        super().__init__(coordinator)
        self._pending: str | None = None
        self._pending_since = 0.0

    @property
    def name(self) -> str:
        return "Charger Working Mode Setting"

    @property
    def unique_id(self) -> str:
        return f"{DOMAIN}-{self.coordinator.api.get_device_unique_id('Charger Working Mode Setting', 'select')}"

    @property
    def device_info(self):
        return build_charger_device_info(self.coordinator)

    @property
    def current_option(self) -> str | None:
        mode = self._pending if self._pending is not None else self.coordinator.api.charger_working_mode_setting
        return WORKING_MODES.get(str(mode)) if mode is not None else None

    async def async_select_option(self, option: str) -> None:
        mode = next((k for k, v in WORKING_MODES.items() if v == option), None)
        if mode is None:
            raise HomeAssistantError(f"Unknown working mode: {option}")
        try:
            ok = await self.hass.async_add_executor_job(self.coordinator.api.set_charger_working_mode, mode)
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"Setting the charger working mode failed: {err}") from err
        if not ok:
            raise HomeAssistantError("FusionSolar did not accept the working mode change")
        self._pending, self._pending_since = mode, time.monotonic()
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()

    @callback
    def _handle_coordinator_update(self) -> None:
        if self._pending is not None:
            api = self.coordinator.api
            confirmed = api.charger_config_read_at > self._pending_since and api.charger_working_mode_setting == self._pending
            if confirmed or time.monotonic() - self._pending_since > PENDING_TIMEOUT_SECONDS:
                # confirmed by a read-back after the write, or timed out -> show the observed mode again
                self._pending = None
        super()._handle_coordinator_update()
