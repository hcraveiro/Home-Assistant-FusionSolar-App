"""Developer-only scenario control; never registers for real/static entries."""
from __future__ import annotations

import asyncio
import os

import voluptuous as vol

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.service import async_register_admin_service

from .api import APIConnectionError
from .const import CONF_MOCK_PROFILE, DOMAIN
from .mock_api import MockFusionSolarAPI
from .mock_profile import PROFILE_DIR_ENV

SERVICE = "mock_scenario"
SCHEMA = vol.Schema({
    vol.Required("config_entry_id"): str,
    vol.Required("operation"): vol.In(("advance", "reset")),
}, extra=vol.PREVENT_EXTRA)


def register_mock_service(hass):
    """Called only after an opted-in transition entry has successfully loaded."""
    if hass.services.has_service(DOMAIN, SERVICE):
        return
    locks = {}

    async def handle(call):
        entry_id = call.data["config_entry_id"]
        async with locks.setdefault(entry_id, asyncio.Lock()):
            entry = hass.config_entries.async_get_entry(entry_id)
            runtime = hass.data.get(DOMAIN, {}).get(entry_id)
            if (not os.environ.get(PROFILE_DIR_ENV) or entry is None
                    or CONF_MOCK_PROFILE not in entry.data or runtime is None
                    or not isinstance(runtime.coordinator.api, MockFusionSolarAPI)
                    or not runtime.coordinator.api.mock_profile.get("frames")):
                raise HomeAssistantError("Only loaded, opted-in mock transition entries may be targeted")
            coordinator = runtime.coordinator
            if getattr(coordinator, "_shutdown_requested", False):
                raise HomeAssistantError("Mock entry is unloading")
            try:
                await hass.async_add_executor_job(coordinator.api.queue_frame, call.data["operation"])
            except (ValueError, APIConnectionError) as err:
                raise HomeAssistantError(str(err)) from err
            if getattr(coordinator, "_shutdown_requested", False):
                raise HomeAssistantError("Mock entry is unloading")
            # Bypass refresh debouncing: a blocking service call completes after
            # the real reader/coordinator poll (including declared failure).
            await coordinator.async_refresh()

    async_register_admin_service(hass, DOMAIN, SERVICE, handle, schema=SCHEMA)


def remove_mock_service_if_unused(hass):
    """No control surface remains once the last transition entry is unloaded."""
    if not any(isinstance(runtime.coordinator.api, MockFusionSolarAPI)
               and runtime.coordinator.api.mock_profile.get("frames")
               for runtime in hass.data.get(DOMAIN, {}).values()):
        hass.services.async_remove(DOMAIN, SERVICE)
