"""Regression tests for the real integration entry lifecycle.

These tests import the production __init__.py and isolate Home Assistant interfaces
with lightweight fakes. No calls to FusionSolar or live HA are performed.
"""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_entry_lifecycle"


@pytest.fixture(scope="module")
def integration():
    saved = {}

    def register(name, **attrs):
        saved[name] = sys.modules.get(name)
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        sys.modules[name] = module
        return module

    def package(name, path=None):
        mod = register(name)
        mod.__path__ = [str(path)] if path else []
        return mod

    package("homeassistant")
    register("homeassistant.config_entries", ConfigEntry=object)

    from enum import StrEnum

    class Platform(StrEnum):
        SENSOR = "sensor"

    register("homeassistant.const", Platform=Platform)
    register("homeassistant.core", HomeAssistant=object, callback=lambda fn: fn)

    class ConfigEntryNotReady(Exception):
        pass

    register("homeassistant.exceptions", ConfigEntryNotReady=ConfigEntryNotReady)
    package("homeassistant.helpers")
    register("homeassistant.helpers.device_registry", DeviceEntry=object, async_get=lambda hass: Mock())
    register("homeassistant.helpers.entity_registry", RegistryEntry=object, async_get=lambda hass: Mock(), async_migrate_entries=AsyncMock())
    register("homeassistant.helpers.update_coordinator", DataUpdateCoordinator=object)

    package(PREFIX, ROOT)
    register(f"{PREFIX}.const", DOMAIN="fusion_solar_app")
    mock_coordinator_class = Mock()
    register(f"{PREFIX}.coordinator", FusionSolarCoordinator=mock_coordinator_class)

    spec = importlib.util.spec_from_file_location(
        PREFIX, ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    target = importlib.util.module_from_spec(spec)
    saved[PREFIX] = sys.modules.get(PREFIX)
    sys.modules[PREFIX] = target
    spec.loader.exec_module(target)

    yield target, mock_coordinator_class, ConfigEntryNotReady

    for name, previous in reversed(list(saved.items())):
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


@pytest.fixture
def environment(integration):
    _, coordinator_class, _ = integration
    hass = Mock()
    hass.data = {}
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    hass.config_entries.async_reload = AsyncMock()

    entry = Mock()
    entry.entry_id = "entry-1"
    entry.data = {"username": "fake"}
    entry.add_update_listener.return_value = Mock()

    coordinator = Mock()
    coordinator.api.connected = True
    coordinator.async_config_entry_first_refresh = AsyncMock()
    coordinator_class.reset_mock()
    coordinator_class.return_value = coordinator
    return hass, entry, coordinator


@pytest.mark.asyncio
async def test_entry_setup_registers_runtime_and_platforms(integration, environment):
    module, coordinator_class, _ = integration
    hass, entry, coordinator = environment

    assert await module.async_setup_entry(hass, entry) is True

    coordinator_class.assert_called_once_with(hass, entry)
    coordinator.async_config_entry_first_refresh.assert_awaited_once()
    assert hass.data[module.DOMAIN][entry.entry_id].coordinator is coordinator
    entry.add_update_listener.assert_called_once()
    hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(
        entry, [module.PLATFORMS[0]]
    )


@pytest.mark.asyncio
async def test_stale_auth_session_is_cleared_only_after_success(integration, environment):
    module, _, _ = integration
    hass, entry, _ = environment
    entry.data = {
        "username": "fake", "dp_session": "expired-token",
        "data_host": "example.invalid", "station_dn": "station-1",
    }

    assert await module.async_setup_entry(hass, entry)
    changed = hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert changed == {"username": "fake", "station_dn": "station-1"}


@pytest.mark.asyncio
async def test_setup_rejects_disconnected_session_without_platform_forward(integration, environment):
    module, _, not_ready = integration
    hass, entry, coordinator = environment
    coordinator.api.connected = False
    entry.data = {"dp_session": "not-persisted-yet"}

    with pytest.raises(not_ready):
        await module.async_setup_entry(hass, entry)

    hass.config_entries.async_forward_entry_setups.assert_not_awaited()
    hass.config_entries.async_update_entry.assert_not_called()


@pytest.mark.asyncio
async def test_auth_failure_propagates_without_partial_setup(integration, environment):
    module, _, _ = integration
    hass, entry, coordinator = environment
    class AuthFailure(Exception):
        pass
    coordinator.async_config_entry_first_refresh.side_effect = AuthFailure("reauth")
    with pytest.raises(AuthFailure):
        await module.async_setup_entry(hass, entry)
    assert entry.entry_id not in hass.data[module.DOMAIN]
    entry.add_update_listener.assert_not_called()


@pytest.mark.asyncio
async def test_unload_success_removes_runtime(integration, environment):
    module, _, _ = integration
    hass, entry, _ = environment
    await module.async_setup_entry(hass, entry)
    cancel = entry.add_update_listener.return_value

    assert await module.async_unload_entry(hass, entry) is True

    cancel.assert_called_once()
    hass.config_entries.async_unload_platforms.assert_awaited_once_with(
        entry, module.PLATFORMS
    )
    assert entry.entry_id not in hass.data[module.DOMAIN]


@pytest.mark.asyncio
async def test_unload_failure_preserves_runtime(integration, environment):
    module, _, _ = integration
    hass, entry, _ = environment
    await module.async_setup_entry(hass, entry)
    hass.config_entries.async_unload_platforms.return_value = False

    assert await module.async_unload_entry(hass, entry) is False
    assert entry.entry_id in hass.data[module.DOMAIN]


@pytest.mark.asyncio
async def test_options_change_reloads_entry(integration, environment):
    module, _, _ = integration
    hass, entry, _ = environment
    await module._async_update_listener(hass, entry)
    hass.config_entries.async_reload.assert_awaited_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_device_removal_hook_returns_true(integration, environment):
    module, _, _ = integration
    hass, entry, _ = environment
    assert await module.async_remove_config_entry_device(hass, entry, Mock()) is True
