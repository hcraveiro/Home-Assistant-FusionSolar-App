"""Service guard/control unit tests; actual HA registration is checked in Docker."""
import importlib
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest
import voluptuous as vol

from test_runtime_mock_transitions import fast_poll
from test_runtime_mock_api import runtime
from test_api_lifecycle_behavior import api_module, PREFIX


@pytest.fixture
def service(fast_poll, monkeypatch):
    loader, backend = fast_poll
    class HomeAssistantError(Exception):
        pass
    exceptions = sys.modules.get("homeassistant.exceptions", types.ModuleType("homeassistant.exceptions"))
    monkeypatch.setattr(exceptions, "HomeAssistantError", HomeAssistantError, raising=False)
    monkeypatch.setitem(sys.modules, "homeassistant.exceptions", exceptions)
    handlers = {}
    def register(hass, domain, name, handler, schema):
        handlers[name] = (handler, schema)
    monkeypatch.setitem(sys.modules, "homeassistant.helpers.service", types.SimpleNamespace(async_register_admin_service=register))
    monkeypatch.delitem(sys.modules, f"{PREFIX}.mock_service", raising=False)
    module = importlib.import_module(f"{PREFIX}.mock_service")
    api = backend.MockFusionSolarAPI(loader.load_profile("transitions-energy"))
    api.login()
    coordinator = types.SimpleNamespace(api=api, async_refresh=AsyncMock(side_effect=api.get_devices))
    hass = Mock()
    hass.data = {module.DOMAIN: {"mock": types.SimpleNamespace(coordinator=coordinator)}}
    entries = {"mock": types.SimpleNamespace(data={"mock_profile": "transitions-energy"}),
               "real": types.SimpleNamespace(data={"username": "fictional"})}
    hass.config_entries.async_get_entry.side_effect = entries.get
    hass.services.has_service.side_effect = lambda domain, name: name in handlers
    hass.services.async_remove.side_effect = lambda domain, name: handlers.pop(name, None)
    async def executor(method, *args):
        return method(*args)
    hass.async_add_executor_job = executor
    module.register_mock_service(hass)
    handler, schema = handlers[module.SERVICE]
    async def call(operation="advance", entry="mock", **extra):
        await handler(types.SimpleNamespace(data=schema({"operation": operation, "config_entry_id": entry, **extra})))
    yield module, hass, coordinator, handlers, call, HomeAssistantError
    api.close()


@pytest.mark.asyncio
async def test_service_refresh_reset_strict_guards_and_lifecycle(service, monkeypatch):
    module, hass, coordinator, handlers, call, error = service
    module.register_mock_service(hass)  # idempotent
    await call()
    assert coordinator.api.frame_id == "correction-34"
    assert coordinator.async_refresh.await_count == 1
    await call("reset")
    assert coordinator.api.frame_id == "valid-35"
    for target in ("real", "missing"):
        with pytest.raises(error, match="mock transition"):
            await call(entry=target)
    for args in ({"operation": "exec"}, {"unknown": "x"}):
        with pytest.raises(vol.Invalid):
            await call(**args)
    monkeypatch.delenv("FUSIONSOLAR_DEV_PROFILE_DIR")
    with pytest.raises(error):
        await call()
    module.remove_mock_service_if_unused(hass)
    assert module.SERVICE in handlers  # loaded transition still owns registration
    hass.data[module.DOMAIN].clear()
    module.remove_mock_service_if_unused(hass)
    assert module.SERVICE not in handlers


@pytest.mark.asyncio
async def test_service_rejects_static_mock_and_end_of_sequence(service):
    module, hass, coordinator, handlers, call, error = service
    coordinator.api.frame_index = len(coordinator.api.mock_profile["frames"]) - 1
    with pytest.raises(error, match="Final frame"):
        await call()
    coordinator.api.mock_profile.pop("frames")
    with pytest.raises(error, match="mock transition"):
        await call()
    module.remove_mock_service_if_unused(hass)
    assert module.SERVICE not in handlers


@pytest.mark.asyncio
async def test_service_rejects_shutdown_before_queueing(service):
    _, _, coordinator, _, call, error = service
    coordinator._shutdown_requested = True
    with pytest.raises(error, match="unloading"):
        await call()
    assert coordinator.api._pending_frame is None
    coordinator.async_refresh.assert_not_awaited()


@pytest.mark.asyncio
async def test_service_translates_closed_api_error(service):
    _, _, coordinator, _, call, error = service
    coordinator.api.close()
    with pytest.raises(error, match="closed"):
        await call()
    coordinator.async_refresh.assert_not_awaited()
