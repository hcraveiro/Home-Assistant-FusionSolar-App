"""Entry/flow cleanup regressions using the assembled production API lifecycle."""

import asyncio
import threading
from unittest.mock import AsyncMock, Mock

import pytest

from test_api_lifecycle_behavior import api_module
from test_config_flow_behavior import config, credentials, hass
from test_integration_entry_lifecycle import environment, integration


@pytest.fixture
def live_api(api_module):
    api = api_module.FusionSolarAPI("user", "password", "eu5", None)
    api.restore_session("transferred-token", "example.invalid")
    api.station = "station-1"
    api.station_name = "Solar plant"
    yield api
    api.close()


def executor_with_thread_check(home, api):
    """Use real executor threads and fail if session.close reaches the event loop."""
    event_loop_thread = threading.get_ident()
    original_close = api.session.close

    def close():
        assert threading.get_ident() != event_loop_thread
        original_close()

    api.session.close = Mock(side_effect=close)

    async def executor(method, *args):
        return await asyncio.to_thread(method, *args)

    home.async_add_executor_job = AsyncMock(side_effect=executor)
    return api.session.close


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["first_refresh", "platform_setup", "cancelled"])
async def test_failed_setup_closes_real_api_off_loop(integration, environment, live_api, failure):
    module, _, _ = integration
    home, entry, coordinator = environment
    coordinator.api = live_api
    close = executor_with_thread_check(home, live_api)
    error = asyncio.CancelledError() if failure == "cancelled" else RuntimeError("setup failed")
    target = (home.config_entries.async_forward_entry_setups
              if failure == "platform_setup" else coordinator.async_config_entry_first_refresh)
    target.side_effect = error

    with pytest.raises(type(error)):
        await module.async_setup_entry(home, entry)

    close.assert_called_once_with()
    assert live_api._closed
    assert not live_api.connected
    assert entry.entry_id not in home.data[module.DOMAIN]
    coordinator.async_shutdown.assert_awaited_once()
    if failure == "platform_setup":
        entry.add_update_listener.return_value.assert_called_once_with()


@pytest.mark.asyncio
async def test_unload_is_idempotent_and_closes_real_api_off_loop(integration, environment, live_api):
    module, _, _ = integration
    home, entry, coordinator = environment
    coordinator.api = live_api
    close = executor_with_thread_check(home, live_api)

    await module.async_setup_entry(home, entry)
    assert await module.async_unload_entry(home, entry)
    assert await module.async_unload_entry(home, entry)

    close.assert_called_once_with()
    coordinator.async_shutdown.assert_awaited_once()
    assert not live_api.connected


@pytest.mark.asyncio
async def test_flow_completion_closes_transport_but_token_transfers(
    config, hass, credentials, live_api, api_module, monkeypatch
):
    close = executor_with_thread_check(hass, live_api)
    live_api.login = Mock(return_value=True)
    live_api.get_station_list = Mock(return_value={
        "data": {"list": [{"dn": "station-1", "name": "Solar plant"}]}
    })
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=live_api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass

    assert (await flow.async_step_user(credentials))["step_id"] == "select_station"
    close.assert_not_called()
    result = await flow.async_step_select_station({config.CONF_STATION_DN: "station-1"})

    close.assert_called_once_with()
    assert flow._api is None
    assert not live_api.connected
    restored = api_module.FusionSolarAPI("user", "password", "eu5", None)
    try:
        restored.restore_session(result["data"]["dp_session"], result["data"]["data_host"])
        assert restored.connected
        assert restored.session.cookies.get("dp-session") == "transferred-token"
        assert restored.session is not live_api.session
    finally:
        restored.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", ["APIAuthError", "APIConnectionError", "unexpected"])
async def test_failed_flow_validation_closes_real_api(config, hass, credentials, live_api, error):
    close = executor_with_thread_check(hass, live_api)
    exception = RuntimeError if error == "unexpected" else getattr(config, error)
    live_api.login = Mock(side_effect=exception("failed"))
    expected = {"APIAuthError": config.InvalidAuth, "APIConnectionError": config.CannotConnect}

    with pytest.raises(expected.get(error, RuntimeError)):
        await config.validate_input(hass, credentials, live_api)

    close.assert_called_once_with()
    assert not live_api.connected


@pytest.mark.asyncio
async def test_external_flow_abort_closes_captcha_session(config, hass, live_api):
    close = executor_with_thread_check(hass, live_api)
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow._api = live_api
    pending = []
    hass.async_create_task.side_effect = lambda coro: pending.append(asyncio.create_task(coro))

    # HA's flow removal hook is a synchronous callback, not a coroutine.
    assert flow.async_remove() is None
    await asyncio.gather(*pending)
    flow.async_remove()

    assert len(pending) == 1
    close.assert_called_once_with()
    assert flow._api is None


@pytest.mark.asyncio
async def test_flow_abort_during_login_owns_and_closes_transport(
    config, hass, credentials, live_api, monkeypatch
):
    close = executor_with_thread_check(hass, live_api)
    entered = threading.Event()
    release = threading.Event()

    def login_transport():
        entered.set()
        assert release.wait(5)
        live_api.connected = True
        return True

    live_api._login_eu5 = Mock(side_effect=login_transport)
    live_api.get_station_list = Mock(return_value={
        "data": {"list": [{"dn": "station-1", "name": "Solar plant"}]}
    })
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=live_api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    pending = []
    hass.async_create_task.side_effect = lambda coro: pending.append(asyncio.create_task(coro))
    login = asyncio.create_task(flow.async_step_user(credentials))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        assert flow._api is live_api
        flow.async_remove()
    finally:
        release.set()
    await login
    await asyncio.gather(*pending)
    assert live_api._closed
    assert not live_api.connected
    close.assert_called_once_with()


@pytest.mark.asyncio
async def test_reauth_reload_failure_still_closes_transferred_session(config, hass, credentials, live_api):
    close = executor_with_thread_check(hass, live_api)
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    entry = Mock(entry_id="entry-1", data=dict(credentials, station_dn="station-1"))
    hass.config_entries.async_reload.side_effect = RuntimeError("reload failed")

    with pytest.raises(RuntimeError, match="reload failed"):
        await flow._finish_entry_update(entry, credentials, live_api)

    close.assert_called_once_with()
    saved = hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert saved["dp_session"] == "transferred-token"
    assert flow._api is None
