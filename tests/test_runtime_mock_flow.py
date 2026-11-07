"""Developer replay entry selection is explicit and cannot become real login."""

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from test_config_flow_behavior import config, hass  # noqa: F401
from test_api_lifecycle_behavior import api_module  # noqa: F401

PREFIX = "_fusion_solar_config_behavior"


@pytest.fixture
def mock_flow(config, hass, monkeypatch):
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "mock-entry"}
    flow.async_show_menu = Mock(side_effect=lambda **kwargs: {"type": "menu", **kwargs})
    flow._abort_if_unique_id_configured = Mock()
    profile = {
        "id": "demo", "title": "Example replay",
        "station": {"dn": "MOCK_RUNTIME_DEMO_STATION", "name": "MOCK demo"},
    }
    helper = SimpleNamespace(
        list_profiles=Mock(return_value={"demo": profile["title"]}),
        load_profile=Mock(return_value=profile),
    )
    monkeypatch.setitem(sys.modules, f"{PREFIX}.mock_profile", helper)
    monkeypatch.setenv("FUSIONSOLAR_DEV_PROFILE_DIR", "/fictional/developer-profiles")
    config.FusionSolarAPI.reset_mock()
    return flow, helper, profile


@pytest.mark.asyncio
async def test_optin_shows_menu_and_normal_account_remains_available(mock_flow, config):
    flow, _, _ = mock_flow
    result = await flow.async_step_user()
    assert result["type"] == "menu"
    assert result["menu_options"] == ["account", "mock"]
    result = await flow.async_step_account()
    assert result["type"] == "form" and result["step_id"] == "user"
    config.FusionSolarAPI.assert_not_called()


@pytest.mark.asyncio
async def test_mock_creates_separate_entry_without_credentials_or_login(mock_flow, config):
    flow, helper, profile = mock_flow
    result = await flow.async_step_mock({"mock_profile": "demo"})
    assert result["type"] == "create_entry"
    assert result["title"] == "MOCK — Example replay"
    assert result["data"] == {
        "mock_profile": "demo", "username": "mock-demo", "password": "unused",
        "fusion_solar_host": "example.invalid", "station_dn": profile["station"]["dn"],
    }
    assert flow.unique_id_set == "mock:demo"
    flow._abort_if_unique_id_configured.assert_called_once()
    config.FusionSolarAPI.assert_not_called()
    helper.load_profile.assert_called_once_with("demo")


@pytest.mark.asyncio
async def test_user_input_can_explicitly_select_mock_but_not_bypass_guard(mock_flow, config):
    flow, helper, _ = mock_flow
    helper.list_profiles.return_value = {}
    result = await flow.async_step_user({"mock_profile": "demo"})
    assert result == {"type": "abort", "reason": "mock_disabled"}
    config.FusionSolarAPI.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_profile_does_not_create_an_entry_or_real_api(mock_flow, config):
    flow, helper, _ = mock_flow
    result = await flow.async_step_mock({"mock_profile": "../real-account"})
    assert result["type"] == "form"
    assert result["errors"] == {"base": "mock_profile_invalid"}
    helper.load_profile.assert_not_called()
    config.FusionSolarAPI.assert_not_called()


@pytest.mark.asyncio
async def test_mock_reconfigure_and_reauth_cannot_open_account_login(mock_flow, config, hass):
    flow, _, _ = mock_flow
    hass.config_entries.async_get_entry.return_value = SimpleNamespace(data={"mock_profile": "demo"})
    result = await flow.async_step_reconfigure({"username": "real-user"})
    assert result["reason"] == "mock_account_action_forbidden"
    result = await flow.async_step_reauth({"mock_profile": "demo"})
    assert result["reason"] == "mock_account_action_forbidden"
    config.FusionSolarAPI.assert_not_called()
