"""Run the production configuration flow against simulated HA interfaces.

Mock only Home Assistant and FusionSolar network boundaries, not methods under test.
"""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusion_solar_config_behavior"


@pytest.fixture(scope="module")
def config():
    originals = {}

    def mod(name, **attrs):
        originals[name] = sys.modules.get(name)
        instance = types.ModuleType(name)
        instance.__dict__.update(attrs)
        sys.modules[name] = instance
        return instance

    def pkg(name, directory=None):
        instance = mod(name)
        instance.__path__ = [str(directory)] if directory else []
        return instance

    pkg("homeassistant")
    class BaseFlow:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__()
        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}
        def async_create_entry(self, **kwargs):
            return {"type": "create_entry", **kwargs}
        def async_abort(self, **kwargs):
            return {"type": "abort", **kwargs}
        async def async_set_unique_id(self, value, **kwargs):
            self.unique_id_set = value
    mod("homeassistant.config_entries", ConfigEntry=object,
        ConfigFlow=BaseFlow, ConfigFlowResult=dict, OptionsFlow=BaseFlow)
    mod("homeassistant.const", CONF_USERNAME="username",
        CONF_PASSWORD="password", CONF_SCAN_INTERVAL="scan_interval")
    mod("homeassistant.core", HomeAssistant=object, callback=lambda func: func)
    class HAError(Exception):
        pass
    mod("homeassistant.exceptions", HomeAssistantError=HAError)
    pkg("homeassistant.helpers")
    class SelectorConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
    class Selector:
        def __init__(self, config):
            self.config = config
        def __call__(self, value):
            return value
    mod("homeassistant.helpers.selector", EntitySelector=Selector,
        EntitySelectorConfig=SelectorConfig, SelectSelector=Selector,
        SelectSelectorConfig=SelectorConfig,
        SelectSelectorMode=types.SimpleNamespace(DROPDOWN="dropdown"))
    pkg(PREFIX, ROOT)
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.const", ROOT / "const.py")
    constants = importlib.util.module_from_spec(spec)
    originals[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = constants
    spec.loader.exec_module(constants)

    class APIAuthError(Exception):
        pass
    class APIConnectionError(Exception):
        pass
    class APIAuthCaptchaError(Exception):
        pass
    fake_api = Mock()
    mod(f"{PREFIX}.api", FusionSolarAPI=fake_api,
        APIAuthError=APIAuthError, APIConnectionError=APIConnectionError,
        APIAuthCaptchaError=APIAuthCaptchaError)
    spec = importlib.util.spec_from_file_location(
        f"{PREFIX}.config_flow", ROOT / "config_flow.py")
    target = importlib.util.module_from_spec(spec)
    originals[spec.name] = sys.modules.get(spec.name)
    sys.modules[spec.name] = target
    spec.loader.exec_module(target)
    yield target
    for key, old in reversed(list(originals.items())):
        if old is None:
            sys.modules.pop(key, None)
        else:
            sys.modules[key] = old


@pytest.fixture
def hass():
    home = Mock()
    async def executor(method, *args):
        return method(*args)
    home.async_add_executor_job = AsyncMock(side_effect=executor)
    home.config_entries.async_reload = AsyncMock()
    return home


@pytest.fixture
def credentials(config):
    return {"username": "user", "password": "example", config.FUSION_SOLAR_HOST: "eu5.fusionsolar.huawei.com"}


@pytest.fixture
def api():
    instance = Mock()
    instance.connected = True
    instance.station = "station-1"
    instance.station_name = "Solar plant"
    instance.dp_session = "dummy-session"
    instance.data_host = "example.invalid"
    instance.get_station_list.return_value = {
        "data": {"list": [{"dn": "station-1", "name": "Solar plant"},
                          {"dn": "station-2", "name": "Second plant"}]}}
    return instance


@pytest.mark.parametrize("details,expected", [
    ({"name": "Plant", "dn": "station"}, "Plant"),
    ({"stationName": "Alternate", "dn": "station"}, "Alternate"),
    ({"dn": "station"}, "station"),
    ({}, "Unknown station"),
])
def test_station_display_fallbacks(config, details, expected):
    assert config._get_station_display_name(details) == expected


@pytest.mark.asyncio
async def test_validate_input_reuses_api_and_strips_captcha(config, hass, credentials, api):
    payload = dict(credentials, captcha_input=" 1234 ", station_dn="station-2")
    info, updated = await config.validate_input(hass, payload, api)
    assert updated is api
    assert api.captcha_input == "1234"
    assert api.station == "station-2"
    assert info["title"] == "user - Solar plant"
    api.login.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("error,expected", [
    ("APIAuthError", "InvalidAuth"),
    ("APIConnectionError", "CannotConnect"),
    ("APIAuthCaptchaError", "InvalidCaptcha"),
])
async def test_validate_input_classifies_login_errors(config, hass, credentials, api, error, expected):
    api.login.side_effect = getattr(config, error)("failure")
    with pytest.raises(getattr(config, expected)):
        await config.validate_input(hass, credentials, api)


@pytest.mark.asyncio
async def test_new_user_flow_selects_station(config, hass, credentials, api, monkeypatch):
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    form = await flow.async_step_user(credentials)
    assert form["step_id"] == "select_station"
    entry = await flow.async_step_select_station({config.CONF_STATION_DN: "station-2"})
    assert entry["type"] == "create_entry"
    assert entry["data"][config.CONF_STATION_DN] == "station-2"
    assert entry["data"]["dp_session"] == "dummy-session"
    assert flow.unique_id_set == "user@station-2"
    assert entry["title"] == "user - Second plant"


@pytest.mark.asyncio
async def test_initial_captcha_is_requested(config, hass, credentials, api, monkeypatch):
    api.login.side_effect = config.APIAuthCaptchaError("captcha")
    api.captcha_img = "data:image/png;base64,example"
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    form = await flow.async_step_user(credentials)
    assert form["step_id"] == "captcha"
    assert "captcha_img" in form["description_placeholders"]


@pytest.mark.asyncio
async def test_invalid_password_creates_user_form_error(config, hass, credentials, api, monkeypatch):
    api.login.side_effect = config.APIAuthError("invalid")
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    form = await flow.async_step_user(credentials)
    assert form["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_station_list_failure_preserves_setup_form(config, hass, credentials, api, monkeypatch):
    api.get_station_list.side_effect = RuntimeError("cloud error")
    monkeypatch.setattr(config, "FusionSolarAPI", Mock(return_value=api))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    result = await flow.async_step_user(credentials)
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_reauth_updates_session_and_reloads(config, hass, credentials, api):
    entry = Mock()
    entry.entry_id = "entry-1"
    entry.data = dict(credentials, station_dn="station-1")
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    result = await flow._finish_entry_update(entry, credentials, api)
    assert result == {"type": "abort", "reason": "reauth_successful"}
    updated = hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert updated["dp_session"] == "dummy-session"
    assert updated[config.CONF_STATION_DN] == "station-1"
    hass.config_entries.async_reload.assert_awaited_once_with("entry-1")


@pytest.mark.asyncio
async def test_missing_reconfigure_entry_aborts(config, hass):
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {}
    assert (await flow.async_step_reconfigure())["reason"] == "missing_entry_id"
    flow.context = {"entry_id": "missing"}
    hass.config_entries.async_get_entry.return_value = None
    assert (await flow.async_step_reconfigure())["reason"] == "config_entry_not_found"


@pytest.mark.asyncio
async def test_options_native_clears_previous_solcast(config, hass):
    entry = Mock()
    entry.options = {
        config.CONF_FORECAST_PROVIDER: config.FORECAST_PROVIDER_SOLCAST,
        config.CONF_SOLCAST_FORECAST_TODAY_ENTITY: "sensor.old",
    }
    handler = config.FusionSolarOptionsFlowHandler(entry)
    handler.hass = hass
    result = await handler.async_step_init({
        "scan_interval": 60,
        config.CONF_FORECAST_PROVIDER: config.FORECAST_PROVIDER_NATIVE,
    })
    assert result["type"] == "create_entry"
    assert config.CONF_SOLCAST_FORECAST_TODAY_ENTITY not in result["data"]


@pytest.mark.asyncio
async def test_options_solcast_rejects_invalid_entity(config, hass):
    entry = Mock()
    entry.options = {}
    handler = config.FusionSolarOptionsFlowHandler(entry)
    handler.hass = hass
    hass.states.get.return_value = None
    assert (await handler.async_step_init({
        config.CONF_FORECAST_PROVIDER: config.FORECAST_PROVIDER_SOLCAST
    }))["step_id"] == "solcast"
    result = await handler.async_step_solcast({
        config.CONF_SOLCAST_FORECAST_TODAY_ENTITY: "sensor.bad"
    })
    assert result["errors"]["base"] == "invalid_solcast_entity"


@pytest.mark.asyncio
async def test_options_solcast_accepts_hourly_forecast(config, hass):
    entry = Mock()
    entry.options = {}
    handler = config.FusionSolarOptionsFlowHandler(entry)
    handler.hass = hass
    hass.states.get.return_value = types.SimpleNamespace(
        attributes={"detailedHourly": [
            {"period_start": "2026-10-25T09:00:00+00:00", "pv_estimate": 1.2}]})
    await handler.async_step_init({
        config.CONF_FORECAST_PROVIDER: config.FORECAST_PROVIDER_SOLCAST
    })
    result = await handler.async_step_solcast({
        config.CONF_SOLCAST_FORECAST_TODAY_ENTITY: "sensor.solcast"
    })
    assert result["type"] == "create_entry"
    assert result["data"][config.CONF_SOLCAST_FORECAST_TODAY_ENTITY] == "sensor.solcast"


@pytest.mark.parametrize("samples,expected", [
    ([], False),
    ([{"period_start": "2026-10-25T09:00:00Z"}], False),
    ([{"pv_estimate": 1.2}], False),
    ([None, {"period_start": "2026-10-25T09:00:00Z", "pv_estimate": 0}], True),
])
def test_solcast_attribute_schema(config, hass, samples, expected):
    entry = Mock()
    entry.options = {}
    flow = config.FusionSolarOptionsFlowHandler(entry)
    flow.hass = hass
    hass.states.get.return_value = types.SimpleNamespace(attributes={"detailedHourly": samples})
    assert flow._is_valid_solcast_forecast_entity("sensor.solcast") == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("source,expected", [
    ("reauth", "reauth_successful"),
    ("reconfigure", "reconfigure_successful"),
])
async def test_captcha_completion_updates_existing_entry(
    config, hass, credentials, api, source, expected
):
    """A successful CAPTCHA must update credentials without creating a second entry."""
    entry = Mock()
    entry.entry_id = "existing-entry"
    entry.data = dict(credentials, station_dn="plant-1")
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"source": source}
    flow._target_entry = entry
    flow._api = api
    flow._captcha_credentials = dict(credentials, station_dn="plant-1")
    api.captcha_img = "data:image/png;base64,test"

    result = await flow.async_step_captcha({config.CAPTCHA_INPUT: " 9876 "})

    assert result == {"type": "abort", "reason": expected}
    assert api.captcha_input == "9876"
    api.get_station_list.assert_not_called()
    hass.config_entries.async_reload.assert_awaited_once_with("existing-entry")
    stored = hass.config_entries.async_update_entry.call_args.kwargs["data"]
    assert stored[config.CONF_STATION_DN] == "plant-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("error_name,expected", [
    ("APIAuthCaptchaError", "invalid_captcha"),
    ("APIAuthError", "invalid_auth"),
    ("APIConnectionError", "cannot_connect"),
])
async def test_captcha_error_does_not_update_credentials(
    config, hass, credentials, api, error_name, expected
):
    """Invalid challenge and transport errors must not mutate the config entry."""
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"source": "reauth"}
    flow._api = api
    flow._captcha_credentials = credentials
    flow._target_entry = Mock(entry_id="existing-entry", data={})
    api.captcha_img = ""
    api.login.side_effect = getattr(config, error_name)("challenge failed")

    result = await flow.async_step_captcha({config.CAPTCHA_INPUT: "0000"})

    assert result["step_id"] == "captcha"
    assert result["errors"]["base"] == expected
    hass.config_entries.async_update_entry.assert_not_called()
    hass.config_entries.async_reload.assert_not_awaited()


@pytest.mark.asyncio
async def test_captcha_flow_without_saved_credentials_returns_to_login(config, hass):
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow._api = None
    flow._captcha_credentials = None

    result = await flow.async_step_captcha({config.CAPTCHA_INPUT: "1234"})

    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "unknown"


@pytest.mark.asyncio
async def test_captcha_initial_setup_fetches_stations_after_success(config, hass, credentials, api):
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow._api = api
    flow._captcha_credentials = credentials
    flow._target_entry = None
    api.captcha_img = ""

    result = await flow.async_step_captcha({config.CAPTCHA_INPUT: " 1234 "})

    assert result["step_id"] == "select_station"
    assert flow._stations[0]["dn"] == "station-1"
    assert api.captcha_input == "1234"


@pytest.mark.xfail(strict=True, reason="Known Config Flow bug: station fetch failure is overwritten as invalid_captcha")
@pytest.mark.asyncio
async def test_captcha_initial_setup_station_fetch_failure_is_recoverable(
    config, hass, credentials, api
):
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow._api = api
    flow._captcha_credentials = credentials
    flow._target_entry = None
    api.captcha_img = ""
    api.get_station_list.side_effect = RuntimeError("station endpoint offline")

    result = await flow.async_step_captcha({config.CAPTCHA_INPUT: "1234"})

    assert result["step_id"] == "captcha"
    assert result["errors"]["base"] == "cannot_connect"


@pytest.mark.asyncio
async def test_reauth_challenge_maintains_existing_plant(config, hass, credentials, api, monkeypatch):
    """Reauth must retain the selected station across the CAPTCHA redirect."""
    entry = Mock()
    entry.entry_id = "previous-entry"
    entry.data = dict(credentials, station_dn="original-plant")
    hass.config_entries.async_get_entry.return_value = entry
    api.captcha_img = ""
    monkeypatch.setattr(config, "validate_input",
        AsyncMock(side_effect=config.InvalidCaptcha(api)))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "previous-entry", "source": "reauth"}

    initial = await flow.async_step_reauth(entry.data)
    assert initial["step_id"] == "reauth_confirm"
    challenge = await flow.async_step_reauth_confirm(credentials)
    assert challenge["step_id"] == "captcha"
    assert flow._captcha_credentials[config.CONF_STATION_DN] == "original-plant"
    assert flow._target_entry is entry


@pytest.mark.asyncio
async def test_reconfigure_challenge_preserves_station(config, hass, credentials, api, monkeypatch):
    entry = Mock()
    entry.entry_id = "previous-entry"
    entry.data = dict(credentials, station_dn="original-plant")
    hass.config_entries.async_get_entry.return_value = entry
    api.captcha_img = ""
    monkeypatch.setattr(config, "validate_input",
        AsyncMock(side_effect=config.InvalidCaptcha(api)))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "previous-entry", "source": "reconfigure"}

    result = await flow.async_step_reconfigure(credentials)

    assert result["step_id"] == "captcha"
    assert flow._captcha_credentials[config.CONF_STATION_DN] == "original-plant"
    assert flow._target_entry is entry


@pytest.mark.asyncio
async def test_reconfigure_success_updates_existing_entry(config, hass, credentials, api, monkeypatch):
    entry = Mock()
    entry.entry_id = "previous-entry"
    entry.data = dict(credentials, station_dn="original-plant")
    hass.config_entries.async_get_entry.return_value = entry
    monkeypatch.setattr(config, "validate_input", AsyncMock(return_value=({}, api)))
    flow = config.FusionSolarConfigFlow()
    flow.hass = hass
    flow.context = {"entry_id": "previous-entry", "source": "reconfigure"}

    result = await flow.async_step_reconfigure(credentials)

    assert result == {"type": "abort", "reason": "reconfigure_successful"}
    hass.config_entries.async_reload.assert_awaited_once_with("previous-entry")
    assert hass.config_entries.async_update_entry.call_args.kwargs["data"][config.CONF_STATION_DN] == "original-plant"
