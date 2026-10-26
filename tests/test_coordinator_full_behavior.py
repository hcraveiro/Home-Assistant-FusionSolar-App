"""Coordinator regression tests with a fake Home Assistant executor and API.

The production coordinator module is imported and its async state machine is run.
No network access, wall-clock sleeps, or Home Assistant installation is required.
"""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import AsyncMock, Mock

import pytest

ROOT = Path(__file__).resolve().parents[1] / "custom_components/fusion_solar_app"
PREFIX = "_fusionsolar_coordinator_behavior"


@pytest.fixture(scope="module")
def coordinator_module():
    names = {}

    def package(name):
        m = types.ModuleType(name)
        m.__path__ = []
        sys.modules[name] = m
        names[name] = m
        return m

    def module(name, **attributes):
        m = types.ModuleType(name)
        m.__dict__.update(attributes)
        sys.modules[name] = m
        names[name] = m
        return m

    package("homeassistant")
    module("homeassistant.config_entries", ConfigEntry=type("ConfigEntry", (), {}))
    module("homeassistant.const", CONF_PASSWORD="password", CONF_SCAN_INTERVAL="scan_interval", CONF_USERNAME="username")
    module("homeassistant.core", HomeAssistant=type("HomeAssistant", (), {}))
    class ConfigEntryAuthFailed(Exception):
        pass
    module("homeassistant.exceptions", ConfigEntryAuthFailed=ConfigEntryAuthFailed)
    package("homeassistant.helpers")
    module("homeassistant.helpers.device_registry", async_get=lambda hass: Mock())
    class DataUpdateCoordinator:
        pass
    class UpdateFailed(Exception):
        pass
    module("homeassistant.helpers.update_coordinator", DataUpdateCoordinator=DataUpdateCoordinator, UpdateFailed=UpdateFailed)

    p = package(PREFIX)
    p.__path__ = [str(ROOT)]
    for short, directory in (("api", ROOT / "api"), ("forecast", ROOT / "forecast")):
        p = package(f"{PREFIX}.{short}")
        p.__path__ = [str(directory)]
    const_spec = importlib.util.spec_from_file_location(f"{PREFIX}.const", ROOT / "const.py")
    const_module = importlib.util.module_from_spec(const_spec)
    sys.modules[const_spec.name] = const_module
    const_spec.loader.exec_module(const_module)
    names[const_spec.name] = const_module
    class APIAuthCaptchaError(Exception):
        pass
    class APIAuthError(Exception):
        pass
    class APIConnectionError(Exception):
        pass
    class APIDataStructureError(Exception):
        pass
    from enum import StrEnum
    class DeviceType(StrEnum):
        SENSOR_KW = "sensor"
        SENSOR_KWH = "sensor_kwh"
    class FakeDevice:
        def __init__(self, device_id, device_type, state):
            self.device_id, self.device_type, self.state = device_id, device_type, state
    module(f"{PREFIX}.api",
           APIAuthCaptchaError=APIAuthCaptchaError,
           APIAuthError=APIAuthError,
           APIConnectionError=APIConnectionError,
           APIDataStructureError=APIDataStructureError,
           Device=FakeDevice, DeviceType=DeviceType, FusionSolarAPI=Mock)
    module(f"{PREFIX}.forecast", ForecastProvider=object, FusionSolarForecastData=object,
           NativeForecastBuilder=Mock, SolcastForecastBuilder=Mock)
    spec = importlib.util.spec_from_file_location(f"{PREFIX}.coordinator", ROOT / "coordinator.py")
    result = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = result
    names[spec.name] = result
    spec.loader.exec_module(result)
    yield result
    for name in reversed(list(names)):
        sys.modules.pop(name, None)


@pytest.fixture
def coordinator(coordinator_module):
    coordinator = object.__new__(coordinator_module.FusionSolarCoordinator)
    coordinator.api = Mock()
    coordinator.api.connected = True
    coordinator.api.station = "station"
    coordinator.api.controller_name = "test-controller"
    coordinator.api._session_lock = None
    coordinator.api.get_devices.return_value = []
    async def execute(function, *args):
        if function is coordinator_module.time.sleep:
            return None
        return function(*args)
    coordinator.hass = Mock()
    coordinator.hass.async_add_executor_job = AsyncMock(side_effect=execute)
    coordinator.config_entry = Mock()
    coordinator.config_entry.options = {}
    coordinator.config_entry.data = {}
    coordinator._build_panel_production_forecast = AsyncMock(return_value=None)
    return coordinator


@pytest.mark.asyncio
async def test_connected_refresh_returns_api_devices(coordinator):
    device = object()
    coordinator.api.get_devices.return_value = [device]
    result = await coordinator.async_update_data()
    assert result.devices == [device]
    assert result.controller_name == "test-controller"
    coordinator.api.login.assert_not_called()


@pytest.mark.asyncio
async def test_disconnected_refresh_logs_in(coordinator):
    coordinator.api.connected = False
    await coordinator.async_update_data()
    coordinator.api.login.assert_called_once()


@pytest.mark.asyncio
async def test_transient_failure_retries_once(coordinator, coordinator_module):
    coordinator.api.get_devices.side_effect = [coordinator_module.APIConnectionError("reset"), ["recovered"]]
    assert (await coordinator.async_update_data()).devices == ["recovered"]
    assert coordinator.api.get_devices.call_count == 2


@pytest.mark.asyncio
async def test_second_connection_failure_is_updatefailed(coordinator, coordinator_module):
    coordinator.api.get_devices.side_effect = coordinator_module.APIConnectionError("down")
    with pytest.raises(coordinator_module.UpdateFailed):
        await coordinator.async_update_data()
    assert coordinator.api.get_devices.call_count == 2


@pytest.mark.asyncio
async def test_expired_session_resets_and_logs_in_once(coordinator, coordinator_module):
    coordinator.api.get_devices.side_effect = [coordinator_module.APIAuthError("expired"), ["restored"]]
    assert (await coordinator.async_update_data()).devices == ["restored"]
    coordinator.api.reset_session.assert_called_once()
    coordinator.api.login.assert_called_once()


@pytest.mark.asyncio
async def test_captcha_causes_reauth_required(coordinator, coordinator_module):
    coordinator.api.get_devices.side_effect = coordinator_module.APIAuthCaptchaError("captcha")
    with pytest.raises(coordinator_module.ConfigEntryAuthFailed):
        await coordinator.async_update_data()
    coordinator.api.reset_session.assert_not_called()


@pytest.mark.asyncio
async def test_failed_reauthentication_is_updatefailed(coordinator, coordinator_module):
    coordinator.api.get_devices.side_effect = coordinator_module.APIAuthError("expired")
    coordinator.api.login.side_effect = RuntimeError("login failed")
    with pytest.raises(coordinator_module.UpdateFailed, match="Re-login failed"):
        await coordinator.async_update_data()


@pytest.mark.asyncio
async def test_forecast_error_does_not_drop_telemetry(coordinator):
    coordinator.api.get_devices.return_value = ["device"]
    coordinator._build_panel_production_forecast.side_effect = RuntimeError("forecast outage")
    result = await coordinator.async_update_data()
    assert result.devices == ["device"]
    assert result.forecast is None


@pytest.mark.asyncio
async def test_missing_station_auto_selected_and_persisted(coordinator):
    coordinator.api.station = None
    coordinator.api.get_station_list.return_value = {"data": {"list": [{"dn": "plant-dn"}]}}
    coordinator.config_entry.data = {"username": "test"}
    await coordinator._ensure_station_dn()
    assert coordinator.api.station == "plant-dn"
    coordinator.hass.config_entries.async_update_entry.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{"data": {"list": []}}, {"data": {"list": [{}]}}])
async def test_missing_station_fails_closed(coordinator, coordinator_module, payload):
    coordinator.api.station = None
    coordinator.api.get_station_list.return_value = payload
    with pytest.raises(coordinator_module.UpdateFailed):
        await coordinator._ensure_station_dn()


@pytest.mark.parametrize("provider,expected", [
    ("invalid", "native"), ("native", "native"), ("solcast", "solcast"),
])
def test_forecast_provider_selection(coordinator, coordinator_module, provider, expected):
    coordinator.config_entry.options = {
        coordinator_module.CONF_FORECAST_PROVIDER: provider
    }
    assert coordinator._get_forecast_provider() == (
        coordinator_module.DEFAULT_FORECAST_PROVIDER if provider == "invalid" else expected
    )


@pytest.mark.parametrize("raw,expected", [(None,None),("",None),("   ",None),(" sensor.pv ", "sensor.pv")])
def test_solcast_entity_normalized(coordinator, coordinator_module, raw, expected):
    coordinator.config_entry.options = {
        coordinator_module.CONF_SOLCAST_FORECAST_TODAY_ENTITY: raw
    }
    assert coordinator._get_solcast_forecast_today_entity() == expected


@pytest.mark.parametrize("value,expected", [("5.2",5.2),("unavailable",None),(None,None)])
def test_production_today_value(coordinator, coordinator_module, value, expected):
    device = coordinator_module.Device("Panel Production Today", coordinator_module.DeviceType.SENSOR_KWH, value)
    assert coordinator._get_actual_panel_production_today([device]) == expected


@pytest.mark.parametrize("value,expected", [("0.5",0.5),("--",None)])
def test_production_power_value(coordinator, coordinator_module, value, expected):
    device = coordinator_module.Device("Panel Production Power", coordinator_module.DeviceType.SENSOR_KW, value)
    assert coordinator._get_actual_panel_production_power([device]) == expected
