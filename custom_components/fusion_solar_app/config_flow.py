"""Config flow for Fusion Solar App Integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError

from .api import FusionSolarAPI, APIAuthError, APIConnectionError, APIAuthCaptchaError
from .const import DEFAULT_SCAN_INTERVAL, DOMAIN, MIN_SCAN_INTERVAL, FUSION_SOLAR_HOST, CAPTCHA_INPUT, CONF_STATION_DN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(FUSION_SOLAR_HOST, description={"suggested_value": "eu5.fusionsolar.huawei.com"}): str
    }
)

STEP_CAPTCHA_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CAPTCHA_INPUT): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    api = FusionSolarAPI(data[CONF_USERNAME], data[CONF_PASSWORD], data[FUSION_SOLAR_HOST], data.get(CAPTCHA_INPUT, None))
    try:
        await hass.async_add_executor_job(api.login)
        # If you cannot connect, raise CannotConnect
        # If the authentication is wrong, raise InvalidAuth
    except APIAuthError as err:
        raise InvalidAuth from err
    except APIAuthCaptchaError as err:
        raise InvalidCaptcha from err
    except APIConnectionError as err:
        raise CannotConnect from err

    # Return info that you want to store in the config entry.
    return {"title": f"Fusion Solar App Integration"}


class FusionSolarConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fusion Solar App Integration."""

    VERSION = 1
    _input_data: dict[str, Any]
    _stations: list[dict[str, Any]]

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        # Remove this method and the FusionSolarConfigFlow class
        # if you do not want any options for your integration.
        return FusionSolarOptionsFlowHandler(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        # Called when you initiate adding an integration via the UI
        errors: dict[str, str] = {}

        if user_input is not None:
            # The form has been filled in and submitted, so process the data provided.
            try:
                # Validate that the setup data is valid and if not handle errors.
                # The errors["base"] values match the values in your strings.json and translation files.
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha:
                _LOGGER.exception("Captcha failed, redirecting to Captcha screen")
                return await self.async_step_captcha(user_input)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

            if "base" not in errors:
                # Store validated input and fetch station list before proceeding
                self._input_data = user_input
                api = FusionSolarAPI(
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    user_input[FUSION_SOLAR_HOST],
                    user_input.get(CAPTCHA_INPUT, None),
                )
                try:
                    await self.hass.async_add_executor_job(api.login)
                    station_data = await self.hass.async_add_executor_job(api.get_station_list)
                    self._stations = station_data["data"]["list"]
                except Exception:  # pylint: disable=broad-except
                    _LOGGER.exception("Unexpected exception while fetching station list")
                    errors["base"] = "cannot_connect"
                else:
                    return await self.async_step_select_station()

        # Show initial form.
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_select_station(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the station selection step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            station_dn = user_input[CONF_STATION_DN]
            # Use username and station DN to build a unique id per plant
            unique_id = f"{self._input_data[CONF_USERNAME]}@{station_dn}"
            await self.async_set_unique_id(unique_id, raise_on_progress=False)

            data = {**self._input_data, CONF_STATION_DN: station_dn}

            title = next(
                (
                    station.get("stationName", "Fusion Solar App Integration")
                    for station in self._stations
                    if station.get("dn") == station_dn
                ),
                "Fusion Solar App Integration",
            )

            return self.async_create_entry(title=title, data=data)

        # Build station selection form.
        if not getattr(self, "_stations", None):
            # Fallback to initial step if for some reason stations are not available
            errors["base"] = "cannot_connect"
            return self.async_show_form(
                step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
            )

        station_options = {
            station["dn"]: station.get("stationName", station["dn"])
            for station in self._stations
        }

        data_schema = vol.Schema(
            {
                vol.Required(CONF_STATION_DN): vol.In(station_options),
            }
        )

        return self.async_show_form(
            step_id="select_station",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the captcha step."""
        errors: dict[str, str] = {}
        captcha_img = ""
        if user_input is not None:
            try:
                api = FusionSolarAPI(
                    user_input[CONF_USERNAME],
                    user_input[CONF_PASSWORD],
                    user_input[FUSION_SOLAR_HOST],
                    user_input.get(CAPTCHA_INPUT, None),
                )
                await self.hass.async_add_executor_job(api.login)
                captcha_img = api.captcha_img if api.captcha_img else ""
                if api.connected:
                    # Login was successful after captcha, so save config data.
                    unique_id = f"{user_input[CONF_USERNAME]}"
                    await self.async_set_unique_id(unique_id, raise_on_progress=False)
                    return self.async_create_entry(
                        title="Fusion Solar App Integration", data=user_input
                    )
                else:
                    errors["base"] = "invalid_captcha"
            except APIAuthCaptchaError:
                errors["base"] = "invalid_captcha"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during captcha handling")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="captcha",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=user_input[CONF_USERNAME]): str,
                    vol.Required(CONF_PASSWORD, default=user_input[CONF_PASSWORD]): str,
                    vol.Required(FUSION_SOLAR_HOST, default=user_input[FUSION_SOLAR_HOST]): str,
                    vol.Required(CAPTCHA_INPUT): str,
                }
            ),
            description_placeholders={"captcha_img": '<img id="fusion_solar_app_security_captcha" src="' + captcha_img + '"/>'},
            errors=errors,
        )

    async def async_step_reconfigure(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        """Handle reconfiguration of Fusion Solar App Integration."""
        errors: dict[str, str] = {}
    
        entry_id = self.context.get("entry_id")
        if not entry_id:
            return self.async_abort(reason="missing_entry_id")
    
        config_entry = self.hass.config_entries.async_get_entry(entry_id)
        if config_entry is None:
            return self.async_abort(reason="config_entry_not_found")
    
        if user_input is not None:
            try:
                # Validate the new credentials
                await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha:
                errors["base"] = "invalid_captcha"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during reconfiguration")
                errors["base"] = "unknown"
    
            if "base" not in errors:
                # Update the existing config entry with new data
                self.hass.config_entries.async_update_entry(
                    config_entry,
                    data={
                        **config_entry.data,
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        FUSION_SOLAR_HOST: user_input[FUSION_SOLAR_HOST],
                    },
                )
                await self.hass.config_entries.async_reload(config_entry.entry_id)
                return self.async_abort(reason="reconfigure_successful")
    
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=config_entry.data.get(CONF_USERNAME, ""),
                    ): str,
                    # Do not prefill passwords in UI
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(
                        FUSION_SOLAR_HOST,
                        default=config_entry.data.get(FUSION_SOLAR_HOST, config_entry.data.get(CONF_LOGIN_HOST, "")),
                    ): str,
                }
            ),
            errors=errors,
        )



class FusionSolarOptionsFlowHandler(OptionsFlow):
    """Handles the options flow."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        # NOTE: In recent Home Assistant versions, OptionsFlow exposes a read-only
        # `config_entry` property, so assigning to it raises an AttributeError.
        # Keep our own reference instead.
        self._config_entry = config_entry
        self.options = dict(config_entry.options)


    async def async_step_init(self, user_input=None):
        """Handle options flow."""
        if user_input is not None:
            options = self._config_entry.options | user_input
            return self.async_create_entry(title="", data=options)
    
        # It is recommended to prepopulate options fields with default values if available.
        # These will be the same default values you use on your coordinator for setting variable values
        # if the option has not been set.
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=self.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): (vol.All(vol.Coerce(int), vol.Clamp(min=MIN_SCAN_INTERVAL))),
            }
        )
    
        return self.async_show_form(step_id="init", data_schema=data_schema)


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""

class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""

class InvalidCaptcha(HomeAssistantError):
    """Error to indicate there is invalid captcha."""
