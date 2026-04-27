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


async def validate_input(
    hass: HomeAssistant,
    data: dict[str, Any],
    api: FusionSolarAPI | None = None,
) -> tuple[dict[str, Any], FusionSolarAPI]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    Returns a tuple of (info dict, api instance).
    """
    captcha_input = data.get(CAPTCHA_INPUT)

    if isinstance(captcha_input, str):
        captcha_input = captcha_input.strip()

    if api is None:
        api = FusionSolarAPI(
            data[CONF_USERNAME],
            data[CONF_PASSWORD],
            data[FUSION_SOLAR_HOST],
            captcha_input,
        )
    else:
        api.user = data[CONF_USERNAME]
        api.pwd = data[CONF_PASSWORD]
        api.login_host = data[FUSION_SOLAR_HOST]
        api.captcha_input = captcha_input

    try:
        await hass.async_add_executor_job(api.login)
    except APIAuthCaptchaError as err:
        raise InvalidCaptcha(api) from err
    except APIAuthError as err:
        raise InvalidAuth from err
    except APIConnectionError as err:
        raise CannotConnect from err

    return {"title": "Fusion Solar App Integration"}, api


class FusionSolarConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Fusion Solar App Integration."""

    VERSION = 1
    _input_data: dict[str, Any]
    _stations: list[dict[str, Any]]
    _api: FusionSolarAPI | None = None
    _captcha_credentials: dict[str, Any] | None = None
    _target_entry: ConfigEntry | None = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return FusionSolarOptionsFlowHandler(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info, api = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha as exc:
                _LOGGER.warning("Captcha required, redirecting to captcha screen")
                self._api = exc.api
                self._captcha_credentials = user_input
                return await self.async_step_captcha()
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

            if "base" not in errors:
                self._input_data = user_input
                self._api = api
                try:
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

            # Persist authenticated session so coordinator can restore it
            if self._api and self._api.connected:
                data["dp_session"] = self._api.dp_session
                data["data_host"] = self._api.data_host

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

    async def _finish_entry_update(
        self, entry: ConfigEntry, credentials: dict[str, Any], api: FusionSolarAPI | None = None,
    ) -> ConfigFlowResult:
        """Update an existing config entry with new credentials/session and reload."""
        update_data = {
            **entry.data,
            CONF_USERNAME: credentials[CONF_USERNAME],
            CONF_PASSWORD: credentials[CONF_PASSWORD],
            FUSION_SOLAR_HOST: credentials[FUSION_SOLAR_HOST],
        }
        if api and api.connected:
            update_data["dp_session"] = api.dp_session
            update_data["data_host"] = api.data_host
        self.hass.config_entries.async_update_entry(entry, data=update_data)
        await self.hass.config_entries.async_reload(entry.entry_id)
        return self.async_abort(reason="reauth_successful")

    async def async_step_captcha(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the captcha step."""
        errors: dict[str, str] = {}

        if self._api is None or self._captcha_credentials is None:
            errors["base"] = "unknown"

            return self.async_show_form(
                step_id="user",
                data_schema=STEP_USER_DATA_SCHEMA,
                errors=errors,
            )

        if user_input is not None and CAPTCHA_INPUT in user_input:
            captcha_input = user_input[CAPTCHA_INPUT]

            if isinstance(captcha_input, str):
                captcha_input = captcha_input.strip()

            self._api.captcha_input = captcha_input

            try:
                await self.hass.async_add_executor_job(self._api.login)

                if self._api.connected:
                    if self._target_entry:
                        return await self._finish_entry_update(
                            self._target_entry,
                            self._captcha_credentials,
                            self._api,
                        )

                    self._input_data = {**self._captcha_credentials}

                    try:
                        station_data = await self.hass.async_add_executor_job(
                            self._api.get_station_list
                        )
                        self._stations = station_data["data"]["list"]
                    except Exception:  # pylint: disable=broad-except
                        _LOGGER.exception("Failed to fetch station list after captcha login")
                        errors["base"] = "cannot_connect"
                    else:
                        return await self.async_step_select_station()

                errors["base"] = "invalid_captcha"

            except APIAuthCaptchaError:
                errors["base"] = "invalid_captcha"
            except APIAuthError:
                errors["base"] = "invalid_auth"
            except APIConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during captcha handling")
                errors["base"] = "unknown"

        captcha_img = ""

        if self._api and self._api.captcha_img:
            captcha_img = self._api.captcha_img

        return self.async_show_form(
            step_id="captcha",
            data_schema=STEP_CAPTCHA_DATA_SCHEMA,
            description_placeholders={
                "captcha_img": f'<img id="fusion_solar_app_security_captcha" src="{captcha_img}"/>'
            },
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle reauth when login fails at runtime."""
        self._target_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle reauth confirmation step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info, api = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha as exc:
                self._api = exc.api
                self._captcha_credentials = user_input
                return await self.async_step_captcha()
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during reauth")
                errors["base"] = "unknown"

            if "base" not in errors:
                return await self._finish_entry_update(
                    self._target_entry, user_input, api,
                )

        existing_data = self._target_entry.data if self._target_entry else {}
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME, default=existing_data.get(CONF_USERNAME, "")): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(FUSION_SOLAR_HOST, default=existing_data.get(FUSION_SOLAR_HOST, "")): str,
                }
            ),
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
                info, api = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except InvalidCaptcha as exc:
                self._api = exc.api
                self._captcha_credentials = user_input
                self._target_entry = config_entry
                return await self.async_step_captcha()
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
                        default=config_entry.data.get(FUSION_SOLAR_HOST, ""),
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
    """Error to indicate captcha is required."""
    def __init__(self, api: FusionSolarAPI | None = None):
        super().__init__("Captcha required")
        self.api = api
