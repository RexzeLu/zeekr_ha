"""Config flow for the Zeekr EV integration (China mainland SMS login)."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api_sms import ZeekrError, ZeekrSmsApiClient
from .const import (
    CONF_AC_DURATION,
    CONF_ENABLE_COMMANDS,
    CONF_PHONE,
    CONF_POLLING_INTERVAL,
    CONF_REGION_CODE,
    CONF_SEAT_DURATION,
    CONF_STEERING_WHEEL_DURATION,
    CONF_VEHICLE_TOKEN,
    DEFAULT_AC_DURATION,
    DEFAULT_ENABLE_COMMANDS,
    DEFAULT_POLLING_INTERVAL,
    DEFAULT_REGION_CODE,
    DEFAULT_SEAT_DURATION,
    DEFAULT_STEERING_WHEEL_DURATION,
    DOMAIN,
    MAX_POLLING_INTERVAL,
    MIN_POLLING_INTERVAL,
    MIN_DURATION,
    MAX_DURATION,
)

_LOGGER = logging.getLogger(__name__)

REGIONS = ["+86", "+852", "+853", "+886"]


def _phone_schema() -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_REGION_CODE, default=DEFAULT_REGION_CODE): vol.In(REGIONS),
            vol.Required(CONF_PHONE): str,
        }
    )


class ZeekrEVConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the SMS login flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._phone: str = ""
        self._region: str = DEFAULT_REGION_CODE
        self._device_id: str | None = None
        self._detail: str = ""
        self._reauth_entry: config_entries.ConfigEntry | None = None

    # -- helpers ----------------------------------------------------------

    def _show(self, step_id: str, schema: vol.Schema, errors: dict[str, str],
              **placeholders: Any):
        return self.async_show_form(
            step_id=step_id,
            data_schema=schema,
            errors=errors,
            description_placeholders={"detail": self._detail, **placeholders},
        )

    async def _async_finish(self, client: ZeekrSmsApiClient):
        """Persist tokens and create / update the entry."""
        tokens = client.get_token_storage()
        vehicles = client.vehicles
        data = {
            CONF_PHONE: self._phone,
            CONF_REGION_CODE: self._region,
            **tokens,
        }

        if self._reauth_entry is not None:
            self.hass.config_entries.async_update_entry(
                self._reauth_entry, data={**self._reauth_entry.data, **data}
            )
            await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
            return self.async_abort(reason="reauth_successful")

        await self.async_set_unique_id(self._phone)
        self._abort_if_unique_id_configured()

        title = f"极氪 · {self._phone}"
        plate = next(
            (v.meta.get("plate") for v in vehicles if v.meta.get("plate")), None
        )
        if plate:
            title = f"极氪 {plate}"

        if not vehicles:
            _LOGGER.warning(
                "登录成功但暂时未获取到车辆，集成会持续重试列表接口。"
            )

        return self.async_create_entry(title=title, data=data)

    # -- steps ------------------------------------------------------------

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            phone = str(user_input[CONF_PHONE]).strip()
            region = user_input.get(CONF_REGION_CODE, DEFAULT_REGION_CODE)
            if not phone:
                errors["base"] = "phone_required"
            else:
                session = async_get_clientsession(self.hass)
                client = ZeekrSmsApiClient(session)
                try:
                    resp = await client.async_send_sms(phone, region)
                except ZeekrError as err:
                    errors["base"] = "cannot_connect"
                    self._detail = str(err)
                else:
                    if resp.get("code") == "000000":
                        self._phone = phone
                        self._region = region
                        self._device_id = client.device_id
                        return await self.async_step_sms_code()
                    errors["base"] = "sms_failed"
                    self._detail = str(
                        resp.get("msg") or resp.get("message") or resp.get("code")
                    )
        return self._show("user", _phone_schema(), errors)

    async def async_step_sms_code(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            code = str(user_input.get("sms_code", "")).strip()
            if not code:
                errors["base"] = "code_required"
            else:
                session = async_get_clientsession(self.hass)
                client = ZeekrSmsApiClient(session)
                client.set_device_id(self._device_id)
                try:
                    await client.async_full_login(self._phone, code, self._region)
                except ZeekrError as err:
                    errors["base"] = "invalid_auth"
                    self._detail = str(err)
                else:
                    return await self._async_finish(client)
        return self._show(
            "sms_code",
            vol.Schema({vol.Required("sms_code"): str}),
            errors,
            phone=self._phone,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any] | None = None):
        entry_id = self.context.get("entry_id")
        if entry_id:
            self._reauth_entry = self.hass.config_entries.async_get_entry(entry_id)
        if self._reauth_entry is not None:
            self._phone = self._reauth_entry.data.get(CONF_PHONE, "")
            self._region = self._reauth_entry.data.get(
                CONF_REGION_CODE, DEFAULT_REGION_CODE
            )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ):
        errors: dict[str, str] = {}
        if user_input is not None:
            session = async_get_clientsession(self.hass)
            client = ZeekrSmsApiClient(session)
            try:
                resp = await client.async_send_sms(self._phone, self._region)
            except ZeekrError as err:
                errors["base"] = "cannot_connect"
                self._detail = str(err)
            else:
                if resp.get("code") == "000000":
                    self._device_id = client.device_id
                    return await self.async_step_sms_code()
                errors["base"] = "sms_failed"
                self._detail = str(
                    resp.get("msg") or resp.get("message") or resp.get("code")
                )
        return self._show(
            "reauth_confirm", vol.Schema({}), errors, phone=self._phone
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return ZeekrEVOptionsFlow()


class ZeekrEVOptionsFlow(config_entries.OptionsFlow):
    """Tune polling, durations and the command master switch."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        current = {**self.config_entry.data, **self.config_entry.options}
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_POLLING_INTERVAL,
                    default=current.get(
                        CONF_POLLING_INTERVAL, DEFAULT_POLLING_INTERVAL
                    ),
                ): vol.All(
                    vol.Coerce(int),
                    vol.Range(min=MIN_POLLING_INTERVAL, max=MAX_POLLING_INTERVAL),
                ),
                vol.Optional(
                    CONF_ENABLE_COMMANDS,
                    default=current.get(
                        CONF_ENABLE_COMMANDS, DEFAULT_ENABLE_COMMANDS
                    ),
                ): bool,
                vol.Optional(
                    CONF_SEAT_DURATION,
                    default=current.get(CONF_SEAT_DURATION, DEFAULT_SEAT_DURATION),
                ): vol.All(
                    vol.Coerce(int), vol.Range(min=MIN_DURATION, max=MAX_DURATION)
                ),
                vol.Optional(
                    CONF_AC_DURATION,
                    default=current.get(CONF_AC_DURATION, DEFAULT_AC_DURATION),
                ): vol.All(
                    vol.Coerce(int), vol.Range(min=MIN_DURATION, max=MAX_DURATION)
                ),
                vol.Optional(
                    CONF_STEERING_WHEEL_DURATION,
                    default=current.get(
                        CONF_STEERING_WHEEL_DURATION, DEFAULT_STEERING_WHEEL_DURATION
                    ),
                ): vol.All(
                    vol.Coerce(int), vol.Range(min=MIN_DURATION, max=MAX_DURATION)
                ),
                # Optional.  The SNCTSP platform addresses a car with this
                # opaque token instead of the VIN, and the token is what carries
                # the car's permissions, so it cannot be computed here.  Leave
                # it empty to keep using an encrypted VIN (see README).
                vol.Optional(
                    CONF_VEHICLE_TOKEN,
                    default=current.get(CONF_VEHICLE_TOKEN, ""),
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
