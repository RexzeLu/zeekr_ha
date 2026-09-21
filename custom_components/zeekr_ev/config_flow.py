"""Config flow for the Zeekr EV integration.

The first step picks the channel; everything after it is channel specific.

* **SMS (+86)** — the classic login.  Works for the car's *owner* and needs the
  phone number plus a verification code.
* **GRIC** — seeded with the app's own refresh token.  This is the channel for
  an account the SNC gateway refuses, such as a shared car
  (``isOwner: false``), which cannot be fixed by logging in differently.

The GRIC step also asks for the car's ``x-vehicle-identifier``: the gateway
decrypts it, so it cannot be derived offline and has to be pasted from the app
(see the README).  It is validated against the live service before the entry is
created, so a wrong value fails in the UI rather than at first poll.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api_gric import ZeekrGricApiClient
from .api_sms import ZeekrError, ZeekrSmsApiClient
from .const import (
    AUTH_METHOD_GRIC,
    AUTH_METHOD_SMS,
    CONF_AC_DURATION,
    CONF_AUTH_METHOD,
    CONF_ENABLE_COMMANDS,
    CONF_HIDDEN_ENTITIES,
    CONF_PHONE,
    CONF_POLLING_INTERVAL,
    CONF_REGION_CODE,
    CONF_SEAT_DURATION,
    CONF_STEERING_WHEEL_DURATION,
    CONF_VEHICLE_IDENTIFIER,
    CONF_VEHICLE_TOKEN,
    DEFAULT_AC_DURATION,
    DEFAULT_AUTH_METHOD,
    DEFAULT_ENABLE_COMMANDS,
    DEFAULT_HIDDEN_ENTITIES,
    DEFAULT_POLLING_INTERVAL,
    DEFAULT_REGION_CODE,
    DEFAULT_SEAT_DURATION,
    DEFAULT_STEERING_WHEEL_DURATION,
    DOMAIN,
    HIDABLE_ENTITIES,
    MAX_DURATION,
    MAX_POLLING_INTERVAL,
    MIN_DURATION,
    MIN_POLLING_INTERVAL,
    STORAGE_GRIC_REFRESH_TOKEN,
)

_LOGGER = logging.getLogger(__name__)

REGIONS = ["+86", "+852", "+853", "+886"]

#: Labels for the channel picker.  Rendered verbatim by Home Assistant, so they
#: are written here rather than in the translations file (a ``vol.In(dict)``
#: shows its values, not a translatable key).
LOGIN_METHODS = {
    AUTH_METHOD_SMS: "短信验证码登录（车主账号）",
    AUTH_METHOD_GRIC: "GRIC 令牌（共享车 / 非车主账号）",
}


def _entry_auth_method(entry: config_entries.ConfigEntry | None) -> str:
    """Channel of an existing entry (entries from before it are SMS ones)."""
    if entry is None:
        return DEFAULT_AUTH_METHOD
    return str(
        entry.options.get(CONF_AUTH_METHOD)
        or entry.data.get(CONF_AUTH_METHOD)
        or DEFAULT_AUTH_METHOD
    )


def _method_schema() -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(
                CONF_AUTH_METHOD, default=DEFAULT_AUTH_METHOD
            ): vol.In(LOGIN_METHODS),
        }
    )


def _phone_schema() -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_REGION_CODE, default=DEFAULT_REGION_CODE): vol.In(REGIONS),
            vol.Required(CONF_PHONE): str,
        }
    )


def _entry_identifier(entry: config_entries.ConfigEntry | None) -> str:
    """The ``x-vehicle-identifier`` an existing entry already carries."""
    if entry is None:
        return ""
    return str(
        entry.options.get(CONF_VEHICLE_IDENTIFIER)
        or entry.data.get(CONF_VEHICLE_IDENTIFIER)
        or ""
    )


def _gric_schema(identifier_default: str = "") -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(STORAGE_GRIC_REFRESH_TOKEN): str,
            # Pre-filled on reauth, where the car's identifier is already known
            # and only the token needs replacing.
            vol.Optional(CONF_VEHICLE_IDENTIFIER, default=identifier_default): str,
        }
    )


class ZeekrEVConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle both login channels."""

    VERSION = 1

    def __init__(self) -> None:
        self._auth_method: str = DEFAULT_AUTH_METHOD
        self._phone: str = ""
        self._region: str = DEFAULT_REGION_CODE
        self._device_id: str | None = None
        self._detail: str = ""
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._gric_client: ZeekrGricApiClient | None = None
        #: The refresh token the user typed.  Kept so a second submission of the
        #: same form is recognised as a retry rather than a new seed — the token
        #: rotates on use, so re-seeding from the form would send a dead one.
        self._gric_pasted: str = ""

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
        """Persist SMS tokens and create / update the entry."""
        tokens = client.get_token_storage()
        vehicles = client.vehicles
        data = {
            CONF_AUTH_METHOD: AUTH_METHOD_SMS,
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

    def _seed_gric_client(self, refresh: str) -> ZeekrGricApiClient:
        """Return the flow's GRIC client, seeding it from ``refresh`` once.

        A refreshToken is invalidated the instant it is exchanged, so if the
        form is submitted twice (a typo in the identifier, say) the second
        attempt must keep using the *rotated* token the first one obtained.
        Re-seeding from the form each time would send a dead token and report
        a perfectly good credential as invalid.  A genuinely different token
        typed by the user does re-seed.
        """
        if self._gric_client is not None and refresh == self._gric_pasted:
            return self._gric_client
        session = async_get_clientsession(self.hass)
        client = ZeekrGricApiClient(session)
        client.store_tokens({STORAGE_GRIC_REFRESH_TOKEN: refresh})
        self._gric_client = client
        self._gric_pasted = refresh
        return client

    async def _async_finish_gric(self, client: ZeekrGricApiClient):
        """Persist GRIC tokens and create / update the entry."""
        tokens = client.get_token_storage()
        vehicles = client.vehicles
        data = {
            CONF_AUTH_METHOD: AUTH_METHOD_GRIC,
            **tokens,
        }

        if self._reauth_entry is not None:
            self.hass.config_entries.async_update_entry(
                self._reauth_entry, data={**self._reauth_entry.data, **data}
            )
            await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
            return self.async_abort(reason="reauth_successful")

        # The VIN is the natural identity of a GRIC entry — there is no phone
        # number to key on.  When the account has no car yet, fall back to the
        # identifier so two entries can still be told apart.
        vin = vehicles[0].vin if vehicles else None
        unique = vin or f"gric:{tokens.get(CONF_VEHICLE_IDENTIFIER) or client.device_id}"
        await self.async_set_unique_id(unique)
        self._abort_if_unique_id_configured()

        title = "极氪 (GRIC)"
        plate = next(
            (v.meta.get("plate") for v in vehicles if v.meta.get("plate")), None
        )
        nickname = next(
            (v.meta.get("nickname") for v in vehicles if v.meta.get("nickname")), None
        )
        if plate:
            title = f"极氪 {plate}"
        elif nickname:
            title = f"极氪 {nickname}"

        if not vehicles:
            _LOGGER.warning("GRIC 登录成功但账号下未返回车辆，集成会继续重试。")

        return self.async_create_entry(title=title, data=data)

    # -- steps ------------------------------------------------------------

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Pick the channel, then hand over to its own flow."""
        if user_input is not None:
            self._auth_method = str(
                user_input.get(CONF_AUTH_METHOD) or DEFAULT_AUTH_METHOD
            )
            if self._auth_method == AUTH_METHOD_GRIC:
                return await self.async_step_gric()
            return await self.async_step_phone()
        return self._show("user", _method_schema(), {})

    # -- SMS channel ------------------------------------------------------

    async def async_step_phone(self, user_input: dict[str, Any] | None = None):
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
        return self._show("phone", _phone_schema(), errors)

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

    # -- GRIC channel -----------------------------------------------------

    async def async_step_gric(self, user_input: dict[str, Any] | None = None):
        """Seed the GRIC channel from the app's refresh token."""
        errors: dict[str, str] = {}
        if user_input is not None:
            refresh = str(user_input.get(STORAGE_GRIC_REFRESH_TOKEN, "")).strip()
            identifier = str(user_input.get(CONF_VEHICLE_IDENTIFIER, "")).strip()
            if not refresh:
                errors["base"] = "gric_token_required"
            elif not identifier:
                # Every per-vehicle route needs it, so refuse *before* spending
                # a token rotation on a request that cannot work.
                errors["base"] = "gric_identifier_required"
            else:
                client = self._seed_gric_client(refresh)
                client.set_vehicle_identifier(identifier)
                try:
                    # Exchange the refresh token first: a rejected or expired
                    # one is the single most likely failure, and it deserves
                    # its own message rather than a generic connect error.
                    refreshed = await client.async_ensure_gw3_token()
                    vehicles = (
                        await client.async_get_vehicle_list() if refreshed else []
                    )
                except ZeekrError as err:
                    refreshed, vehicles = False, []
                    self._detail = str(err)
                except Exception as err:  # noqa: BLE001 - never 500 the form
                    refreshed, vehicles = False, []
                    self._detail = str(err)

                if not refreshed:
                    errors["base"] = "gric_refresh_failed"
                    if not self._detail:
                        self._detail = (
                            "refreshToken 被服务端拒绝或已失效。"
                            "请注意：令牌会轮换，同一会话只有最后持有者有效，"
                            "再次使用时请粘贴 App 里最新的那条。"
                        )
                else:
                    # The token is good.  Whether the identifier is right can
                    # only be told by a per-vehicle read — the vehicle *list*
                    # does not use it — so verify one car here and turn a bad
                    # value into a form error instead of a silent first poll.
                    ok, detail = True, ""
                    if vehicles:
                        try:
                            ok, detail = await client.async_probe_vehicle(
                                vehicles[0].vin
                            )
                        except ZeekrError as err:
                            ok, detail = False, str(err)
                    if ok:
                        return await self._async_finish_gric(client)
                    errors["base"] = "gric_identifier_failed"
                    self._detail = detail or (
                        "无法读取车况。请确认 x-vehicle-identifier 是本车的值，"
                        "并且该账号在 App 里确实能控制这台车。"
                    )

        return self._show(
            "gric", _gric_schema(_entry_identifier(self._reauth_entry)), errors
        )

    # -- reauth -----------------------------------------------------------

    async def async_step_reauth(self, entry_data: dict[str, Any] | None = None):
        entry_id = self.context.get("entry_id")
        if entry_id:
            self._reauth_entry = self.hass.config_entries.async_get_entry(entry_id)
        if self._reauth_entry is not None:
            self._auth_method = _entry_auth_method(self._reauth_entry)
            self._phone = self._reauth_entry.data.get(CONF_PHONE, "")
            self._region = self._reauth_entry.data.get(
                CONF_REGION_CODE, DEFAULT_REGION_CODE
            )
        if self._auth_method == AUTH_METHOD_GRIC:
            return await self.async_step_gric()
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
        return self.async_show_form(
            step_id="init", data_schema=self._options_schema()
        )

    def _options_schema(self) -> vol.Schema:
        """Build the options form, dropping whatever cannot be built.

        Building it used to raise ``NameError`` (``cv`` was never imported in
        this module), which left Home Assistant with no schema to render and
        turned the whole dialog into a 500.  The optional part is therefore
        built last and dropped on failure: a broken picker should cost one
        option, not access to every other setting.
        """
        try:
            return self._build_options_schema()
        except Exception:  # noqa: BLE001 - never 500 the dialog
            _LOGGER.exception("选项表单构建失败，已退回精简版")
            return self._build_options_schema(full=False)

    def _build_options_schema(self, *, full: bool = True) -> vol.Schema:
        current = {**self.config_entry.data, **self.config_entry.options}
        minutes = vol.All(
            vol.Coerce(int), vol.Range(min=MIN_DURATION, max=MAX_DURATION)
        )
        fields: dict[Any, Any] = {
            vol.Optional(
                CONF_POLLING_INTERVAL,
                default=current.get(CONF_POLLING_INTERVAL, DEFAULT_POLLING_INTERVAL),
            ): vol.All(
                vol.Coerce(int),
                vol.Range(min=MIN_POLLING_INTERVAL, max=MAX_POLLING_INTERVAL),
            ),
            vol.Optional(
                CONF_ENABLE_COMMANDS,
                default=current.get(CONF_ENABLE_COMMANDS, DEFAULT_ENABLE_COMMANDS),
            ): bool,
            vol.Optional(
                CONF_SEAT_DURATION,
                default=current.get(CONF_SEAT_DURATION, DEFAULT_SEAT_DURATION),
            ): minutes,
            vol.Optional(
                CONF_AC_DURATION,
                default=current.get(CONF_AC_DURATION, DEFAULT_AC_DURATION),
            ): minutes,
            vol.Optional(
                CONF_STEERING_WHEEL_DURATION,
                default=current.get(
                    CONF_STEERING_WHEEL_DURATION, DEFAULT_STEERING_WHEEL_DURATION
                ),
            ): minutes,
            # Optional.  The SNCTSP platform addresses a car with this
            # opaque token instead of the VIN, and the token is what carries
            # the car's permissions, so it cannot be computed here.  Leave
            # it empty to keep using an encrypted VIN (see README).
            vol.Optional(
                CONF_VEHICLE_TOKEN, default=current.get(CONF_VEHICLE_TOKEN, "")
            ): str,
            # GRIC channel only: the app's per-vehicle ``x-vehicle-identifier``.
            # Vehicle lists work without it, but every read and every command
            # is refused — so it is what turns a listing into control.
            vol.Optional(
                CONF_VEHICLE_IDENTIFIER,
                default=current.get(CONF_VEHICLE_IDENTIFIER, ""),
            ): str,
        }
        if full:
            # Controls for hardware this particular car does not have (rear
            # seat heaters…).  Nothing in the payload reveals it: the
            # capability bitmap is per service rather than per seat, and a
            # missing feature still reports a plain 0, so the owner has to
            # say which ones to drop.
            fields[
                vol.Optional(
                    CONF_HIDDEN_ENTITIES, default=_hidden_default(current)
                )
            ] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        selector.SelectOptionDict(value=key, label=label)
                        for key, label in HIDABLE_ENTITIES.items()
                    ],
                    multiple=True,
                    custom_value=False,
                )
            )
        return vol.Schema(fields)


def _hidden_default(current: dict[str, Any]) -> list[str]:
    """The stored selection, minus keys this version no longer offers.

    Dropping unknown keys keeps a renamed or retired option from turning into
    an invalid selection the next time the form is saved.
    """
    raw = current.get(CONF_HIDDEN_ENTITIES)
    if isinstance(raw, (list, tuple, set)):
        return [str(item) for item in raw if str(item) in HIDABLE_ENTITIES]
    return list(DEFAULT_HIDDEN_ENTITIES)
