"""Config flow for Zeekr EV - supports email+password and SMS (+86) login."""
from __future__ import annotations
import logging
import re
from typing import Dict, Any, Optional
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from .const import (
    CONF_HMAC_ACCESS_KEY, CONF_HMAC_SECRET_KEY, CONF_PASSWORD,
    CONF_PASSWORD_PUBLIC_KEY, CONF_PROD_SECRET, CONF_USERNAME,
    CONF_VIN_IV, CONF_VIN_KEY, CONF_COUNTRY_CODE, CONF_USE_LOCAL_API,
    CONF_DRIVE_SIDE, DRIVE_SIDE_LHD, DRIVE_SIDE_RHD,
    DEFAULT_POLLING_INTERVAL, DOMAIN, COUNTRY_CODE_MAPPING,
    CONF_LOGIN_TYPE, LOGIN_TYPE_EMAIL, LOGIN_TYPE_SMS,
    CONF_PHONE, CONF_SMS_CODE, CONF_REGION_CODE, CONF_DEVICE_ID,
    DEFAULT_REGION_CODE,
    STORAGE_JWT_TOKEN, STORAGE_ACCESS_TOKEN, STORAGE_REFRESH_TOKEN,
    STORAGE_USER_ID, STORAGE_CLIENT_ID,
    STORAGE_NEW_ACCESS_TOKEN, STORAGE_NEW_REFRESH_TOKEN,
)
from .utils import get_zeekr_client_class, get_zeekr_sms_client_class, is_base64
_LOGGER = logging.getLogger(__name__)
LOGIN_TYPE_SCHEMA = vol.Schema({
    vol.Required(CONF_LOGIN_TYPE, default=LOGIN_TYPE_SMS): vol.In({
        LOGIN_TYPE_EMAIL: "邮箱密码登录",
        LOGIN_TYPE_SMS: "手机号短信验证码 (支持+86)",
    }),
})
SMS_PHONE_SCHEMA = vol.Schema({
    vol.Required(CONF_REGION_CODE, default=DEFAULT_REGION_CODE): vol.In(["+86", "+852", "+853", "+886"]),
    vol.Required(CONF_PHONE): str,
})
SMS_CODE_SCHEMA = vol.Schema({
    vol.Required(CONF_SMS_CODE): str,
})
class ZeekrEVAPIFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_CLOUD_POLL
    def __init__(self):
        self._errors: Dict[str, str] = {}
        self._temp_client = None
        self._phone = ""
        self._region_code = DEFAULT_REGION_CODE
        self._device_id = ""
    async def async_step_user(self, user_input=None):
        self._errors = {}
        if user_input is not None:
            lt = user_input.get(CONF_LOGIN_TYPE, LOGIN_TYPE_SMS)
            if lt == LOGIN_TYPE_SMS:
                return await self.async_step_sms_phone()
            else:
                return await self.async_step_credentials()
        return self.async_show_form(step_id="user", data_schema=LOGIN_TYPE_SCHEMA, errors=self._errors)
    async def async_step_sms_phone(self, user_input=None):
        self._errors = {}
        if user_input is not None:
            phone = user_input[CONF_PHONE].strip()
            region = user_input.get(CONF_REGION_CODE, DEFAULT_REGION_CODE)
            if not phone:
                self._errors["base"] = "请输入手机号"
            else:
                self._phone = phone
                self._region_code = region
                session = async_get_clientsession(self.hass)
                from .api_sms import ZeekrSmsApiClient
                client = ZeekrSmsApiClient(session)
                try:
                    resp = await client.send_sms(phone, region)
                    if resp.get("code") == "000000":
                        self._device_id = client._device_id
                        return await self.async_step_sms_code()
                    else:
                        msg = resp.get("msg", resp.get("message", "SMS error"))
                        self._errors["base"] = f"发送验证码失败: {msg}"
                except Exception as exc:
                    _LOGGER.exception("SMS send failed")
                    self._errors["base"] = f"网络错误: {exc}"
        return self.async_show_form(step_id="sms_phone", data_schema=SMS_PHONE_SCHEMA, errors=self._errors)
    async def async_step_sms_code(self, user_input=None):
        self._errors = {}
        if user_input is not None:
            sms_code = user_input[CONF_SMS_CODE].strip()
            if not sms_code:
                self._errors["base"] = "请输入验证码"
            else:
                session = async_get_clientsession(self.hass)
                from .api_sms import ZeekrSmsApiClient
                client = ZeekrSmsApiClient(session)
                client.set_device_id(self._device_id)
                try:
                    flow_res = await client.full_login(self._phone, sms_code, self._region_code)
                    login_resp = flow_res.get("sms_login", {})
                    if login_resp.get("code") == "000000":
                        tokens = client.get_token_storage()
                        return self.async_create_entry(
                            title=f"Zeekr ({self._phone})",
                            data={CONF_LOGIN_TYPE: LOGIN_TYPE_SMS, CONF_PHONE: self._phone, CONF_REGION_CODE: self._region_code, **tokens})
                    else:
                        msg = login_resp.get("msg", login_resp.get("message", "登录失败"))
                        self._errors["base"] = f"登录失败: {msg}"
                except Exception as exc:
                    _LOGGER.exception("SMS login failed")
                    self._errors["base"] = f"登录异常: {exc}"
        return self.async_show_form(step_id="sms_code", data_schema=SMS_CODE_SCHEMA, errors=self._errors, description_placeholders={"phone": self._phone})
    async def async_step_credentials(self, user_input=None):
        self._errors = {}
        if user_input is not None:
            try:
                info = await self._validate_input(user_input)
                if isinstance(info, str):
                    self._errors["base"] = info
                else:
                    return self.async_create_entry(title=info["title"], data=info["data"])
            except Exception as ex:
                self._errors["base"] = str(ex)
        return self.async_show_form(step_id="credentials", data_schema=vol.Schema({
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_COUNTRY_CODE, default="CN"): vol.In(sorted(COUNTRY_CODE_MAPPING.keys())),
            vol.Optional(CONF_HMAC_ACCESS_KEY, default=""): str,
            vol.Optional(CONF_HMAC_SECRET_KEY, default=""): str,
            vol.Optional(CONF_PASSWORD_PUBLIC_KEY, default=""): str,
            vol.Optional(CONF_PROD_SECRET, default=""): str,
            vol.Optional(CONF_VIN_KEY, default=""): str,
            vol.Optional(CONF_VIN_IV, default=""): str,
        }), errors=self._errors)
    async def _validate_input(self, user_input):
        username = user_input.get(CONF_USERNAME, "").strip()
        password = user_input.get(CONF_PASSWORD, "").strip()
        country_code = user_input.get(CONF_COUNTRY_CODE, "CN")
        if not username or not password:
            return "用户名和密码不能为空"
        hmac_access = user_input.get(CONF_HMAC_ACCESS_KEY, "").strip()
        hmac_secret = user_input.get(CONF_HMAC_SECRET_KEY, "").strip()
        pwd_public_key = user_input.get(CONF_PASSWORD_PUBLIC_KEY, "").strip()
        prod_secret = user_input.get(CONF_PROD_SECRET, "").strip()
        vin_key = user_input.get(CONF_VIN_KEY, "").strip()
        vin_iv = user_input.get(CONF_VIN_IV, "").strip()
        for key, val, desc in [
            (CONF_HMAC_ACCESS_KEY, hmac_access, "HMAC Access Key"),
            (CONF_HMAC_SECRET_KEY, hmac_secret, "HMAC Secret Key"),
            (CONF_PASSWORD_PUBLIC_KEY, pwd_public_key, "Password Public Key"),
            (CONF_PROD_SECRET, prod_secret, "Prod Secret"),
            (CONF_VIN_KEY, vin_key, "VIN Key"),
            (CONF_VIN_IV, vin_iv, "VIN IV"),
        ]:
            if val and not is_base64(val):
                return f"{desc} 格式无效 (需要 Base64 编码)"
        kwargs = {"country_code": country_code, "username": username, "password": password}
        if hmac_access:
            kwargs["hmac_access_key"] = hmac_access
        if hmac_secret:
            kwargs["hmac_secret_key"] = hmac_secret
        if pwd_public_key:
            kwargs["password_public_key"] = pwd_public_key
        if prod_secret:
            kwargs["prod_secret"] = prod_secret
        if vin_key:
            kwargs["vin_key"] = vin_key
        if vin_iv:
            kwargs["vin_iv"] = vin_iv
        try:
            client_class = get_zeekr_client_class(use_local=False)
            client = await self.hass.async_add_executor_job(lambda: client_class(**kwargs))
            vehicles = await self.hass.async_add_executor_job(lambda: client.get_vehicle_list())
        except Exception as ex:
            return f"登录失败: {ex}"
        if not vehicles:
            return "未找到车辆"
        return {"title": f"Zeekr ({username})", "data": {CONF_LOGIN_TYPE: LOGIN_TYPE_EMAIL, CONF_USERNAME: username, CONF_PASSWORD: password, CONF_COUNTRY_CODE: country_code, CONF_HMAC_ACCESS_KEY: hmac_access, CONF_HMAC_SECRET_KEY: hmac_secret, CONF_PASSWORD_PUBLIC_KEY: pwd_public_key, CONF_PROD_SECRET: prod_secret, CONF_VIN_KEY: vin_key, CONF_VIN_IV: vin_iv}}
    async def async_step_reauth(self, user_input=None):
        return await self.async_step_user()
    async def async_step_import(self, user_input=None):
        return await self.async_step_user()
    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return ZeekrEVOptionsFlow(config_entry)
class ZeekrEVOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        super().__init__(config_entry)
    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(step_id="init", data_schema=vol.Schema({
            vol.Optional(CONF_POLLING_INTERVAL, default=self.config_entry.data.get(CONF_POLLING_INTERVAL, DEFAULT_POLLING_INTERVAL)): vol.All(vol.Coerce(int), vol.Range(min=1, max=60)),
            vol.Optional(CONF_DRIVE_SIDE, default=self.config_entry.data.get(CONF_DRIVE_SIDE, DRIVE_SIDE_LHD)): vol.In({DRIVE_SIDE_LHD: "Left-Hand Drive (LHD)", DRIVE_SIDE_RHD: "Right-Hand Drive (RHD)"}),
        }))
