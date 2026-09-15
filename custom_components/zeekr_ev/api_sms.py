"""Zeekr SMS (China mainland, +86) API client.

Three gateways are involved:

* **GW1** ``api-gw-toc.zeekrlife.com`` – SMS challenge + mobile login (JWT).
* **GW2** ``api.zeekrline.com``      – obtain the "ecar" access token.
* **GW3** ``snc-tsp-api.zeekrlife.com`` – vehicle list, status, remote control.

The gateway signing code is carried over from the original implementation
(it is the hard-won part); this module adds a clean async, high level surface
used by the coordinator:

    client = ZeekrSmsApiClient(session)
    client.store_tokens(entry.data)
    await client.async_send_sms(phone)                 # SMS challenge
    await client.async_full_login(phone, code)         # exchange code
    await client.async_bootstrap()                     # resume w/ saved tokens
    await client.async_fetch_all()                     # {vin: canonical dict}
    await client.async_do_remote_control(...)          # send a command

Secrets are the China-mainland production values baked into the Zeekr app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import random
import time
import uuid
from typing import Any

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from .const import (
    CONF_PHONE,
    STORAGE_ACCESS_TOKEN,
    STORAGE_CLIENT_ID,
    STORAGE_DEVICE_ID,
    STORAGE_JWT_TOKEN,
    STORAGE_NEW_ACCESS_TOKEN,
    STORAGE_NEW_REFRESH_TOKEN,
    STORAGE_REFRESH_TOKEN,
    STORAGE_USER_ID,
)
from .parser import (
    extract_vehicle_meta,
    normalize_vehicle_data,
    vehicle_display_name,
)

_LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# China-mainland production secrets (as shipped in the Zeekr app).
# --------------------------------------------------------------------------
_CA_SECRET = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz09z6e9WOcNq+nUMX8Vq1Xe2EmJxuR3XbtureDCS90dfkok"
_LINE_SECRET = "e83a60805fa54de9bdfcb0f2d6bca757"
_SNC_SECRET = "890efe3207af95348b95f66b2ee7da04"
_AES_KEY = "a01a6db985a2f5d4"
_AES_IV = "ed446b8b8845013d"

_GW1_BASE = "https://api-gw-toc.zeekrlife.com"
_GW2_BASE = "https://api.zeekrline.com"
_GW3_BASE = "https://snc-tsp-api.zeekrlife.com"

_SUCCESS = "000000"

# Gateway auth error codes / markers that should trigger a reauth.
_AUTH_CODES = {"401", "40101", "40102", "40106", "40001", "10401"}
_AUTH_MARKERS = ("token", "expire", "未登录", "登录失效", "unauthorized",
                 "invalid session")


class ZeekrError(Exception):
    """Base class for Zeekr API errors."""


class ZeekrAuthError(ZeekrError):
    """Credentials missing/expired/rejected – the config entry needs reauth."""


class ZeekrApiError(ZeekrError):
    """Non-auth API failure (network, business rejection, ...)."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _ts() -> str:
    return str(int(time.time() * 1000))


def _nonce() -> int:
    return random.randrange(0, 10**8)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _looks_like_auth_error(result: Any, status: int | None = None) -> bool:
    if status in (401, 403):
        return True
    if not isinstance(result, dict):
        return False
    code = str(result.get("code", "")).strip()
    if code in _AUTH_CODES:
        return True
    blob = " ".join(
        str(result.get(key, "")) for key in ("msg", "message", "error", "errorMsg")
    ).lower()
    return any(marker in blob for marker in _AUTH_MARKERS)


def _payload_of(result: Any) -> Any:
    """Return the meaningful body of a gateway response."""
    if isinstance(result, dict):
        if "data" in result:
            return result.get("data")
        return result
    return result


class ZeekrVehicle:
    """A vehicle plus the metadata discovered during login."""

    __slots__ = ("vin", "meta", "data", "raw")

    def __init__(self, vin: str, meta: dict[str, Any] | None = None,
                 raw: dict[str, Any] | None = None) -> None:
        self.vin = vin
        self.meta = dict(meta or {})
        self.data: dict[str, Any] = {}
        # The untouched vehicle-list entry, kept so the diagnostics download can
        # show which field every piece of metadata came from.
        self.raw: dict[str, Any] | None = raw

    @property
    def display_name(self) -> str:
        return vehicle_display_name(self.meta)

    @property
    def model(self) -> str:
        return self.meta.get("model") or self.meta.get("series") or "Zeekr EV"


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class ZeekrSmsApiClient:
    """Async client for the Zeekr China mainland (SMS) API."""

    def __init__(self, session) -> None:
        self._session = session
        self._device_id = uuid.uuid4().hex
        self._phone: str | None = None
        self._jwt_token: str | None = None
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._user_id: str | None = None
        self._client_id: str | None = None
        self._new_access_token: str | None = None
        self._new_refresh_token: str | None = None
        self._vehicles: list[ZeekrVehicle] = []
        self._vehicle_data: dict[str, dict[str, Any]] = {}
        self._raw_payloads: dict[str, Any] = {}
        self._gw3_available = False

    # -- token persistence ------------------------------------------------

    def set_device_id(self, device_id: str | None) -> None:
        if device_id:
            self._device_id = device_id

    def store_tokens(self, data: dict[str, Any]) -> None:
        """Load persisted tokens / identifiers from a config entry."""
        self._device_id = data.get(STORAGE_DEVICE_ID) or self._device_id
        self._phone = data.get(CONF_PHONE) or self._phone
        self._jwt_token = data.get(STORAGE_JWT_TOKEN) or self._jwt_token
        self._access_token = data.get(STORAGE_ACCESS_TOKEN) or self._access_token
        self._refresh_token = data.get(STORAGE_REFRESH_TOKEN) or self._refresh_token
        self._user_id = data.get(STORAGE_USER_ID) or self._user_id
        self._client_id = data.get(STORAGE_CLIENT_ID) or self._client_id
        self._new_access_token = (
            data.get(STORAGE_NEW_ACCESS_TOKEN) or self._new_access_token
        )
        self._new_refresh_token = (
            data.get(STORAGE_NEW_REFRESH_TOKEN) or self._new_refresh_token
        )

    def get_token_storage(self) -> dict[str, Any]:
        return {
            STORAGE_DEVICE_ID: self._device_id,
            CONF_PHONE: self._phone,
            STORAGE_JWT_TOKEN: self._jwt_token,
            STORAGE_ACCESS_TOKEN: self._access_token,
            STORAGE_REFRESH_TOKEN: self._refresh_token,
            STORAGE_USER_ID: self._user_id,
            STORAGE_CLIENT_ID: self._client_id,
            STORAGE_NEW_ACCESS_TOKEN: self._new_access_token,
            STORAGE_NEW_REFRESH_TOKEN: self._new_refresh_token,
        }

    # -- properties -------------------------------------------------------

    @property
    def logged_in(self) -> bool:
        return bool(self._jwt_token and self._access_token)

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def phone(self) -> str | None:
        return self._phone

    @property
    def vehicles(self) -> list[ZeekrVehicle]:
        return self._vehicles

    def get_vehicle(self, vin: str) -> ZeekrVehicle | None:
        for vehicle in self._vehicles:
            if vehicle.vin == vin:
                return vehicle
        return None

    # -- signing / gateway plumbing --------------------------------------

    def _sign_gw1(self, ts: str, nonce: int) -> str:
        return hashlib.sha1(
            "".join(sorted([ts, str(nonce), _CA_SECRET])).encode()
        ).hexdigest()

    def _gw1_headers(self) -> dict[str, str]:
        ts = _ts()
        nonce = _nonce()
        return {
            "User-Agent": (
                f"ZeekrLife/4.0.2 (iPhone; iOS 17.4.1; Scale/3.00){self._device_id}"
            ),
            "request-original": "zeekr-app",
            "Accept-Language": "zh-Hans-CN;q=1, en-CN;q=0.9",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "x_ca_secret": _CA_SECRET,
            "Version": "2",
            "WorkspaceId": "prod",
            "x_ca_key": "APP-SIGN-SECRET-KEY",
            "app_type": "IOS",
            "app_version": "4.0.2",
            "phone_model": "iPhone13",
            "phone_version": "17.4.1",
            "x_gray_code": "gray74",
            "x_ca_timestamp": ts,
            "x_ca_nonce": str(nonce),
            "x_ca_sign": self._sign_gw1(ts, nonce),
            "app_code": "toc_ios_zeekrapp",
            "device_id": self._device_id,
            "Authorization": self._jwt_token or "",
        }

    def _sign_gw2(self, method: str, path: str, params: dict | None,
                  payload: Any, ts: str, nonce: str) -> str:
        body_b64 = _b64(hashlib.md5(
            json.dumps(payload, separators=(",", ":")).encode()
            if payload else b""
        ).digest())
        qs_str = "&".join(f"{k}={v}" for k, v in sorted((params or {}).items()))
        signing = "\n".join([
            "application/json;responseformat=3",
            f"x-api-signature-nonce:{nonce}",
            "x-api-signature-version:1.0",
            "",
            qs_str,
            body_b64,
            ts,
            method.upper(),
            path,
        ])
        digest = hmac.new(_LINE_SECRET.encode(), signing.encode(),
                          hashlib.sha1).digest()
        return _b64(digest)

    def _gw2_headers(self, method: str, path: str, params: dict | None,
                     payload: Any) -> dict[str, str]:
        ts = _ts()
        nonce = uuid.uuid4().hex.upper()
        headers = {
            "content-type": "application/json",
            "x-api-signature-version": "1.0",
            "x-app-id": "ZEEKRAPP",
            "user-agent": "ZeekrLife/4.0.2 (iPhone; iOS 17.4.1; Scale/3.00)",
            "x-device-model": "iPhone",
            "x-device-manufacture": "Apple",
            "x-agent-type": "iOS",
            "x-device-type": "mobile",
            "platform": "NON-CMA",
            "x-env-type": "production",
            "accept-language": "zh-Hans-CN;q=1, en-CN;q=0.9",
            "x-agent-version": "17.4.1",
            "accept": "application/json;responseformat=3",
            "x-device-brand": "Apple",
            "x-operator-code": "ZEEKR",
            "x-device-identifier": self._device_id,
            "authorization": self._access_token or "",
            "x-client-id": self._client_id or "",
        }
        headers.update({
            "x-timestamp": ts,
            "x-api-signature-nonce": nonce,
            "x-signature": self._sign_gw2(method, path, params, payload, ts, nonce),
        })
        return headers

    _GW3_SIGNED = {
        "x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
        "x-api-signature-version", "x-project-id", "authorization",
        "accept-language", "x-vin", "x-device-id", "x-platform",
    }

    def _sign_gw3(self, method: str, path: str, headers: dict[str, str],
                  params: dict | None, payload: Any) -> str:
        head_part = "".join(
            f"{key.lower()}:{headers[key]}\n"
            for key in sorted(
                k for k, v in headers.items()
                if k.lower() in self._GW3_SIGNED and v
            )
        )
        query_part = (
            "&".join(f"{k}={v}" for k, v in sorted((params or {}).items())) + "\n"
            if params else ""
        )
        ctype = headers.get("Content-Type", headers.get("content-type", "")).lower()
        body_part = ""
        if payload and "application/json" in ctype:
            body_part = _b64(hashlib.md5(
                json.dumps(payload, separators=(",", ":")).encode()
            ).digest()) + "\n"
        canonical = head_part + query_part + body_part + method.upper() + "\n" + path
        return hmac.new(_SNC_SECRET.encode(), canonical.encode(),
                        hashlib.sha256).hexdigest()

    def _gw3_headers(self, method: str, path: str, params: dict | None,
                     payload: Any, extra: dict[str, str] | None = None
                     ) -> dict[str, str]:
        ts = _ts()
        nonce = uuid.uuid4().hex.upper()
        headers = {
            "X-APP-ID": "ZEEKRCNCH001M0000",
            "X-TIMESTAMP": ts,
            "X-API-SIGNATURE-VERSION": "2.0",
            "X-SIGNATURE": "",
            "Accept-Language": "zh-CN",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json;charset=UTF-8",
            "X-PROJECT-ID": "ZEEKR",
            "X-P": "iOS",
            "X-DEVICE-ID": self._device_id,
            "X-APP-OS-VERSION": "4.9.9",
            "X-PLATFORM": "APP",
            "X-API-SIGNATURE-NONCE": nonce,
            "User-Agent": (
                "ZeekrLife/2025061706 CFNetwork/3826.500.131 Darwin/24.5.0"
            ),
        }
        if extra:
            headers.update(extra)
        headers["X-SIGNATURE"] = self._sign_gw3(method, path, headers, params, payload)
        return headers

    @staticmethod
    def _encrypt_vin(vin: str) -> str:
        cipher = AES.new(_AES_KEY.encode(), AES.MODE_CBC, _AES_IV.encode())
        return _b64(cipher.encrypt(pad(vin.encode(), AES.block_size)))

    async def _request(self, method: str, url: str, headers: dict[str, str],
                       payload: Any) -> tuple[Any, int]:
        """Perform the HTTP call, tolerating non-JSON bodies."""
        async with self._session.request(
            method, url, headers=headers, json=payload
        ) as response:
            status = response.status
            try:
                return await response.json(content_type=None), status
            except Exception:  # noqa: BLE001 - fall back to text
                text = await response.text()
                try:
                    return json.loads(text), status
                except Exception:  # noqa: BLE001
                    return {"code": str(status), "msg": text[:200]}, status

    @staticmethod
    def _with_query(url: str, params: dict | None) -> str:
        if not params:
            return url
        return url + "?" + "&".join(f"{k}={v}" for k, v in params.items())

    # -- GW1 --------------------------------------------------------------

    async def _gw1(self, method: str, path: str, params: dict | None = None,
                   payload: Any = None) -> dict[str, Any]:
        url = self._with_query(f"{_GW1_BASE}{path}", params)
        result, status = await self._request(method, url, self._gw1_headers(), payload)
        return result if isinstance(result, dict) else {"code": str(status)}

    async def async_send_sms(self, phone: str, region: str = "+86") -> dict[str, Any]:
        """Request an SMS verification code."""
        try:
            return await self._gw1(
                "GET",
                "/zeekrlife-app-user/v1/user/pub/sms/authCode",
                params={"mobile": phone, "x_ca_time": _ts(), "regionCode": region},
            )
        except Exception as exc:  # noqa: BLE001
            raise ZeekrApiError(f"发送验证码请求失败: {exc}") from exc

    async def _gw1_login(self, phone: str, sms_code: str,
                         region: str = "+86") -> dict[str, Any]:
        return await self._gw1(
            "POST",
            "/zeekrlife-app-user/v1/user/pub/login/mobile",
            payload={
                "mobile": phone,
                "deviceId": self._device_id,
                "smsCode": sms_code,
                "channel": 2,
                "x_ca_time": _ts(),
                "deviceName": "iPhone13",
                "skipSmsCode": "0",
                "regionCode": region,
                "ip": "192.168.1.1",
            },
        )

    async def get_access_code(self) -> dict[str, Any]:
        return await self._gw1(
            "GET", "/zeekrlife-mp-auth2/v1/auth/accessCodeList", params={"envType": 3}
        )

    # -- GW2 --------------------------------------------------------------

    async def _gw2(self, method: str, path: str, params: dict | None = None,
                   payload: Any = None) -> dict[str, Any]:
        url = self._with_query(f"{_GW2_BASE}{path}", params)
        headers = self._gw2_headers(method, path, params, payload)
        result, status = await self._request(method, url, headers, payload)
        if _looks_like_auth_error(result, status):
            raise ZeekrAuthError(f"GW2 鉴权失败: {result.get('msg') if isinstance(result, dict) else status}")
        return result if isinstance(result, dict) else {"code": str(status)}

    async def ecar_login(self, auth_code: str) -> dict[str, Any]:
        result = await self._gw2(
            "POST", "/auth/account/session/secure",
            params={"identity_type": "zeekr"}, payload={"authCode": auth_code},
        )
        data = result.get("data") or {}
        if data.get("accessToken"):
            self._access_token = data["accessToken"]
            self._user_id = data.get("userId") or self._user_id
            self._client_id = data.get("clientId") or self._client_id
            self._refresh_token = data.get("refreshToken") or self._refresh_token
        return result

    async def refresh_gw2(self) -> bool:
        if not self._refresh_token:
            return False
        try:
            result = await self._gw2(
                "PUT", "/auth/account/session/secure",
                payload={"refreshToken": self._refresh_token},
            )
        except ZeekrError:
            return False
        data = result.get("data") or {}
        if data.get("accessToken"):
            self._access_token = data["accessToken"]
            self._user_id = data.get("userId") or self._user_id
            self._client_id = data.get("clientId") or self._client_id
            self._refresh_token = data.get("refreshToken") or self._refresh_token
            return True
        return False

    async def get_vehicle_list_gw2(self) -> list[dict[str, Any]]:
        result = await self._gw2(
            "GET", "/device-platform/user/vehicle/secure",
            params={"id": self._user_id or "", "needSharedCar": 1},
        )
        data = _payload_of(result) or {}
        return data.get("list", []) if isinstance(data, dict) else []

    async def get_vehicle_status_gw2(self, vin: str) -> dict[str, Any]:
        result = await self._gw2(
            "GET", f"/remote-control/vehicle/status/{vin}",
            params={"latest": "Local", "target": "basic%2Cmore",
                    "userId": self._user_id or ""},
        )
        data = _payload_of(result) or {}
        if isinstance(data, dict):
            return data.get("vehicleStatus") or data
        return {}

    # -- GW3 --------------------------------------------------------------

    async def _gw3(self, method: str, path: str, params: dict | None = None,
                   payload: Any = None, extra: dict[str, str] | None = None,
                   retry: bool = True) -> dict[str, Any]:
        url = self._with_query(f"{_GW3_BASE}{path}", params)
        headers = self._gw3_headers(method, path, params, payload, extra)
        result, status = await self._request(method, url, headers, payload)
        if _looks_like_auth_error(result, status):
            if retry and await self.async_refresh():
                return await self._gw3(method, path, params, payload, extra,
                                       retry=False)
            raise ZeekrAuthError(
                f"GW3 鉴权失败: {result.get('msg') if isinstance(result, dict) else status}"
            )
        return result if isinstance(result, dict) else {"code": str(status)}

    @staticmethod
    def _gw3_extra(vin: str, token: str | None,
                   app_id: str = "ZEEKRCNCH001M0001") -> dict[str, str]:
        return {
            "X-VIN": ZeekrSmsApiClient._encrypt_vin(vin),
            "X-APP-ID": app_id,
            "Authorization": token or "",
        }

    async def snc_login(self) -> dict[str, Any]:
        result = await self._gw3(
            "POST", "/ms-user-auth/v1.0/auth/login",
            payload={
                "loginDeviceType": 1,
                "identityType": 5,
                "loginSystem": "ios",
                "loginDeviceId": self._device_id,
                "token": self._jwt_token or "",
                "loginPhoneBrand": "Apple",
            },
            extra={"Authorization": self._jwt_token or ""},
            retry=False,
        )
        if result.get("code") == _SUCCESS:
            data = result.get("data") or {}
            self._new_access_token = data.get("accessToken") or self._new_access_token
            self._new_refresh_token = (
                data.get("refreshToken") or self._new_refresh_token
            )
            self._gw3_available = True
        return result

    async def snc_refresh(self) -> bool:
        if not self._new_refresh_token:
            return False
        try:
            result = await self._gw3(
                "POST", "/ms-user-auth/v1.0/auth/refreshToken",
                payload={
                    "loginDeviceType": 1,
                    "loginDeviceId": self._device_id,
                    "loginPhoneBrand": "Apple",
                    "loginSystem": "ios",
                    "refreshToken": self._new_refresh_token,
                    "accessToken": self._new_access_token,
                },
                extra={"Authorization": self._jwt_token or ""},
                retry=False,
            )
        except ZeekrError:
            return False
        if result.get("code") == _SUCCESS:
            data = result.get("data") or {}
            self._new_access_token = data.get("accessToken") or self._new_access_token
            self._new_refresh_token = (
                data.get("refreshToken") or self._new_refresh_token
            )
            self._gw3_available = True
            return True
        return False

    async def get_vehicle_list_gw3(self) -> list[dict[str, Any]]:
        result = await self._gw3(
            "GET", "/ms-app-bff/api/v3.0/veh/vehicle-list",
            params={"needSharedCar": "true"},
            extra={"Authorization": self._jwt_token or ""},
        )
        data = _payload_of(result)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("list") or data.get("vehicles") or []
        return []

    async def get_vehicle_status_gw3(self, vin: str) -> dict[str, Any]:
        result = await self._gw3(
            "GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
            params={"latest": "false", "target": "new"},
            extra=self._gw3_extra(vin, self._new_access_token),
        )
        data = _payload_of(result)
        return data if isinstance(data, dict) else {}

    # -- authentication orchestration ------------------------------------

    async def async_refresh(self) -> bool:
        """Try to renew gateway tokens. Returns True on success."""
        if await self.snc_refresh():
            return True
        if await self.refresh_gw2():
            # A fresh GW2 token lets us re-obtain the GW3 token.
            try:
                if await self.snc_login_with_current_jwt():
                    return True
            except ZeekrError:
                pass
            return True
        return False

    async def snc_login_with_current_jwt(self) -> bool:
        result = await self.snc_login()
        return result.get("code") == _SUCCESS

    async def async_full_login(self, phone: str, sms_code: str,
                               region: str = "+86") -> dict[str, Any]:
        """Run the SMS -> JWT -> accessCode -> GW2 -> GW3 login pipeline."""
        self._phone = phone

        login = await self._gw1_login(phone, sms_code, region)
        if login.get("code") != _SUCCESS:
            message = login.get("msg") or login.get("message") or "验证码校验失败"
            raise ZeekrAuthError(f"短信登录失败: {message}")
        jwt = (login.get("data") or {}).get("jwtToken")
        if not jwt:
            raise ZeekrAuthError("短信登录未返回 JWT")
        self._jwt_token = jwt

        access = await self.get_access_code()
        yikat = (access.get("data") or {}).get("YIKAT_NEW")
        if not yikat:
            raise ZeekrApiError("未获取到 accessCode (YIKAT_NEW)")

        await self.ecar_login(yikat)
        if not self._access_token:
            raise ZeekrAuthError("网关2登录失败：未返回 accessToken")

        try:
            await self.snc_login()
        except ZeekrError as exc:
            _LOGGER.warning("GW3 登录失败（将回退到 GW2）: %s", exc)

        await self.async_get_vehicle_list()
        return {"ok": True, "vehicles": [v.vin for v in self._vehicles]}

    async def async_bootstrap(self) -> list[ZeekrVehicle]:
        """Resume a session from stored tokens and load the vehicle list.

        Raises :class:`ZeekrAuthError` if the stored credentials are dead,
        which the coordinator turns into a reauth prompt.
        """
        if not self._jwt_token:
            raise ZeekrAuthError("缺少登录凭据，请重新登录")
        try:
            await self.async_get_vehicle_list()
        except ZeekrAuthError:
            raise
        except ZeekrError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ZeekrApiError(f"获取车辆列表失败: {exc}") from exc
        return self._vehicles

    # -- data fetching ----------------------------------------------------

    async def async_get_vehicle_list(self) -> list[ZeekrVehicle]:
        entries: list[dict[str, Any]] = []
        try:
            entries = await self.get_vehicle_list_gw3()
        except ZeekrAuthError:
            raise
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("GW3 vehicle list failed: %s", exc)

        if not entries and self._access_token:
            try:
                entries = await self.get_vehicle_list_gw2()
            except ZeekrAuthError:
                raise
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("GW2 vehicle list failed: %s", exc)

        vehicles: list[ZeekrVehicle] = []
        seen: set[str] = set()
        for entry in entries:
            # A few endpoints return bare VIN strings instead of objects.
            if isinstance(entry, str):
                meta: dict[str, Any] = {"vin": entry}
                raw_entry: dict[str, Any] | None = None
            else:
                meta = extract_vehicle_meta(entry)
                raw_entry = entry
            vin = meta.get("vin")
            if not vin or vin in seen:
                continue
            seen.add(vin)
            vehicles.append(ZeekrVehicle(vin, meta, raw_entry))
        self._vehicles = vehicles
        return vehicles

    async def _fetch_raw_status(self, vin: str) -> dict[str, Any]:
        """Fetch the raw status payload for a VIN (GW3 with GW2 fallback)."""
        if self._new_access_token:
            try:
                raw = await self.get_vehicle_status_gw3(vin)
                if raw:
                    for key, value in (await self._gw3_extras(vin)).items():
                        raw.setdefault(key, value)
                    return raw
            except ZeekrAuthError:
                raise
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("GW3 status failed for %s: %s", vin, exc)

        try:
            raw = await self.get_vehicle_status_gw2(vin)
            if raw:
                return raw
        except ZeekrAuthError:
            raise
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("GW2 status failed for %s: %s", vin, exc)
        return {}

    async def _gw3_extras(self, vin: str) -> dict[str, Any]:
        """Fetch auxiliary GW3 payloads (charging status/limit)."""
        extras: dict[str, Any] = {}
        for key, path, params in (
            ("chargingStatus", "/ms-vehicle-status/api/v1.0/vehicle/charging/status",
             {"latest": "true"}),
            ("chargingLimit", "/ms-vehicle-status/api/v1.0/vehicle/charging/limit",
             None),
        ):
            try:
                result = await self._gw3(
                    "GET", path, params=params,
                    extra=self._gw3_extra(vin, self._new_access_token),
                )
                data = _payload_of(result)
                if isinstance(data, dict) and data:
                    extras[key] = data
            except ZeekrAuthError:
                raise
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("GW3 %s failed for %s: %s", key, vin, exc)
        return extras

    async def async_fetch_all(self) -> dict[str, dict[str, Any]]:
        """Fetch + normalise status for every known vehicle."""
        if not self._vehicles:
            await self.async_get_vehicle_list()

        data: dict[str, dict[str, Any]] = {}
        for vehicle in self._vehicles:
            raw = await self._fetch_raw_status(vehicle.vin)
            self._raw_payloads[vehicle.vin] = raw
            canonical = normalize_vehicle_data(raw, vehicle.meta)
            vehicle.data = canonical
            data[vehicle.vin] = canonical
        self._vehicle_data = data
        return data

    async def async_get_location(self, vin: str) -> dict[str, Any]:
        """Return the (normalised) GPS position for a VIN."""
        vehicle = self.get_vehicle(vin)
        cached = (vehicle.data if vehicle else None) or self._vehicle_data.get(vin)
        if cached and (cached.get("position") or {}).get("valid"):
            return cached["position"]
        raw = await self._fetch_raw_status(vin)
        canonical = normalize_vehicle_data(raw, vehicle.meta if vehicle else None)
        if vehicle:
            vehicle.data = canonical
        self._vehicle_data[vin] = canonical
        return canonical.get("position", {})

    # -- remote control ---------------------------------------------------

    async def async_do_remote_control(self, vin: str, command: str,
                                      service_id: str,
                                      setting: dict[str, Any]) -> dict[str, Any]:
        """Send a remote-control command via GW3."""
        if not self._new_access_token:
            raise ZeekrAuthError("缺少 GW3 访问令牌，无法下发指令")
        try:
            result = await self._gw3(
                "POST", "/ms-vehicle-control/api/v1.0/vehicle/control",
                payload={
                    "command": command,
                    "serviceId": service_id,
                    "serviceParameters": setting.get("serviceParameters", []),
                },
                extra=self._gw3_extra(vin, self._new_access_token),
            )
        except ZeekrAuthError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ZeekrApiError(f"指令下发失败({service_id}): {exc}") from exc

        if result.get("code") != _SUCCESS:
            raise ZeekrApiError(
                "车辆拒绝了指令 {sid}: {msg}".format(
                    sid=service_id,
                    msg=result.get("msg") or result.get("code"),
                )
            )
        return result

    async def async_set_charge_plan(self, vin: str, start_time: str,
                                    end_time: str, command: str,
                                    bc_cycle: bool = False,
                                    bc_temp: bool = False) -> dict[str, Any]:
        return await self._gw3(
            "POST", "/ms-app-bff/api/v3.0/veh/charge/plan",
            payload={
                "command": command,
                "startTime": start_time,
                "endTime": end_time,
                "bcCycleActive": bc_cycle,
                "bcTempActive": bc_temp,
            },
            extra=self._gw3_extra(vin, self._new_access_token),
        )

    async def async_set_travel_plan(self, vin: str, command: str,
                                    start_time: str, scheduled_time: str,
                                    ac_preconditioning: bool = True,
                                    steering_wheel_heating: bool = False
                                    ) -> dict[str, Any]:
        return await self._gw3(
            "POST", "/ms-app-bff/api/v3.0/veh/travel/plan",
            payload={
                "command": command,
                "startTime": start_time,
                "scheduledTime": scheduled_time,
                "ac": "true" if ac_preconditioning else "false",
                "bw": "1" if steering_wheel_heating else "0",
            },
            extra=self._gw3_extra(vin, self._new_access_token),
        )

    # -- diagnostics ------------------------------------------------------

    def dump_raw(self) -> dict[str, Any]:
        """Return raw payloads for the whole account (secrets excluded)."""
        return {
            "device_id": self._device_id,
            "phone": self._phone,
            "gw3_available": self._gw3_available,
            "vehicles": [
                {"vin": v.vin, **v.meta} for v in self._vehicles
            ],
            "raw_payloads": self._raw_payloads,
        }
