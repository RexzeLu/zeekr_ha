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

# The SNCTSP (GW3) gateway identifies the app twice in every request.  The
# signing key is looked up by ``X-APP-ID``; a value it does not know comes back
# as ``079025 Signature authentication failed``.  Both values below are taken
# from a captured request of the official app and apply to *all* GW3 endpoints,
# ``/ms-user-auth/v1.0/auth/login`` included.
_GW3_APP_ID = "ZEEKRCNCH001M0001"
_GW3_APPID_HEADER = "ONEX97FB91F061405"

_SUCCESS = "000000"
# GW2 (the legacy `api.zeekrline.com` pipe) reports success as "1000"/"操作成功"
# instead of the "000000" the SNCTSP and GW1 gateways use.
_SUCCESS_CODES = {_SUCCESS, "1000"}

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


def _response_brief(result: Any) -> dict[str, Any]:
    """Summarise a gateway response without leaking credentials.

    Tokens are only ever reported as *which fields the backend answered with*,
    which is what makes a silent GW3 login failure debuggable.
    """
    if not isinstance(result, dict):
        return {"code": None, "msg": str(result)[:200], "data_keys": None}
    data = result.get("data")
    return {
        "code": result.get("code"),
        "msg": result.get("msg") or result.get("message"),
        "data_keys": sorted(data) if isinstance(data, dict) else None,
    }


def _pick(data: Any, *keys: str) -> Any:
    """First non-empty value among ``keys``."""
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if value:
            return value
    return None


def _json_body(payload: Any) -> bytes | None:
    """Serialise a request body exactly the way the signatures hash it.

    GW2 and GW3 embed ``base64(md5(body))`` in their canonical string, so the
    bytes we sign and the bytes we put on the wire must be **byte-identical**.
    The reference client is a JavaScript app, where ``JSON.stringify`` emits
    compact JSON — no spaces after ``:`` or ``,`` — which is what
    ``separators=(",", ":")`` reproduces.

    Passing ``json=payload`` to aiohttp instead lets ``json.dumps`` use its
    default ``", "`` / ``": "`` separators, so every POST was signed over one
    byte string and sent as another.  The gateway answers
    ``079025 Signature authentication failed`` for all of them (login included),
    while GETs — which carry no body — kept working.
    """
    if payload is None:
        return None
    return json.dumps(payload, separators=(",", ":")).encode()


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
        # GW3 (SNCTSP) is the only gateway that accepts remote-control writes,
        # so its login result is kept verbatim-ish: a silent failure here is
        # exactly what later shows up as "缺少 GW3 访问令牌".
        self._gw3_login: dict[str, Any] | None = None
        self._gw3_login_error: str | None = None
        # Shape of the most recent GW3 request — what a "signature
        # authentication failed" has to be compared against.
        self._gw3_last_request: dict[str, Any] | None = None
        self._gw3_last_rejected: dict[str, Any] | None = None
        # Which gateway actually served the data (diagnostics only).
        self._status_source: dict[str, str] = {}
        self._vehicle_list_source: str | None = None
        # Outcome of the gateways tried by the last remote-control command.
        self._command_attempts: list[dict[str, Any]] = []

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

    # -- gateway state ----------------------------------------------------

    @property
    def has_gw3_token(self) -> bool:
        """Whether remote control can be attempted at all."""
        return bool(self._new_access_token)

    def gateway_summary(self) -> dict[str, Any]:
        """Gateway health for the diagnostics dump (never includes tokens)."""
        return {
            "gw3_available": self._gw3_available,
            "gw3_has_token": self.has_gw3_token,
            "gw3_login": self._gw3_login,
            "gw3_login_error": self._gw3_login_error,
            "vehicle_list_source": self._vehicle_list_source,
            "status_source": dict(self._status_source),
            "gw3_last_request": self._gw3_last_request,
            "gw3_last_rejected": self._gw3_last_rejected,
            "command_attempts": list(self._command_attempts),
        }

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
            _json_body(payload) or b""
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

    @staticmethod
    def _gw3_escape_query(params: dict | None) -> str:
        """Serialise query params the way the app does.

        The reference client (Node-RED flow / official app) builds the query
        with these substitutions: ``*`` → ``%2A``, then ``%2F`` → ``/`` and
        ``%3F`` → ``?`` (undoing those two percent-encodings), keys sorted.
        """
        if not params:
            return ""
        parts = []
        for key in sorted(params):
            value = params[key]
            escaped = str(value).replace("*", "%2A").replace("%2F", "/").replace("%3F", "?")
            parts.append(f"{key}={escaped}")
        return "&".join(parts)

    def _sign_gw3(self, method: str, path: str, headers: dict[str, str],
                  params: dict | None, payload: Any) -> str:
        # Header part: lower-cased name + value, keys sorted, matching the
        # reference implementation.  ``x-vin`` / ``authorization`` are dropped
        # when empty; the other signed headers are emitted as-is.
        header_lines: list[str] = []
        for key in sorted(headers, key=str.lower):
            lower = key.lower()
            if lower not in self._GW3_SIGNED:
                continue
            value = headers[key]
            if lower in ("x-vin", "authorization") and not value:
                continue
            header_lines.append(f"{lower}:{value}\n")
        head_part = "".join(header_lines)

        query = self._gw3_escape_query(params)
        query_part = query + "\n" if query else ""

        ctype = headers.get("Content-Type", headers.get("content-type", "")).lower()
        body = _json_body(payload)
        body_part = ""
        if body is not None and "application/json" in ctype:
            body_part = _b64(hashlib.md5(body).digest()) + "\n"

        canonical = head_part + query_part + body_part + method.upper() + "\n" + path
        digest = hmac.new(_SNC_SECRET.encode(), canonical.encode(),
                          hashlib.sha256).digest()
        # The app encodes the HMAC as Base64, not hex.
        return _b64(digest)

    def _gw3_headers(self, method: str, path: str, params: dict | None,
                     payload: Any, extra: dict[str, str] | None = None
                     ) -> dict[str, str]:
        ts = _ts()
        # The Zeekr app sends a plain dashed UUID here; the gateway is known to
        # accept the app's request verbatim, so match it.
        nonce = str(uuid.uuid4())
        headers = {
            # Every GW3 call — auth/login included — uses the *same* app id.
            # The gateway looks the signing key up by X-APP-ID, so a wrong one
            # is reported as "Signature authentication failed" rather than as an
            # unknown app.  Values below mirror a captured, working app request.
            "X-APP-ID": _GW3_APP_ID,
            "AppId": _GW3_APPID_HEADER,
            "X-TIMESTAMP": ts,
            "X-API-SIGNATURE-VERSION": "2.0",
            "X-SIGNATURE": "",
            "Accept-Language": "en-US",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/json; charset=UTF-8",
            "X-PROJECT-ID": "ZEEKR",
            "X-P": "Android",
            "X-DEVICE-ID": self._device_id,
            "X-APP-OS-VERSION": "4.9.28",
            "X-PLATFORM": "APP",
            "X-API-SIGNATURE-NONCE": nonce,
            "User-Agent": "okhttp/4.12.0",
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
        """Perform the HTTP call, tolerating non-JSON bodies.

        The body is serialised here — not handed to aiohttp as ``json=`` — so the
        bytes on the wire are exactly the ones the signature hashed.  See
        :func:`_json_body` for why that matters.
        """
        body = _json_body(payload)
        request_kwargs: dict[str, Any] = {"headers": headers}
        if body is not None:
            request_kwargs["data"] = body
        async with self._session.request(method, url, **request_kwargs) as response:
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

    def _gw3_request_shape(self, method: str, path: str, headers: dict[str, str],
                           params: dict | None, payload: Any) -> dict[str, Any]:
        """Describe a GW3 request without its secrets.

        A ``Signature authentication failed`` is only actionable if we can see
        which headers went into the canonical string and which app id was used —
        those are exactly the two things that differ between the endpoints that
        work (GET, no body) and the ones that get rejected (POST).
        """
        body = _json_body(payload)
        return {
            "method": method.upper(),
            "path": path,
            "app_id": headers.get("X-APP-ID"),
            # In the order the canonical string signs them.
            "signed_headers": sorted(
                key for key, value in headers.items()
                if key.lower() in self._GW3_SIGNED and value
            ),
            "query": "&".join(
                f"{k}={v}" for k, v in sorted((params or {}).items())
            ),
            "body_md5_b64": _b64(hashlib.md5(body).digest())
            if body is not None else None,
            "content_type": headers.get(
                "Content-Type", headers.get("content-type")
            ),
            "has_authorization": bool(headers.get("Authorization")),
        }

    async def _gw3(self, method: str, path: str, params: dict | None = None,
                   payload: Any = None, extra: dict[str, str] | None = None,
                   retry: bool = True) -> dict[str, Any]:
        url = self._with_query(f"{_GW3_BASE}{path}", params)
        headers = self._gw3_headers(method, path, params, payload, extra)
        shape = self._gw3_request_shape(method, path, headers, params, payload)
        self._gw3_last_request = shape
        result, status = await self._request(method, url, headers, payload)
        if not isinstance(result, dict) or result.get("code") != _SUCCESS:
            # Kept apart from ``last_request``: the coordinator keeps polling
            # GETs after a command fails, and those would overwrite the very
            # request we need to look at.
            self._gw3_last_rejected = {
                **shape,
                "status": status,
                "response": _response_brief(result),
            }
        if _looks_like_auth_error(result, status):
            if retry and await self.async_refresh():
                return await self._gw3(method, path, params, payload, extra,
                                       retry=False)
            raise ZeekrAuthError(
                f"GW3 鉴权失败: {result.get('msg') if isinstance(result, dict) else status}"
            )
        return result if isinstance(result, dict) else {"code": str(status)}

    def _first_known_vin(self) -> str | None:
        """A VIN to identify the car with, when one is already known.

        GW3 auth calls carry ``X-VIN`` just like the data calls do.  On the very
        first login nothing is known yet, which is fine — the header is simply
        omitted until the (GW2-served) vehicle list has arrived.
        """
        if self._vehicles:
            return self._vehicles[0].vin
        for vin in self._vehicle_data:
            return vin
        return None

    @staticmethod
    def _bearer(token: str | None) -> str:
        """``Authorization`` value for a GW3 access token.

        The gateway answers with the token already prefixed (``"Bearer ey…"``),
        in which case it is passed through untouched; anything else gets the
        prefix added so the header is well-formed either way.
        """
        if not token:
            return ""
        return token if token.lower().startswith("bearer ") else f"Bearer {token}"

    @staticmethod
    def _gw3_extra(vin: str | None, token: str | None) -> dict[str, str]:
        """Extra GW3 headers: the encrypted VIN, plus a token when there is one.

        Both are omitted rather than sent blank — the app simply leaves the
        header out, and an empty-but-present header is not the same request.
        """
        extra: dict[str, str] = {}
        if vin:
            extra["X-VIN"] = ZeekrSmsApiClient._encrypt_vin(vin)
        if token:
            extra["Authorization"] = ZeekrSmsApiClient._bearer(token)
        return extra

    def _absorb_gw3_tokens(self, result: dict[str, Any], what: str) -> bool:
        """Store the tokens of a successful GW3 auth response."""
        data = result.get("data") or {}
        token = _pick(data, "accessToken", "access_token", "tokenValue")
        if not token:
            self._gw3_login_error = (
                f"{what} 成功但响应里没有 accessToken（data 字段: "
                f"{sorted(data) if isinstance(data, dict) else type(data).__name__}）"
            )
            _LOGGER.error("%s —— 远程指令将不可用", self._gw3_login_error)
            return False

        self._new_access_token = token
        self._new_refresh_token = (
            _pick(data, "refreshToken", "refresh_token") or self._new_refresh_token
        )
        self._gw3_available = True
        self._gw3_login_error = None
        _LOGGER.debug("GW3 %s 成功", what)
        return True

    async def snc_login(self) -> dict[str, Any]:
        """Log into the SNCTSP (GW3) gateway with the GW1 JWT.

        Never raises: the response is recorded either way, because a silent
        failure here is what later surfaces as a bare "缺少 GW3 访问令牌" when
        the user tries to control the car.
        """
        try:
            result = await self._gw3(
                "POST", "/ms-user-auth/v1.0/auth/login",
                payload={
                    "credential": "",
                    "identifier": "",
                    "identityType": 5,
                    "loginDeviceId": self._device_id,
                    "loginDeviceJgId": "",
                    "loginDeviceType": 1,
                    "loginPhoneBrand": "Android",
                    "loginPhoneModel": "Android SDK built for arm64",
                    "loginSystem": "Android",
                    # The app forwards the JWT straight out of the GW1 answer,
                    # which already carries the "Bearer " prefix.
                    "token": self._bearer(self._jwt_token),
                },
                # No Authorization header here — the app authenticates this call
                # with the JWT in the body, but it *does* identify the car.
                extra=self._gw3_extra(self._first_known_vin(), None),
                retry=False,
            )
        except ZeekrError as exc:
            self._gw3_login_error = f"GW3 登录请求失败: {exc}"
            _LOGGER.error("%s —— 远程指令将不可用", self._gw3_login_error)
            return {"code": None, "msg": str(exc)}

        self._gw3_login = _response_brief(result)
        if result.get("code") == _SUCCESS:
            if not self._absorb_gw3_tokens(result, "登录"):
                self._gw3_login = _response_brief(result)
        else:
            self._gw3_login_error = (
                "GW3 登录被拒绝: code={code} msg={msg}".format(
                    code=result.get("code"),
                    msg=result.get("msg") or result.get("message"),
                )
            )
            _LOGGER.error("%s —— 远程指令将不可用", self._gw3_login_error)
        return result

    async def snc_refresh(self) -> bool:
        if not self._new_refresh_token:
            return False
        try:
            result = await self._gw3(
                "POST", "/ms-user-auth/v1.0/auth/refreshToken",
                payload={
                    "loginDeviceId": self._device_id,
                    "loginDeviceType": 1,
                    "loginPhoneBrand": "Android",
                    "loginPhoneModel": "Android SDK built for arm64",
                    "loginSystem": "Android",
                    "refreshToken": self._new_refresh_token,
                    "accessToken": self._new_access_token,
                },
                # Mirrors the login call: tokens travel in the body, the request
                # only carries the encrypted VIN.
                extra=self._gw3_extra(self._first_known_vin(), None),
                retry=False,
            )
        except ZeekrError as exc:
            _LOGGER.debug("GW3 token 刷新失败: %s", exc)
            return False
        if result.get("code") == _SUCCESS:
            return self._absorb_gw3_tokens(result, "token 刷新")
        _LOGGER.debug(
            "GW3 token 刷新被拒绝: code=%s msg=%s",
            result.get("code"), result.get("msg"),
        )
        return False

    async def async_ensure_gw3_token(self) -> bool:
        """Make sure a GW3 token exists, renewing it when possible.

        Called before every command: the token may simply not have been issued
        at login time (or may have expired since), and the GW1 JWT is enough to
        ask for a fresh one.
        """
        if self._new_access_token:
            return True

        try:
            if await self.snc_refresh():
                return True
        except ZeekrError as exc:  # pragma: no cover - snc_refresh swallows
            _LOGGER.debug("GW3 token 刷新异常: %s", exc)

        # A fresh GW2 token lets the GW3 login be retried from scratch.
        try:
            await self.refresh_gw2()
        except ZeekrError as exc:
            _LOGGER.debug("GW2 token 刷新失败: %s", exc)
        await self.snc_login()
        return bool(self._new_access_token)

    async def _require_gw3_token(self) -> None:
        """Guarantee a GW3 token or explain precisely why we cannot."""
        if self._new_access_token or await self.async_ensure_gw3_token():
            return
        reason = self._gw3_login_error or "原因未知（GW3 登录未返回任何错误信息）"
        raise ZeekrAuthError(
            "无法下发指令：缺少 GW3 访问令牌，自动获取也失败。"
            f"最后一次 GW3 登录结果：{reason}。"
            "可先尝试「设置 → 设备与服务 → 极氪 → 重新认证」重新登录；"
            "若仍失败请下载诊断信息反馈，其中的 gw3 段包含网关原始返回码。"
        )

    async def get_vehicle_list_gw3(self) -> list[dict[str, Any]]:
        result = await self._gw3(
            "GET", "/ms-app-bff/api/v3.0/veh/vehicle-list",
            params={"needSharedCar": "true"},
            # The GW3 access token is the one the app presents once logged in;
            # the GW1 JWT is only the seed used to obtain it.
            extra={
                "Authorization": self._bearer(
                    self._new_access_token or self._jwt_token
                )
            },
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

        # Learn the VIN before talking to GW3: GW2 serves the list happily, and
        # the GW3 auth call carries X-VIN the way the app's does.
        await self.async_get_vehicle_list()

        await self.snc_login()
        if not self._new_access_token:
            _LOGGER.warning(
                "GW3 登录没有取得令牌：车辆状态会回退到 GW2，但远程指令（车锁 / "
                "空调等）将无法下发。原因：%s",
                self._gw3_login_error,
            )

        return {"ok": True, "vehicles": [v.vin for v in self._vehicles]}

    async def async_bootstrap(self) -> list[ZeekrVehicle]:
        """Resume a session from stored tokens and load the vehicle list.

        Raises :class:`ZeekrAuthError` if the stored credentials are dead,
        which the coordinator turns into a reauth prompt.
        """
        if not self._jwt_token:
            raise ZeekrAuthError("缺少登录凭据，请重新登录")
        # Load the vehicle list first: it is served happily by GW2 even when GW3
        # is down, and knowing a VIN lets the GW3 auth calls carry X-VIN the way
        # the app does.
        try:
            await self.async_get_vehicle_list()
        except ZeekrAuthError:
            raise
        except ZeekrError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ZeekrApiError(f"获取车辆列表失败: {exc}") from exc
        # GW3 is the only gateway that accepts commands; re-acquire its token on
        # every start-up (the JWT alone is enough) instead of only at login.
        await self.async_ensure_gw3_token()
        return self._vehicles

    # -- data fetching ----------------------------------------------------

    async def async_get_vehicle_list(self) -> list[ZeekrVehicle]:
        entries: list[dict[str, Any]] = []
        source: str | None = None
        try:
            entries = await self.get_vehicle_list_gw3()
            if entries:
                source = "gw3"
        except Exception as exc:  # noqa: BLE001
            # A GW3-auth failure says nothing about the account credentials —
            # GW2 is the authority on those and is consulted below.  Raising
            # here would turn a GW3-side problem into a bogus reauth prompt.
            _LOGGER.debug("GW3 vehicle list failed: %s", exc)

        if not entries and self._access_token:
            try:
                entries = await self.get_vehicle_list_gw2()
                if entries:
                    source = "gw2"
            except ZeekrAuthError:
                raise
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("GW2 vehicle list failed: %s", exc)
        self._vehicle_list_source = source

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
                    self._status_source[vin] = "gw3"
                    return raw
            except Exception as exc:  # noqa: BLE001
                # GW3 auth problems must not be mistaken for dead account
                # credentials — GW2 below decides that.
                _LOGGER.debug("GW3 status failed for %s: %s", vin, exc)

        try:
            raw = await self.get_vehicle_status_gw2(vin)
            if raw:
                self._status_source[vin] = "gw2"
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
            except Exception as exc:  # noqa: BLE001
                # Auxiliary payloads (charging status/limit) are optional.
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

    def _telematics_body(self, command: str, service_id: str,
                         setting: dict[str, Any]) -> dict[str, Any]:
        """Body for the classic ECARX/Geely "telematics" write pipe.

        ``{command, serviceId, serviceParameters}`` is the essential part; the
        surrounding fields mirror the shape the sibling Geely integration sends
        (``creator`` / ``timestamp`` / ``userId``, plus an optional
        ``operationScheduling`` window for timed runs such as pre-conditioning).
        """
        body: dict[str, Any] = {
            "command": command,
            "creator": "tc",
            "serviceId": service_id,
            "serviceParameters": list(setting.get("serviceParameters") or []),
            "timestamp": _ts(),
        }
        if self._user_id:
            body["userId"] = self._user_id
        duration = setting.get("duration")
        if duration is not None:
            body["operationScheduling"] = {
                "duration": int(duration),
                "interval": 0,
                "occurs": 1,
                "recurrentOperation": False,
            }
        return body

    async def _command_via_gw2(self, vin: str, command: str, service_id: str,
                               setting: dict[str, Any]) -> dict[str, Any]:
        """``PUT /remote-control/vehicle/telematics/{VIN}``.

        GW2 already serves the ``/remote-control/`` family for us (that is where
        vehicle status comes from), and this is the write path of the same pipe
        on the ECARX platform the Zeekr backend is built on.
        """
        return await self._gw2(
            "PUT", f"/remote-control/vehicle/telematics/{vin}",
            payload=self._telematics_body(command, service_id, setting),
        )

    async def _command_via_gw3(self, vin: str, command: str, service_id: str,
                               setting: dict[str, Any]) -> dict[str, Any]:
        """SNCTSP remote-control endpoint — the one the app actually uses.

        ``/ms-remote-control/v1.0/remoteControl/control`` with
        ``{command, serviceId, setting:{serviceParameters}}``.  The path/first
        shape was taken from a working Zeekr integration that authenticates
        against this very gateway; the earlier ``ms-vehicle-control/...`` path
        was an invention and 404s.
        """
        await self._require_gw3_token()
        return await self._gw3(
            "POST", "/ms-remote-control/v1.0/remoteControl/control",
            payload={
                "command": command,
                "serviceId": service_id,
                "setting": {
                    "serviceParameters": list(
                        setting.get("serviceParameters") or []
                    ),
                },
            },
            extra=self._gw3_extra(vin, self._new_access_token),
        )

    async def async_do_remote_control(self, vin: str, command: str,
                                      service_id: str,
                                      setting: dict[str, Any]) -> dict[str, Any]:
        """Send a remote-control command, reporting which gateway took it."""
        # Recorded as we go, so the diagnostics keep the trail even on success.
        attempts: list[dict[str, Any]] = []
        self._command_attempts = attempts
        failures: list[str] = []
        # GW3 first: that is where the app's control endpoint lives.  The GW2
        # telematics pipe used to answer "1000 操作成功" and then do nothing, so
        # it is only a fallback.
        for name, sender in (("gw3", self._command_via_gw3),
                             ("gw2", self._command_via_gw2)):
            try:
                result = await sender(vin, command, service_id, setting)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{name}: {exc}")
                attempts.append({"gateway": name, "error": str(exc)})
                continue

            code = str(result.get("code") or "")
            accepted = code in _SUCCESS_CODES or result.get("success") is True
            attempts.append({
                "gateway": name,
                "code": result.get("code"),
                "msg": result.get("msg") or result.get("message"),
            })
            if accepted:
                _LOGGER.debug("指令 %s 经 %s 被接受", service_id, name)
                return {**result, "gateway": name}
            failures.append(f"{name}: {result.get('msg') or code}")

        raise ZeekrApiError(
            "车辆拒绝了指令 {sid}（依次尝试 {tried}）：{why}".format(
                sid=service_id,
                tried=" → ".join(item["gateway"] for item in attempts),
                why="；".join(failures),
            )
        )

    async def async_set_charge_plan(self, vin: str, start_time: str,
                                    end_time: str, command: str,
                                    bc_cycle: bool = False,
                                    bc_temp: bool = False) -> dict[str, Any]:
        await self._require_gw3_token()
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
        await self._require_gw3_token()
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
            "gateways": self.gateway_summary(),
            "vehicles": [
                {"vin": v.vin, **v.meta} for v in self._vehicles
            ],
            "raw_payloads": self._raw_payloads,
        }
