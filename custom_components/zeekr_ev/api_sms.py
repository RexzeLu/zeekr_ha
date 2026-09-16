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
    CREDENTIAL_REVISION,
    DEFAULT_LOGIN_DEVICE_ID,
    DEVICE_MODEL,
    DEVICE_SDK,
    STORAGE_ACCESS_TOKEN,
    STORAGE_CLIENT_ID,
    STORAGE_CREDENTIAL_REVISION,
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

_GW1_HOST = "api-gw-toc.zeekrlife.com"
_GW1_BASE = f"https://{_GW1_HOST}"

# The app version every GW3 request claims to come from.  It mirrors a captured
# request (``4.9.28``, 2026-01) — but that capture is eight months old and the
# owner's App is now ``5.0.5``.  Gateways commonly expose interfaces only from a
# minimum client version onwards, and this is the one field that says which
# client we are, so it is kept in step with the real App rather than frozen at
# the captured value.  (The signature version actually used is unchanged; see
# ``_LOGIN_VARIANTS`` for the combinations worth trying.)
_GW3_APP_VERSION = "5.0.5"
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

# The account holds a single SNCTSP session: each fresh login invalidates the
# previous token, and using a superseded one answers 079021 "logged in
# elsewhere".  Renewing the login is the cure.
_DISPLACED_CODES = {"079021"}
_DISPLACED_MARKERS = ("logged in elsewhere", "已在其他设备登录", "别处登录")

# "This interface is not authorized" — the token is fine, the endpoint just is
# not permitted for it.  Re-logging in cannot help, and doing so would only
# invalidate the session we are already using, so it must NOT be treated as a
# session problem.
_FORBIDDEN_CODES = {"079001"}
_FORBIDDEN_MARKERS = ("未被授权", "not authorized")

# The vehicle interfaces (status, remote control) are authorised by a token
# minted from a short-lived ``tspCode``, NOT by the legacy ``identityType: 5``
# login this integration has used from the start.  The published client fetches
# the code from ``user/tspCode`` on its regional IDaaS host — with the region
# baked into BOTH the host (``gateway-pub-hw-em-sg``) and the path prefix
# (``zeekr-cuc-idaas-sea``).  China's pair is published nowhere, so the plausible
# combinations are asked in turn; which host/prefix answers at all is what pins
# it down.  A 404 costs one request and settles a candidate for good.
_TSP_CODE_CANDIDATES = (
    ("api-gw-toc.zeekrlife.com", "/zeekr-cuc-idaas-cn/user/tspCode"),
    ("api-gw-toc.zeekrlife.com", "/zeekrlife-app-user/v1/user/tspCode"),
    ("api-gw-toc.zeekrlife.com", "/zeekrlife-mp-auth2/v1/auth/tspCode"),
    ("api-gw-toc.zeekrlife.com", "/zeekr-cuc-idaas-cn/user/tsp/code"),
)
# The SEA-style hosts (``gateway-pub-hw-em-sg`` and friends) are deliberately
# absent: ``gateway-pub-hw-em-cn`` / ``-em`` / ``-cn`` were tried and do not even
# resolve in China, so the regional host cannot be guessed from the SEA name.
# ``client-id`` values known from the published clients.  The account's own id
# (handed out by GW2) is preferred — it is the one that describes this user.
_TSP_CLIENT_IDS = (
    "1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc",
    "2JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc",
)
# Hard cap: this runs at most once per process, and only after the gateway has
# already told us the current token cannot reach a vehicle interface.  A build
# that never needs it pays nothing.
_TSP_CODE_ATTEMPT_LIMIT = 8

# "Decrypt X-VIN failed" — the gateway could not open the ``X-VIN`` header it
# was given.  The app AES-encrypts the VIN (see :meth:`ZeekrSmsApiClient.
# _encrypt_vin`), so this code always means the header was sent in the wrong
# encoding — a plain VIN is exactly the thing that cannot be decrypted.
_VIN_DECRYPT_CODES = {"079025"}
_VIN_DECRYPT_MARKERS = ("decrypt x-vin",)


def _is_vin_decrypt_failure(result: Any) -> bool:
    """True when the gateway could not decrypt our ``X-VIN`` header."""
    if not isinstance(result, dict):
        return False
    if str(result.get("code") or "") in _VIN_DECRYPT_CODES:
        return True
    blob = _result_text(result).lower()
    return any(marker in blob for marker in _VIN_DECRYPT_MARKERS)


class ZeekrError(Exception):
    """Base class for Zeekr API errors."""


class ZeekrAuthError(ZeekrError):
    """Credentials missing/expired/rejected – the config entry needs reauth."""


class ZeekrApiError(ZeekrError):
    """Non-auth API failure (network, business rejection, ...)."""


def _data_shape(value: Any, prefix: str = "", depth: int = 2,
                limit: int = 60) -> list[str]:
    """The *shape* of a response body: dotted key paths, never their values.

    A successful GW3 login is the one response whose fields we cannot guess —
    it is where a per-vehicle token would have to arrive, if the platform hands
    one out at all.  Listing nested paths (``data.vehicle.encVin``) is what makes
    that visible while keeping credentials out of the diagnostics file.
    """
    if depth <= 0:
        return []
    if isinstance(value, list):
        first = next(
            (item for item in value if isinstance(item, (dict, list))), None
        )
        # A list is a container, not a level of nesting: descending into it must
        # not spend budget, or ``{"list": [{...}]}`` comes back as just "list".
        return _data_shape(first, prefix + "[0].", depth, limit)
    if not isinstance(value, dict):
        return []
    paths: list[str] = []
    for key in sorted(value):
        item = value[key]
        path = f"{prefix}{key}"
        paths.append(path)
        if isinstance(item, (dict, list)):
            paths.extend(_data_shape(item, path + ".", depth - 1, limit))
        if len(paths) >= limit:
            break
    return paths[:limit]


def _response_brief(result: Any) -> dict[str, Any]:
    """Summarise a gateway response without leaking credentials.

    Tokens are only ever reported as *which fields the backend answered with*
    (and how those fields nest), which is what makes a silent GW3 login failure
    debuggable.
    """
    if not isinstance(result, dict):
        return {"code": None, "msg": str(result)[:200], "data_keys": None}
    data = result.get("data")
    return {
        "code": result.get("code"),
        "msg": result.get("msg") or result.get("message"),
        "data_keys": _data_shape(data) if data is not None else None,
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


def _result_text(result: Any) -> str:
    """Lower-cased message blob of a gateway response."""
    if not isinstance(result, dict):
        return ""
    return " ".join(
        str(result.get(key, "")) for key in ("msg", "message", "error", "errorMsg")
    ).lower()


def _is_displaced(result: Any) -> bool:
    """True when the gateway says another login owns the account's session."""
    if not isinstance(result, dict):
        return False
    if str(result.get("code") or "") in _DISPLACED_CODES:
        return True
    blob = _result_text(result)
    return any(marker in blob for marker in _DISPLACED_MARKERS)


def _is_forbidden_interface(result: Any) -> bool:
    """True for "interface not authorized" — a permission, not a session, issue."""
    if not isinstance(result, dict):
        return False
    if str(result.get("code") or "") in _FORBIDDEN_CODES:
        return True
    blob = _result_text(result)
    return any(marker in blob for marker in _FORBIDDEN_MARKERS)


def _looks_like_auth_error(result: Any, status: int | None = None) -> bool:
    # An endpoint the token is simply not entitled to says nothing about the
    # session: re-authenticating would not help and would only displace the
    # token we are using, so it must not be reported as an auth failure.
    if _is_forbidden_interface(result):
        return False
    # A superseded session is recoverable by logging in again — and its message
    # contains none of the generic markers below, so it needs its own check.
    if _is_displaced(result):
        return True
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


def _ok_payload(result: Any) -> Any:
    """Body of a **successful** response, else ``None``.

    Gateways answer failures with an envelope of their own (``code`` / ``msg`` /
    ``success`` and no ``data``).  Treating that as a payload is how an error
    once reached the parser and turned every entity into *unknown*, so every
    consumer guards on this instead of on "is it a non-empty dict".
    """
    if not isinstance(result, dict):
        return None
    code = str(result.get("code") or "")
    if code and code not in _SUCCESS_CODES and result.get("success") is not True:
        return None
    return _payload_of(result)


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
        # Sent as ``loginDeviceId``; see DEFAULT_LOGIN_DEVICE_ID for why this is
        # a composite string rather than the uuid above.
        self._login_device_id = DEFAULT_LOGIN_DEVICE_ID
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
        # How X-VIN is encoded, and whether the alternative was already tried.
        #
        # Encrypted is the default because it is what the app does and what the
        # gateway demonstrably expects: sending the VIN in the clear answers
        # ``079025 Decrypt X-VIN failed``.  The plain form is still reachable as
        # a single fallback, because one independent integration sends it that
        # way — but it can only ever be the *second* thing we try.
        self._gw3_vin_encrypted = True
        self._gw3_vin_flipped = False
        # Every X-VIN encoding tried, with the gateway's verdict — this is what
        # settles the question when a dump comes back.
        self._gw3_vin_attempts: list[dict[str, Any]] = []
        # Opaque per-vehicle ``X-VIN`` token (None = derive it locally by
        # encrypting the VIN), and where it came from ("configured" or
        # "backend:<field>") — diagnostics only, never the value itself.
        self._vehicle_token: str | None = None
        self._vehicle_token_source: str | None = None
        # Which generation of the platform minted the GW3 token in hand:
        # "legacy" (identityType 5 + JWT) or "platform" (tspCode exchange).  The
        # legacy token reaches the legacy vehicle list but is refused by the
        # vehicle interfaces with 079001.
        self._gw3_token_source = "legacy"
        # Steps of the one-shot tspCode chain, and whether it already ran.
        self._platform_chain: list[dict[str, Any]] = []
        self._platform_chain_done = False
        # Header overrides adopted from a login variant that turned out to open
        # the vehicle interfaces; applied to every request while it is set.
        self._variant_headers: dict[str, str] = {}

    # -- token persistence ------------------------------------------------

    def set_device_id(self, device_id: str | None) -> None:
        if device_id:
            self._device_id = device_id

    def set_vehicle_token(self, token: str | None) -> None:
        """Use the app's own ``X-VIN`` value instead of a locally derived one."""
        token = (token or "").strip()
        self._vehicle_token = token or None
        self._vehicle_token_source = "configured" if token else None

    def store_tokens(self, data: dict[str, Any]) -> None:
        """Load persisted tokens / identifiers from a config entry."""
        # A token minted by an older login shape describes a session the gateway
        # built from a request this build has since corrected, so reusing it
        # would keep the fix from taking effect.  Only the GW3 token is dropped
        # — the GW1/GW2 credentials stay, so this costs one silent
        # ``snc_login`` and never a reauth.
        stale_session = (
            data.get(STORAGE_CREDENTIAL_REVISION) != CREDENTIAL_REVISION
        )
        self._device_id = data.get(STORAGE_DEVICE_ID) or self._device_id
        self._phone = data.get(CONF_PHONE) or self._phone
        self._jwt_token = data.get(STORAGE_JWT_TOKEN) or self._jwt_token
        self._access_token = data.get(STORAGE_ACCESS_TOKEN) or self._access_token
        self._refresh_token = data.get(STORAGE_REFRESH_TOKEN) or self._refresh_token
        self._user_id = data.get(STORAGE_USER_ID) or self._user_id
        self._client_id = data.get(STORAGE_CLIENT_ID) or self._client_id
        if not stale_session:
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
            STORAGE_CREDENTIAL_REVISION: CREDENTIAL_REVISION,
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
            "gw3_vin_encrypted": self._gw3_vin_encrypted,
            # Only whether it is set (and where it came from) — the token itself
            # is a capability secret.
            "vehicle_token_configured": bool(self._vehicle_token),
            "vehicle_token_source": self._vehicle_token_source,
            "gw3_vin_attempts": list(self._gw3_vin_attempts),
            # The device profile the session was created with.  Not a secret
            # (it is a synthetic brand/model/sdk/release string) and the single
            # most useful field for telling whether the fix took effect.
            "login_device_id": self._login_device_id,
            # Which generation of the platform minted the token in hand, and the
            # one-shot tspCode chain that is tried when the gateway refuses a
            # vehicle interface.  ``platform_chain`` answers "did it work, and
            # if not, which route said what".
            "gw3_token_source": self._gw3_token_source,
            "platform_chain": list(self._platform_chain),
        }

    # -- signing / gateway plumbing --------------------------------------

    def _sign_gw1(self, ts: str, nonce: int) -> str:
        return hashlib.sha1(
            "".join(sorted([ts, str(nonce), _CA_SECRET])).encode()
        ).hexdigest()

    def _gw1_headers(self) -> dict[str, str]:
        """The client identity GW1 routes on — the captured **Android** app.

        This used to claim the iOS client (``toc_ios_zeekrapp``, ``app_version``
        4.0.2, an iPhone UA) and a grey-release channel (``x_gray_code:
        gray74``).  The captured app traffic is Android on both gateways, and
        GW1 selects the service — and therefore which routes exist — from
        ``app_code``/``app_type``/``platform``.  Asking as the wrong client is
        how a route ends up 404 rather than refused, which is exactly what the
        ``tspCode`` probes answered.  ``x_gray_code`` is sent **empty**, as the
        app sends it: a grey channel is a feature-flag bucket, not a licence to
        use every interface.
        """
        ts = _ts()
        nonce = _nonce()
        return {
            "User-Agent": "okhttp/4.12.0",
            "request-original": "zeekr-app",
            "Accept-Language": "zh-Hans-CN;q=1, en-CN;q=0.9",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/json; charset=UTF-8",
            "app_code": "toc_android_zeekrapp",
            "app_type": "android",
            "app_version": _GW3_APP_VERSION,
            "platform": "ANDROID",
            "phone_model": DEVICE_MODEL,
            "phone_version": DEVICE_SDK,
            "workspaceId": "prod",
            "x_gray_code": "",
            "x_ca_secret": _CA_SECRET,
            "x_ca_key": "APP-SIGN-SECRET-KEY",
            "x_ca_timestamp": ts,
            "x_ca_nonce": str(nonce),
            "x_ca_sign": self._sign_gw1(ts, nonce),
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
            "X-APP-OS-VERSION": _GW3_APP_VERSION,
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
                   payload: Any = None,
                   host: str | None = None) -> dict[str, Any]:
        # ``host`` exists for the tspCode probes: the regional IDaaS host is one
        # of the unknowns, so it must be overridable without a second code path.
        url = self._with_query(f"https://{host or _GW1_HOST}{path}", params)
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
        data = _ok_payload(result) or {}
        return data.get("list", []) if isinstance(data, dict) else []

    async def get_vehicle_status_gw2(self, vin: str) -> dict[str, Any]:
        result = await self._gw2(
            "GET", f"/remote-control/vehicle/status/{vin}",
            params={"latest": "Local", "target": "basic%2Cmore",
                    "userId": self._user_id or ""},
        )
        data = _ok_payload(result) or {}
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

    def _gw3_auth_headers(self, vin: str | None, token: str | None,
                          vin_encrypted: bool | None = None
                          ) -> dict[str, str]:
        """Extra GW3 headers: the VIN, plus a token when there is one.

        Both are omitted rather than sent blank — the app simply leaves the
        header out, and an empty-but-present header is not the same request.
        """
        extra: dict[str, str] = {}
        if vin:
            extra["X-VIN"] = self._gw3_vin_value(vin, vin_encrypted)
        if token:
            extra["Authorization"] = self._bearer(token)
        return extra

    async def _gw3(self, method: str, path: str, params: dict | None = None,
                   payload: Any = None, token: str | None = None,
                   vin: str | None = None, retry: bool = True,
                   vin_encrypted: bool | None = None,
                   headers_extra: dict[str, str] | None = None
                   ) -> dict[str, Any]:
        # The auth headers are derived here rather than by the caller so that a
        # retry with a different X-VIN encoding actually changes the request.
        extra = self._gw3_auth_headers(vin, token, vin_encrypted)
        # Overrides that a successful probe adopted stay in force: a variant is
        # only worth adopting if every later request keeps using it.
        extra.update(self._variant_headers)
        if headers_extra:
            extra.update(headers_extra)
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
        if vin:
            self._record_vin_attempt(
                shape.get("method"), shape.get("path"),
                extra.get("X-VIN") != vin, status, result,
            )
        if _looks_like_auth_error(result, status):
            if retry and await self._recover_gw3_session(result):
                return await self._gw3(method, path, params, payload,
                                       token=token, vin=vin, retry=False,
                                       vin_encrypted=vin_encrypted)
            raise ZeekrAuthError(
                f"GW3 鉴权失败: {result.get('msg') if isinstance(result, dict) else status}"
            )
        # "This interface is not authorized" on an authenticated vehicle call,
        # while the legacy vehicle list keeps working: the token in hand was
        # minted by the previous generation of the platform.  Raise a platform
        # token once and retry with it.  ``token is not None`` keeps this off the
        # auth calls themselves, and ``_platform_chain_done`` keeps it to a
        # single attempt per process.
        if (retry and token is not None and not self._platform_chain_done
                and _is_forbidden_interface(result)):
            if await self._platform_token():
                return await self._gw3(method, path, params, payload,
                                       token=self._new_access_token, vin=vin,
                                       retry=False, vin_encrypted=vin_encrypted)
        # Two failures mention the X-VIN header: "decrypt failed" (we sent
        # something it cannot open) and "interface not authorized" (it may have
        # opened it into the wrong VIN).  Spend exactly one request finding out
        # which encoding the gateway wants — but treat it as a *probe*: it must
        # not be allowed to poison every later poll, because the alternative is
        # strictly worse (a plain VIN can never be decrypted at all).
        if (retry and vin_encrypted is None and not self._gw3_vin_flipped
                and not self._vehicle_token
                and (_is_vin_decrypt_failure(result)
                     or _is_forbidden_interface(result))):
            original = self._gw3_vin_encrypted
            self._gw3_vin_encrypted = not original
            self._gw3_vin_flipped = True
            _LOGGER.warning(
                "GW3 拒绝了 X-VIN（%s），改用%s重试一次以确认",
                _response_brief(result).get("msg"),
                "AES 加密" if self._gw3_vin_encrypted else "明文",
            )
            probe = await self._gw3(method, path, params, payload,
                                    token=token, vin=vin, retry=False)
            if not (isinstance(probe, dict) and probe.get("code") == _SUCCESS):
                self._gw3_vin_encrypted = original
                _LOGGER.warning(
                    "另一种 X-VIN 编码同样不被接受，恢复为%s",
                    "AES 加密" if original else "明文",
                )
            return probe
        return result if isinstance(result, dict) else {"code": str(status)}

    def _vehicle_raw(self, vin: str) -> dict[str, Any]:
        for vehicle in self._vehicles:
            if vehicle.vin == vin:
                return vehicle.raw or {}
        return {}

    @staticmethod
    def _encrypt_ecb(plain: str) -> str:
        """AES-128-ECB variant, in case the platform uses no chaining mode."""
        cipher = AES.new(_AES_KEY.encode(), AES.MODE_ECB)
        return _b64(cipher.encrypt(pad(plain.encode(), AES.block_size)))

    @staticmethod
    def _encrypt_zero_iv(plain: str) -> str:
        """AES-128-CBC with a zero IV, in case the IV constant is wrong."""
        cipher = AES.new(_AES_KEY.encode(), AES.MODE_CBC, b"\x00" * AES.block_size)
        return _b64(cipher.encrypt(pad(plain.encode(), AES.block_size)))

    def x_vin_candidates(self, vin: str) -> list[tuple[str, str, bool]]:
        """``(label, value, adopt)`` triples worth trying in ``X-VIN``.

        The gateway told us the header must be **at least 17 characters** (the
        length of a VIN) and that the plain VIN is not accepted — so ``X-VIN``
        is a VIN ciphertext.  What is *not* settled is whether our ``079001``
        means "decrypted fine, but this account may not use this car" or "wrong
        key, so it decrypted to garbage and no car matched".  A control entry of
        valid-looking ciphertext that cannot possibly decrypt correctly tells
        the two apart, and the remaining entries cover the plausible crypto
        variants.

        ``adopt`` is False for the control: it must never be latched onto.
        """
        candidates: list[tuple[str, str, bool]] = [
            ("aes(vin)", self._encrypt_vin(vin), True),
            ("aes-ecb(vin)", self._encrypt_ecb(vin), True),
            ("aes-zeroiv(vin)", self._encrypt_zero_iv(vin), True),
        ]
        raw = self._vehicle_raw(vin)
        user_veh_id = raw.get("userVehId")
        if user_veh_id:
            candidates.append(
                ("aes(userVehId)", self._encrypt_vin(str(user_veh_id)), True)
            )
            candidates.append(("userVehId", str(user_veh_id), False))
        tem_id = raw.get("temId")
        if tem_id:
            candidates.append(("aes(temId)", self._encrypt_vin(str(tem_id)), True))
        # Controls — known-bad shapes, kept so the report shows the boundary.
        candidates.append(("vin", vin, False))
        candidates.append(("control:zero-ciphertext", _b64(b"\x00" * 32), False))
        return candidates

    async def _probe_x_vin(self, label: str, value: str) -> dict[str, Any]:
        """Try one candidate ``X-VIN`` value without touching shared state.

        Built by hand rather than through :meth:`_gw3` so a probe can never
        record, flip or otherwise disturb the request path real traffic uses.
        """
        path = "/ms-vehicle-status/api/v1.0/vehicle/status/latest"
        params = {"latest": "", "target": "new"}
        extra = {"X-VIN": value}
        if self._new_access_token:
            extra["Authorization"] = self._bearer(self._new_access_token)
        url = self._with_query(f"{_GW3_BASE}{path}", params)
        headers = self._gw3_headers("GET", path, params, None, extra)
        try:
            result, status = await self._request("GET", url, headers, None)
        except Exception as exc:  # noqa: BLE001 - a probe must never raise
            return {"label": label, "error": str(exc)}
        brief = _response_brief(result)
        return {
            "label": label,
            # The shape, never the value: it is a capability if it works.
            "chars": len(value),
            "status": status,
            "code": brief.get("code"),
            "msg": brief.get("msg"),
        }

    async def probe_endpoints(self, vin: str) -> dict[str, Any]:
        """Map what this account is allowed to reach, and with what.

        Two questions, both answerable only by the gateway:

        * **Where is the boundary?** The vehicle list works while every X-VIN
          endpoint answers ``079001 此接口未被授权`` — is that "this account may
          not touch this car", or one wrong path?
        * **What should ``X-VIN`` contain?** The owner's app encrypts the VIN;
          a shared account may need something else.

        A candidate that is accepted is adopted immediately, so a diagnostics
        download can by itself repair the header.  Runs on demand only.
        """
        # First, because it changes the token every later step uses: if the
        # gateway is refusing vehicle interfaces, try to raise a platform token.
        # A successful swap shows up as ``paths`` turning green below.
        await self._platform_token()

        paths: list[dict[str, Any]] = []
        saved_rejected = self._gw3_last_rejected
        saved_attempts = list(self._gw3_vin_attempts)
        try:
            for name, method, path, params, with_vin in (
                ("vehicle-list (no X-VIN)", "GET",
                 "/ms-app-bff/api/v3.0/veh/vehicle-list",
                 {"needSharedCar": "true"}, False),
                ("remoteControl/getVehicleState", "GET",
                 "/ms-app-bff/api/v1.0/remoteControl/getVehicleState", None, True),
                ("vehicle-status/latest", "GET",
                 "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
                 {"latest": "", "target": "new"}, True),
            ):
                try:
                    result = await self._gw3(
                        method, path, params=params, token=self._new_access_token,
                        vin=vin if with_vin else None, retry=False,
                        vin_encrypted=True,
                    )
                except Exception as exc:  # noqa: BLE001
                    paths.append({"name": name, "path": path, "error": str(exc)})
                    continue
                brief = _response_brief(result)
                paths.append({
                    "name": name,
                    "path": path,
                    "with_x_vin": with_vin,
                    "code": brief.get("code"),
                    "msg": brief.get("msg"),
                })
        finally:
            self._gw3_last_rejected = saved_rejected
            self._gw3_vin_attempts = saved_attempts

        candidates: list[dict[str, Any]] = []
        for label, value, adopt in self.x_vin_candidates(vin):
            outcome = await self._probe_x_vin(label, value)
            outcome["adoptable"] = adopt
            candidates.append(outcome)
            if outcome.get("code") == _SUCCESS:
                if adopt and not self._vehicle_token:
                    self.set_vehicle_token(value)
                    self._vehicle_token_source = f"probe:{label}"
                    _LOGGER.warning(
                        "X-VIN 候选 %s 被网关接受，已改用该值（来源 probe）", label
                    )
                # No point trying the rest: this one works.
                break
        return {"paths": paths, "x_vin_candidates": candidates}

    def _record_vin_attempt(self, method: Any, path: Any, encrypted: bool,
                            status: int, result: Any) -> None:
        """Remember how each X-VIN encoding fared (diagnostics only)."""
        brief = _response_brief(result)
        self._gw3_vin_attempts.append({
            "method": method,
            "path": path,
            "x_vin_encrypted": encrypted,
            "status": status,
            "code": brief.get("code"),
            "msg": brief.get("msg"),
        })
        # Only the tail is interesting; one poll's worth is plenty.
        del self._gw3_vin_attempts[:-8]

    async def _recover_gw3_session(self, result: Any) -> bool:
        """Renew the GW3 session after an auth failure.

        ``079021 logged in elsewhere`` means our token was superseded — the
        account only holds one SNCTSP session and every new login drops the
        previous token.  Only a fresh login takes it back, so a plain token
        refresh is not enough.
        """
        if _is_displaced(result):
            _LOGGER.warning(
                "GW3 会话已被顶替（%s），重新登录以取回",
                _result_text(result)[:120],
            )
            await self.snc_login()
            return bool(self._new_access_token)
        return await self.async_refresh()


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

    def _gw3_vin_value(self, vin: str, encrypted: bool | None = None) -> str:
        """``X-VIN`` in the requested encoding, defaulting to the detected one.

        A token supplied by the owner always wins.  On the new platform the
        header is not merely an encrypted VIN: it is an opaque per-vehicle token
        that both addresses **and authorises** the car, so nothing we can derive
        locally reproduces it — an encrypted VIN is accepted (login proves that)
        yet answers ``079001 此接口未被授权`` on every endpoint that needs the
        car's capabilities.  Without a token we still send the encrypted VIN, as
        the app's own implementation does.
        """
        if self._vehicle_token:
            return self._vehicle_token
        if self._gw3_vin_encrypted if encrypted is None else encrypted:
            return self._encrypt_vin(vin)
        return vin

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
        self._absorb_vehicle_token(data)
        _LOGGER.debug("GW3 %s 成功", what)
        return True

    # Field names a per-vehicle X-VIN token could plausibly arrive under.  The
    # platform may hand one out at login instead of expecting the client to
    # derive it from the VIN; if so, using it beats anything we can compute.
    _VEHICLE_TOKEN_KEYS = (
        "encVin", "encryptedVin", "encryptionVin", "xVin", "xVinToken",
        "vehicleToken", "vinToken", "secVin",
    )

    def _absorb_vehicle_token(self, data: Any, depth: int = 2) -> bool:
        """Adopt a per-vehicle ``X-VIN`` token if the backend sent one.

        A guess at field names, but a cheap one: the value is only ever used as
        the ``X-VIN`` header, so a miss just means we keep deriving it locally,
        and a hit would explain why a locally derived VIN is turned down.
        """
        if depth <= 0 or self._vehicle_token:
            return False
        if isinstance(data, dict):
            for key in self._VEHICLE_TOKEN_KEYS:
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    self._vehicle_token = value.strip()
                    self._vehicle_token_source = f"backend:{key}"
                    _LOGGER.info(
                        "GW3 登录响应里带有车辆令牌（字段 %s），改用该值作为 X-VIN",
                        key,
                    )
                    return True
            return any(
                self._absorb_vehicle_token(item, depth - 1)
                for item in data.values() if isinstance(item, (dict, list))
            )
        if isinstance(data, list):
            return any(
                self._absorb_vehicle_token(item, depth - 1)
                for item in data if isinstance(item, (dict, list))
            )
        return False

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
                    "loginDeviceId": self._login_device_id,
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
                vin=self._first_known_vin(), vin_encrypted=True,
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
                    "loginDeviceId": self._login_device_id,
                    "loginDeviceType": 1,
                    "loginPhoneBrand": "Android",
                    "loginPhoneModel": "Android SDK built for arm64",
                    "loginSystem": "Android",
                    "refreshToken": self._new_refresh_token,
                    "accessToken": self._new_access_token,
                },
                # Mirrors the login call: tokens travel in the body, the request
                # only carries the encrypted VIN.
                vin=self._first_known_vin(), vin_encrypted=True,
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

    # -- new-platform (TSP) token chain -----------------------------------

    async def _fetch_tsp_code(self) -> str | None:
        """Mint the short-lived ``tspCode`` that the platform login exchanges.

        The published client fetches it from ``user/tspCode`` on its regional
        IDaaS host, with the region baked into both the host and the path
        prefix (``gateway-pub-hw-em-sg`` / ``zeekr-cuc-idaas-sea``).  China's
        pair is not published anywhere, so the candidates are asked in turn and
        every answer — including "this route does not exist" — is recorded:
        which host and prefix answer at all is precisely what pins China down.
        """
        client_id = self._client_id or _TSP_CLIENT_IDS[0]
        attempts = 0
        for host, path in _TSP_CODE_CANDIDATES:
            if attempts >= _TSP_CODE_ATTEMPT_LIMIT:
                break
            attempts += 1
            try:
                result = await self._gw1(
                    "GET", path, params={"tspClientId": client_id}, host=host
                )
            except Exception as exc:  # noqa: BLE001
                self._platform_chain.append({
                    "step": "tspCode", "host": host, "path": path,
                    "error": str(exc)[:160],
                })
                continue
            brief = _response_brief(result)
            data = result.get("data") if isinstance(result, dict) else None
            code = data.get("code") if isinstance(data, dict) else None
            self._platform_chain.append({
                "step": "tspCode", "host": host, "path": path,
                "code": brief.get("code"),
                "msg": brief.get("msg"),
                # Distinguishes "our envelope said no" from a proxy/Spring error
                # body, which is what a wrong route usually answers with.
                "top_keys": sorted(result) if isinstance(result, dict) else None,
                "got_code": bool(code),
            })
            if code:
                return str(code)
        return None

    def _legacy_login_body(self) -> dict[str, Any]:
        """The body of the login this integration has always used."""
        return {
            "credential": "",
            "identifier": "",
            "identityType": 5,
            "loginDeviceId": self._login_device_id,
            "loginDeviceJgId": "",
            "loginDeviceType": 1,
            "loginPhoneBrand": "Android",
            "loginPhoneModel": "Android SDK built for arm64",
            "loginSystem": "Android",
            # The app forwards the JWT straight out of the GW1 answer, which
            # already carries the "Bearer " prefix.
            "token": self._bearer(self._jwt_token),
        }

    async def _login_variant(self, name: str, headers: dict[str, str] | None,
                             body: dict[str, Any] | None = None) -> bool:
        """Log in again with overrides, then see if a vehicle interface opens.

        A login alone proves nothing — the token is minted either way — so each
        variant is judged by the only thing that matters: whether
        ``ms-vehicle-status`` answers it.  On success the overrides are kept for
        every later request, which is what makes this a fix and not a report.
        """
        payload = self._legacy_login_body()
        if body:
            payload.update(body)
        try:
            result = await self._gw3(
                "POST", "/ms-user-auth/v1.0/auth/login", payload=payload,
                vin=self._first_known_vin(), vin_encrypted=True, retry=False,
                headers_extra=headers,
            )
            if result.get("code") == _SUCCESS and self._absorb_gw3_tokens(
                result, name
            ):
                probe = await self._gw3(
                    "GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
                    params={"latest": "", "target": "new"},
                    token=self._new_access_token,
                    vin=self._first_known_vin(), vin_encrypted=True,
                    retry=False, headers_extra=headers,
                )
                verdict = _response_brief(probe)
                ok = probe.get("code") == _SUCCESS
            else:
                verdict = {"login": _response_brief(result)}
                ok = False
        except ZeekrError as exc:
            self._platform_chain.append(
                {"step": name, "error": str(exc)[:160]}
            )
            return False

        self._platform_chain.append({"step": name, "verdict": verdict})
        if not ok:
            return False

        self._variant_headers = dict(headers or {})
        self._gw3_token_source = name
        _LOGGER.warning("登录变体「%s」可以访问车辆接口，已采用该配置", name)
        return True

    def _identity_variants(self) -> list[tuple[str, dict[str, Any]]]:
        """``identityType``/field combinations worth one login each.

        The same endpoint mints tokens of more than one kind: ``identityType 5``
        with the GW1 JWT is the legacy pair this integration has always used, and
        the published new-platform pair is ``identityType 10`` with a
        ``tspCode``.  China's ``tspCode`` route is published nowhere, so the
        identifiers this client already holds are tried in that shape instead —
        and every attempt is judged by whether a vehicle interface answers.

        Header knobs are deliberately *not* here any more: signature version 2.1,
        ``X-PROJECT-ID: ZEEKR_CN`` and both together were tried and all three came
        back ``079001``, so the refusal is not driven by anything in the headers.
        Kept short on purpose — each entry is a real login on an account that
        allows only one session.
        """
        variants: list[tuple[str, dict[str, Any]]] = []
        for label, value in (
            ("jwt", self._bearer(self._jwt_token)),
            ("gw2-token", self._access_token),
            ("client-id", self._client_id),
            ("user-id", self._user_id),
        ):
            if value:
                variants.append((f"id10+{label}", {
                    "identityType": 10,
                    "identifier": value,
                    # The identityType-10 shape carries its proof in
                    # ``identifier``, not in ``token``.
                    "token": "",
                }))
        if self._access_token:
            # The legacy shape, but proving the session with the GW2 (ecarx)
            # token instead of the GW1 JWT.
            variants.append(("id5+gw2-token", {
                "token": self._bearer(self._access_token),
            }))
        return variants

    async def _platform_token(self) -> bool:
        """Find a login the vehicle interfaces will actually authorise.

        ``079001 此接口未被授权`` is what the legacy token gets on
        ``ms-vehicle-status`` / ``ms-remote-control`` while the legacy vehicle
        list keeps working.  The X-VIN control rules the header out (a
        deliberately invalid ciphertext fails decryption, ours decrypts, so the
        key is right and the refusal happens *after* decryption), which leaves
        the token's interface authorisation.

        The published client reaches it by exchanging a ``tspCode``, and the
        platform notes describe exactly that split — but the China pair is
        unpublished, so the knobs are tried in order of how well they are
        documented, each judged by whether a vehicle interface answers.  One
        shot per process, on demand only.
        """
        if self._platform_chain_done:
            return False
        self._platform_chain_done = True

        tsp_code = await self._fetch_tsp_code()
        if tsp_code:
            try:
                result = await self._gw3(
                    "POST", "/ms-user-auth/v1.0/auth/login",
                    payload={
                        # ``identifier`` carries the code and there is
                        # deliberately no ``token`` field: this is the
                        # platform's own login, not the GW1 JWT hand-off.
                        "identifier": tsp_code,
                        "identityType": 10,
                        "loginDeviceId": self._login_device_id,
                        "loginDeviceJgId": "",
                        "loginDeviceType": 1,
                        "loginPhoneBrand": "Android",
                        "loginPhoneModel": "Android SDK built for arm64",
                        "loginSystem": "Android",
                    },
                    vin=self._first_known_vin(), vin_encrypted=True,
                    retry=False,
                )
                brief = _response_brief(result)
                self._gw3_login = brief
                self._platform_chain.append(
                    {"step": "platformLogin", "verdict": brief}
                )
                if result.get("code") == _SUCCESS and self._absorb_gw3_tokens(
                    result, "平台登录"
                ):
                    self._gw3_token_source = "platform"
                    _LOGGER.warning(
                        "已改用新平台令牌（identityType 10 + tspCode）访问车辆接口"
                    )
                    return True
            except ZeekrError as exc:
                self._platform_chain.append(
                    {"step": "platformLogin", "error": str(exc)[:160]}
                )
        else:
            _LOGGER.debug("未能取得 tspCode，改为试探其它登录变体")

        # The token is minted either way and the legacy list still needs one, so
        # the last thing we do is put a known-good legacy token back.
        for name, body in self._identity_variants():
            try:
                if await self._login_variant(name, None, body):
                    return True
            except Exception as exc:  # noqa: BLE001 - a probe must not break setup
                self._platform_chain.append(
                    {"step": name, "error": str(exc)[:160]}
                )

        await self.snc_login()
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
            token=self._new_access_token or self._jwt_token,
        )
        data = _ok_payload(result)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("list") or data.get("vehicles") or []
        return []

    async def get_vehicle_status_gw3(self, vin: str) -> dict[str, Any]:
        result = await self._gw3(
            "GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
            # Exactly as the app sends it: ``latest`` is present but empty,
            # not "false".  The captured request is
            # ``...status/latest?latest=&target=new``.
            params={"latest": "", "target": "new"},
            vin=vin, token=self._new_access_token,
        )
        data = _ok_payload(result)
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
        """Fetch auxiliary GW3 payloads (charging status/limit).

        The two paths come from the published client's constants
        (``VEHICLECHARGINGSTATUS_URL`` / ``CHARGING_LIMIT_URL``).  The ones this
        integration used before were guesses and never returned anything —
        ``ms-vehicle-status`` only answers the ``/qrvs`` route, and the SOC limit
        lives under ``ms-charge-manage``.
        """
        extras: dict[str, Any] = {}
        for key, path, params in (
            ("chargingStatus",
             "/ms-vehicle-status/api/v1.0/vehicle/charging/status/qrvs",
             {"latest": "true"}),
            ("chargingLimit",
             "/ms-charge-manage/api/v1.0/charge/getLatestSoc",
             None),
        ):
            try:
                result = await self._gw3(
                    "GET", path, params=params,
                    vin=vin, token=self._new_access_token,
                )
                data = _ok_payload(result)
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
            vin=vin, token=self._new_access_token,
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
                if failures:
                    # Only a fallback "accepts" what the primary refused, and the
                    # GW2 telematics pipe answers ``1000 操作成功`` for commands it
                    # then silently drops.  Reporting that as a clean success is
                    # how "no error, but the car did not move" happens.
                    _LOGGER.warning(
                        "指令 %s 被 %s 接受，但首选通道被拒（%s）——"
                        "该通道可能只是收下而不执行，车端不一定会动作",
                        service_id, name, "；".join(failures),
                    )
                    return {**result, "gateway": name, "degraded": True}
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
            vin=vin, token=self._new_access_token,
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
            vin=vin, token=self._new_access_token,
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
