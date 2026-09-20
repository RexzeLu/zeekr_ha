"""Zeekr GRIC (China mainland) API client — app signature v2.1.

Why this exists
---------------
The SNC pipe in :mod:`~.api_sms` talks to ``snc-tsp-api.zeekrlife.com`` as the
SNC client (``x-app-id: ZEEKRCNCH001M0001``).  A **non-owner** account
(``isOwner: false``) is refused there — every vehicle interface answers
``079001 此接口未被授权`` — while the very same account drives the car from the
official app.  The app uses a different gateway (GRIC, 吉利中台) and a different
client id, and that client identity is the whole difference.  This module speaks
that gateway.

The GRIC signature
------------------
Recovered from the running app on a rooted device (2026-09-21) and verified
end-to-end against the live server::

    base = "".join(f"{name}:{value}\\n" for name in sorted(signed_headers))
         + [canonical_query + "\\n"]      # only when there is a query
         + [base64(md5(body)) + "\\n"]    # only when there is a body
         + METHOD + "\\n"
         + PATH                           # the path alone, never the query
    signature = base64(HMAC-SHA256(key, base))

The canonical query is ``k=v`` joined with ``&``, sorted by key, with **no**
leading ``?`` — and, crucially, positioned *before* the method.  Getting that
order wrong is what made every earlier attempt fail with ``00A06``.

Only 18 headers are signed (``_SIGNED_HEADERS``); ``accept`` / ``content-type``
/ ``user-agent`` are sent but excluded from the base string.

Two things cannot be derived offline and are configured instead
--------------------------------------------------------------
``x-vehicle-identifier``
    An opaque per-vehicle token that the gateway **decrypts** — a wrong value
    answers ``00A06 Decrypt X-VEHICLE-IDENTIFIER failed``.  Its construction is
    unsolved, so the owner supplies what the app sends, exactly like the SNC
    ``X-VIN`` token.  Vehicle *lists* work without it; every per-vehicle route
    needs it.
``x-device-id``
    Required, but the value is not validated (a random UUID is accepted), so one
    is generated and kept.

The GRIC refresh token is the seed for everything else: access tokens are
rotated on demand against ``refresh/token`` and both tokens are persisted so the
integration never needs the phone again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from .api_sms import (
    ZeekrApiError,
    ZeekrAuthError,
    ZeekrError,
    ZeekrVehicle,
)
from .const import (
    CONF_VEHICLE_IDENTIFIER,
    STORAGE_DEVICE_ID,
    STORAGE_GRIC_ACCESS_TOKEN,
    STORAGE_GRIC_REFRESH_TOKEN,
)
from .parser import extract_vehicle_meta, normalize_vehicle_data

_LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# App identity / shared key (as shipped in the Zeekr app).
# --------------------------------------------------------------------------
_APP_ID = "GEELYCNCH001M0001"
_SIGN_KEY = b"e70024ed24bda3cbd4a6295ed3fac5aa"
_SIGNATURE_VERSION = "2.1"
_APP_VERSION = "v1.0.0"
_PLATFORM = "4"  # x-tsp-platform: 4 = ZEEKR China

# Hosts.  The *core* services (vehicle list, tokens) live on one host and the
# TSP services (status, control) on another; the vehicle list hands out the
# per-car ``tspHost`` and that is what is used from then on.
_HOST_CORE = "gric-api.geely.com"
_HOST_TSP = "gric-zhf-api.geely.com"

# The 18 headers that go into the canonical string.  Note that ``accept``,
# ``content-type``, ``accept-encoding`` and ``user-agent`` are deliberately
# absent — they are sent, but signing them changes the signature.
_SIGNED_HEADERS = (
    "accept-language",
    "authorization",
    "x-api-signature-nonce",
    "x-api-signature-version",
    "x-app-id",
    "x-app-version",
    "x-device-brand",
    "x-device-id",
    "x-device-model",
    "x-device-os-version",
    "x-platform",
    "x-sales-platform",
    "x-tenant-id",
    "x-timestamp",
    "x-tsp-platform",
    "x-vehicle-brand",
    "x-vehicle-identifier",
    "x-vehicle-series",
)

_SUCCESS = "0"

# Error codes that mean "the session is gone and only a fresh login helps".
# ``00A17`` is what the gateway says once another client has rotated the token
# pair out from under us.
_RELOGIN_CODES = {"00A17", "1018P061"}
# ``00A06`` on a correctly assembled request means the *identifier* could not be
# decrypted rather than a signing bug, so it is worth its own message.
_BAD_IDENT_MARKERS = ("x-vehicle-identifier",)
_MISSING_HEADER_CODES = {"00A02"}

# How long before expiry the access token is renewed.  The pair rotates as a
# unit, so renewing early is free; renewing late means a failed poll.
_REFRESH_MARGIN_SECONDS = 3600.0
# A fresh refresh token stays valid for 30 days and every rotation resets that,
# so this is only a sanity bound for the "is it worth trying" decision.
_REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600


# --------------------------------------------------------------------------
# Signature (pure functions, unit-tested without Home Assistant)
# --------------------------------------------------------------------------


def canonical_query(query: dict[str, Any] | None) -> str:
    """Build the canonical query string the signature covers.

    ``k=v`` pairs sorted by key and joined with ``&`` — no leading ``?`` and no
    re-encoding.  The app builds exactly this string and the gateway rebuilds it
    from the raw URL, so any other order or escaping produces ``00A06``.
    """
    if not query:
        return ""
    parts = []
    for key in sorted(query):
        value = query[key]
        parts.append(f"{key}=" if value is None or value == "" else f"{key}={value}")
    return "&".join(parts)


def encode_body(payload: Any) -> bytes:
    """Serialise a request body exactly as it will be sent.

    The body is hashed for the signature, so the bytes hashed must be the bytes
    on the wire: compact separators, ``ensure_ascii=False``, and the same string
    handed to the HTTP layer.
    """
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def build_base(method: str, path: str, headers: dict[str, str],
               query: dict[str, Any] | None = None,
               body: bytes = b"") -> str:
    """Assemble the canonical string for one request."""
    base = "".join(
        f"{name}:{headers[name]}\n"
        for name in sorted(_SIGNED_HEADERS)
        if headers.get(name)
    )
    canonical = canonical_query(query)
    if canonical:
        base += canonical + "\n"
    if body:
        base += base64.b64encode(hashlib.md5(body).digest()).decode() + "\n"
    base += f"{method.upper()}\n"
    base += path
    return base


def sign_request(method: str, path: str, headers: dict[str, str],
                 query: dict[str, Any] | None = None, body: bytes = b"",
                 key: bytes = _SIGN_KEY) -> tuple[str, str]:
    """Return ``(base, signature)`` for one request."""
    base = build_base(method, path, headers, query, body)
    digest = hmac.new(key, base.encode(), hashlib.sha256).digest()
    return base, base64.b64encode(digest).decode()


def _jwt_expiry(token: str | None) -> float | None:
    """Read ``exp`` out of an unverified JWT (no signature check needed)."""
    if not token or token.count(".") < 2:
        return None
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001 - an opaque token is not an error
        return None
    exp = claims.get("exp")
    try:
        return float(exp)
    except (TypeError, ValueError):
        return None


def _host_of(url: str | None) -> str | None:
    """Reduce a ``https://host`` value from the vehicle list to a bare host."""
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        return url.rstrip("/") or None
    host = urlparse(url).netloc
    return host or None


def _payload_of(result: Any) -> Any:
    """Return ``data`` for a successful envelope, else ``None``."""
    if not isinstance(result, dict) or result.get("code") != _SUCCESS:
        return None
    return result.get("data")


def _accepted(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return str(result.get("code") or "") == _SUCCESS or result.get("success") is True


def _result_brief(result: Any) -> str:
    if not isinstance(result, dict):
        return str(result)[:160]
    code = result.get("code")
    msg = result.get("msg") or result.get("message")
    return f"{code} {msg}" if code else str(result)[:160]


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class ZeekrGricApiClient:
    """Async client for the Zeekr GRIC app gateway.

    Deliberately mirrors :class:`~.api_sms.ZeekrSmsApiClient`'s public surface
    so the coordinator and the entity platforms do not care which channel an
    entry uses.
    """

    #: Re-poll schedule after a command.  Wider than the coordinator's SNC
    #: default because a GRIC *lock* took ~120 s to appear in the status
    #: payload — see :data:`~.optimistic.DEFAULT_TTL`.
    command_refresh_delays: tuple[int, ...] = (10, 30, 60, 120, 170)

    def __init__(self, session) -> None:
        self._session = session
        # Required by the gateway but not validated — see the module docstring.
        self._device_id = str(uuid.uuid4())
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        # Per-vehicle capability secret; configured, never derivable offline.
        self._vehicle_identifier: str | None = None
        self._vehicles: list[ZeekrVehicle] = []
        self._vehicle_data: dict[str, dict[str, Any]] = {}
        self._raw_payloads: dict[str, Any] = {}
        self._status_source: dict[str, str] = {}
        # ``base64(seriesCode)``; sent on every request but not validated by the
        # gateway (verified: a deliberately wrong value is accepted).  It is
        # refreshed from the vehicle list so the request still describes the car.
        self._series_b64 = base64.b64encode(b"BX1E").decode()
        self._vehicle_brand = "ZEEKR"
        self._tenant_id = "ZEEKR"
        self._command_attempts: list[dict[str, Any]] = []
        self._last_error: str | None = None
        self._token_log: list[dict[str, Any]] = []

    # -- token / configuration persistence --------------------------------

    def set_device_id(self, device_id: str | None) -> None:
        if device_id:
            self._device_id = device_id

    def set_vehicle_identifier(self, identifier: str | None) -> None:
        """Use the app's ``x-vehicle-identifier`` for this car."""
        value = (identifier or "").strip()
        self._vehicle_identifier = value or None

    def store_tokens(self, data: dict[str, Any]) -> None:
        """Load persisted tokens / identifiers from a config entry."""
        self._device_id = data.get(STORAGE_DEVICE_ID) or self._device_id
        self._access_token = (
            data.get(STORAGE_GRIC_ACCESS_TOKEN) or self._access_token
        )
        self._refresh_token = (
            data.get(STORAGE_GRIC_REFRESH_TOKEN) or self._refresh_token
        )
        self._vehicle_identifier = (
            data.get(CONF_VEHICLE_IDENTIFIER) or self._vehicle_identifier
        )

    def get_token_storage(self) -> dict[str, Any]:
        return {
            STORAGE_DEVICE_ID: self._device_id,
            STORAGE_GRIC_ACCESS_TOKEN: self._access_token,
            STORAGE_GRIC_REFRESH_TOKEN: self._refresh_token,
            CONF_VEHICLE_IDENTIFIER: self._vehicle_identifier,
        }

    # -- properties -------------------------------------------------------

    @property
    def logged_in(self) -> bool:
        """Whether the entry has enough to talk to GRIC at all."""
        return bool(self._refresh_token or self._access_token)

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def phone(self) -> str | None:
        # GRIC entries are seeded with a token, not a phone number.
        return None

    @property
    def vehicles(self) -> list[ZeekrVehicle]:
        return self._vehicles

    def get_vehicle(self, vin: str) -> ZeekrVehicle | None:
        for vehicle in self._vehicles:
            if vehicle.vin == vin:
                return vehicle
        return None

    @property
    def has_gw3_token(self) -> bool:
        """Named for the coordinator's benefit: can commands be attempted?"""
        return bool(self._access_token)

    def gateway_summary(self) -> dict[str, Any]:
        """Gateway health for the diagnostics dump (never includes tokens)."""
        return {
            "channel": "gric",
            "has_access_token": bool(self._access_token),
            "has_refresh_token": bool(self._refresh_token),
            "vehicle_identifier_configured": bool(self._vehicle_identifier),
            "device_id": self._device_id,
            "status_source": dict(self._status_source),
            "command_attempts": list(self._command_attempts),
            "last_error": self._last_error,
            "token_log": list(self._token_log[-10:]),
        }

    # -- signing / transport ----------------------------------------------

    def _build_headers(self, with_identifier: bool = True) -> dict[str, str]:
        headers = {
            "accept-language": "zh_CN",
            "x-api-signature-version": _SIGNATURE_VERSION,
            "x-app-id": _APP_ID,
            "x-app-version": _APP_VERSION,
            # A synthetic device profile is fine: the value is not validated,
            # only its presence is.
            "x-device-brand": "GOOGLE",
            "x-device-id": self._device_id,
            "x-device-model": "Pixel5",
            "x-device-os-version": "Android 14 (API 34)",
            "x-platform": "Android",
            "x-sales-platform": "ZEEKR",
            "x-tenant-id": self._tenant_id,
            "x-tsp-platform": _PLATFORM,
            "x-vehicle-brand": self._vehicle_brand,
            "x-vehicle-series": self._series_b64,
        }
        # Omitted rather than sent blank: the refresh call legitimately has no
        # access token yet, and a present-but-empty header is not the same
        # request as an absent one.
        if self._access_token:
            headers["authorization"] = self._access_token
        if with_identifier and self._vehicle_identifier:
            headers["x-vehicle-identifier"] = self._vehicle_identifier
        return headers

    async def _request(self, method: str, host: str, path: str,
                       query: dict[str, Any] | None = None,
                       payload: Any = None, *,
                       with_identifier: bool = True,
                       retry_auth: bool = True,
                       requires_access: bool = True) -> dict[str, Any]:
        """Sign and perform one GRIC request, returning the JSON envelope.

        The body is serialised here — not handed to aiohttp as ``json=`` — so
        the bytes on the wire are exactly the ones the signature hashed.

        ``requires_access`` is cleared by the token refresh and nothing else.
        That call is authorised by the refresh token alone (verified against the
        live server), and demanding an access token there would make the very
        first bootstrap — where the entry holds nothing but a refresh token —
        impossible.
        """
        if requires_access and not self._access_token:
            raise ZeekrAuthError(
                "GRIC 未配置访问令牌：请在集成配置中粘贴 refreshToken。"
            )

        nonce = str(uuid.uuid4())
        timestamp = str(time.time_ns() // 1_000_000)
        headers = self._build_headers(with_identifier)
        headers["x-api-signature-nonce"] = nonce
        headers["x-timestamp"] = timestamp
        body = encode_body(payload)
        _, signature = sign_request(method, path, headers, query, body)

        url = f"https://{host}{path}"
        canonical = canonical_query(query)
        if canonical:
            url = f"{url}?{canonical}"
        sent = {
            **headers,
            "x-signature": signature,
            "accept": "application/json; charset=UTF-8",
            "content-type": "application/json; charset=UTF-8",
            "accept-encoding": "identity",
            "user-agent": "okhttp/4.12.0",
        }
        request_kwargs: dict[str, Any] = {"headers": sent}
        if body:
            request_kwargs["data"] = body

        try:
            async with self._session.request(method, url,
                                             **request_kwargs) as response:
                status = response.status
                try:
                    result = await response.json(content_type=None)
                except Exception:  # noqa: BLE001 - fall back to text
                    text = await response.text()
                    try:
                        result = json.loads(text)
                    except Exception:  # noqa: BLE001
                        result = {"code": str(status), "msg": text[:200]}
        except ZeekrError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ZeekrApiError(f"GRIC 请求失败（{path}）：{exc}") from exc

        if not isinstance(result, dict):
            result = {"code": str(status), "msg": str(result)[:200]}

        code = str(result.get("code") or "")
        self._last_error = None if code == _SUCCESS else _result_brief(result)

        # A rotated-away token pair answers 00A17.  Re-seeding from the stored
        # refresh token is the cure, and it costs one request.
        if (retry_auth and code in _RELOGIN_CODES
                and self._refresh_token):
            _LOGGER.debug("GRIC 令牌已失效（%s），尝试刷新后重试", code)
            if await self.async_refresh():
                return await self._request(method, host, path, query, payload,
                                           with_identifier=with_identifier,
                                           retry_auth=False)
            raise ZeekrAuthError(
                "GRIC 会话已失效且刷新失败，请在「设置 → 设备与服务 → 极氪 → "
                f"重新认证」中粘贴新的 refreshToken。服务端返回：{_result_brief(result)}"
            )

        if code in _RELOGIN_CODES:
            raise ZeekrAuthError(
                "GRIC 会话已失效，请在集成中重新认证。"
                f"服务端返回：{_result_brief(result)}"
            )
        if code in _MISSING_HEADER_CODES and isinstance(result.get("msg"), str):
            # 00A02 names the header it wanted, which is the fastest way to see
            # that the identifier was never configured.
            message = result["msg"]
            if any(marker in message.lower() for marker in _BAD_IDENT_MARKERS):
                raise ZeekrApiError(
                    "GRIC 车辆接口需要 x-vehicle-identifier，但集成配置里没有它。"
                    "请在「配置 → 选项」中填入该车的 identifier（见 README）。"
                )
        return result

    async def _get(self, host: str, path: str, query: dict[str, Any] | None = None,
                   *, with_identifier: bool = True) -> dict[str, Any]:
        return await self._request("GET", host, path, query,
                                   with_identifier=with_identifier)

    async def _post(self, host: str, path: str, payload: Any,
                    query: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("POST", host, path, query, payload)

    # -- tokens -----------------------------------------------------------

    def _access_token_fresh(self) -> bool:
        expiry = _jwt_expiry(self._access_token)
        if expiry is None:
            # No decodable exp: assume usable and let the gateway judge.
            return bool(self._access_token)
        return expiry - time.time() > _REFRESH_MARGIN_SECONDS

    async def async_refresh(self) -> bool:
        """Rotate the token pair against ``refresh/token``.

        The server *rotates*: every call returns a brand-new refresh token and
        invalidates the one that was sent, and it revokes any other token of the
        same session.  So the replacement is stored immediately — losing it
        would strand the entry on a dead token.
        """
        if not self._refresh_token:
            return False
        try:
            result = await self._request(
                "POST", _HOST_CORE,
                "/ms-midground-user/api/v1.0/user/auth/refresh/token",
                payload={"refreshToken": self._refresh_token},
                # The token endpoint is account-scoped; the per-vehicle
                # identifier is not part of it.
                with_identifier=False,
                # A refresh that fails must not recursively try to refresh.
                retry_auth=False,
                # Authorised by the refresh token alone: this is the call that
                # *produces* an access token, so it cannot require one.
                requires_access=False,
            )
        except ZeekrAuthError as exc:
            # The endpoint itself declaring the token dead (``1018P061``).
            self._token_log.append({"event": "refresh_rejected", "error": str(exc)})
            _LOGGER.warning("GRIC 刷新令牌被拒: %s", exc)
            return False
        except ZeekrError as exc:
            self._token_log.append({"event": "refresh_failed", "error": str(exc)})
            _LOGGER.warning("GRIC 刷新令牌失败: %s", exc)
            return False

        data = _payload_of(result) or {}
        access = data.get("accessToken")
        refresh = data.get("refreshToken")
        if not access:
            self._token_log.append({
                "event": "refresh_rejected",
                "response": _result_brief(result),
            })
            _LOGGER.warning("GRIC 刷新令牌被拒: %s", _result_brief(result))
            return False

        self._access_token = access
        if refresh:
            # Rotation: the old refresh token is dead from here on.
            self._refresh_token = refresh
        self._token_log.append({
            "event": "refreshed",
            "access_expires": data.get("accessExpiresTimestamp"),
            "refresh_expires": data.get("refreshExpiresTimestamp"),
            "rotated": bool(refresh),
        })
        _LOGGER.debug("GRIC 令牌已刷新（轮换=%s）", bool(refresh))
        return True

    async def async_ensure_gw3_token(self) -> bool:
        """Make sure a usable access token is in hand."""
        if self._access_token_fresh():
            return True
        return await self.async_refresh()

    async def async_refresh_session(self) -> bool:
        """Public alias used by the coordinator's recovery path."""
        return await self.async_refresh()

    # -- vehicle list / status -------------------------------------------

    async def async_get_vehicle_list(self) -> list[ZeekrVehicle]:
        """List the account's vehicles.

        Lives on the core host and is the one vehicle route that needs **no**
        ``x-vehicle-identifier`` — which is what makes the very first call
        possible before the owner has supplied it.
        """
        result = await self._get(
            _HOST_CORE,
            "/ms-vehicle-core/api/v1.0/vehicle/favorite-vehicles",
            {"tspPlatform": _PLATFORM},
            with_identifier=False,
        )
        entries = _payload_of(result)
        if isinstance(entries, dict):
            entries = entries.get("list") or entries.get("vehicles") or []
        if not isinstance(entries, list):
            entries = []

        vehicles: list[ZeekrVehicle] = []
        seen: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            meta = extract_vehicle_meta(entry)
            vin = meta.get("vin")
            if not vin or vin in seen:
                continue
            seen.add(vin)
            # Adopt the per-car routing/identity from the list: the TSP host
            # differs per brand, and the series feeds the (unvalidated but
            # still descriptive) ``x-vehicle-series`` header.  This must happen
            # *before* the vehicle is constructed — ``ZeekrVehicle`` copies the
            # metadata dict, so later writes to it are lost.
            if host := _host_of(entry.get("tspHost")):
                meta["tsp_host"] = host
            if series := entry.get("seriesCode") or entry.get("appinnerCode"):
                self._series_b64 = base64.b64encode(str(series).encode()).decode()
            if brand := entry.get("brandCode"):
                self._vehicle_brand = str(brand)
            if tenant := entry.get("tenantId"):
                self._tenant_id = str(tenant)
            vehicles.append(ZeekrVehicle(vin, meta, entry))

        self._vehicles = vehicles
        return vehicles

    def _tsp_host(self, vin: str) -> str:
        """The host that serves this car's status/control."""
        vehicle = self.get_vehicle(vin)
        if vehicle is not None:
            raw = vehicle.raw if isinstance(vehicle.raw, dict) else {}
            host = (vehicle.meta.get("tsp_host")
                    or _host_of(raw.get("tspHost")))
            if host:
                return host
        return _HOST_TSP

    async def get_vehicle_status_gric(self, vin: str) -> dict[str, Any]:
        """Raw status payload for a VIN.

        GRIC serves **v2.0** of this route (SNC serves v1.0); the payload shape
        is close enough that the shared normaliser handles both.
        """
        result = await self._get(
            self._tsp_host(vin),
            "/ms-vehicle-status/api/v2.0/vehicle/status/latest",
            {"latest": "", "target": "new"},
        )
        data = _payload_of(result)
        return data if isinstance(data, dict) else {}

    async def async_probe_vehicle(self, vin: str) -> tuple[bool, str]:
        """Check that one car's reads are actually authorised over GRIC.

        A vehicle *list* succeeds without ``x-vehicle-identifier``, so it cannot
        tell a good identifier from a bad one — but a per-vehicle read can, and
        a per-vehicle read is exactly what the polling loop will do.  The config
        flow calls this before creating the entry so a wrong (or missing)
        identifier surfaces as a form error instead of a silent first-poll
        failure.

        Returns ``(ok, detail)``, where ``detail`` carries the gateway's own
        message when the car is not readable.
        """
        result = await self._get(
            self._tsp_host(vin),
            "/ms-vehicle-status/api/v2.0/vehicle/status/latest",
            {"latest": "", "target": "new"},
        )
        data = _payload_of(result)
        if isinstance(data, dict) and data:
            return True, ""
        return False, _result_brief(result)

    async def _extras(self, vin: str) -> dict[str, Any]:
        """Auxiliary payloads the normaliser looks for but status omits.

        Mirrors ``ZeekrSmsApiClient._gw3_extras``: charging status and the SOC
        limit live under their own services on both channels.
        """
        extras: dict[str, Any] = {}
        for key, path, query in (
            ("chargingStatus",
             "/ms-vehicle-status/api/v1.0/vehicle/status/qrvs",
             {"latest": "true"}),
            ("chargingLimit",
             "/ms-charge-manage/api/v1.0/charge/getLatestSoc",
             {"vin": vin, "tspPlatform": _PLATFORM}),
        ):
            try:
                result = await self._get(self._tsp_host(vin), path, query)
                data = _payload_of(result)
                if isinstance(data, dict) and data:
                    extras[key] = data
            except Exception as exc:  # noqa: BLE001 - extras are optional
                _LOGGER.debug("GRIC %s 获取失败（%s）: %s", key, vin, exc)
        return extras

    async def _fetch_raw_status(self, vin: str) -> dict[str, Any]:
        raw = await self.get_vehicle_status_gric(vin)
        if raw:
            for key, value in (await self._extras(vin)).items():
                raw.setdefault(key, value)
            self._status_source[vin] = "gric"
        return raw

    async def async_bootstrap(self) -> list[ZeekrVehicle]:
        """Resume from a stored refresh token: refresh, then list cars."""
        if not self._refresh_token:
            raise ZeekrAuthError(
                "GRIC 配置缺少 refreshToken，无法建立会话。"
                "请到「设置 → 设备与服务 → 极氪 → 重新认证」粘贴一次。"
            )
        await self.async_ensure_gw3_token()
        return await self.async_get_vehicle_list()

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
        """Send a remote-control command over GRIC.

        ``setting.serviceParameters`` nesting is mandatory: the flat
        ``serviceParameters`` shape belongs to the legacy telematics pipe and is
        rejected here.
        """
        await self._require_access_token()
        payload = {
            "command": command,
            "serviceId": service_id,
            "setting": {
                "serviceParameters": list(setting.get("serviceParameters") or []),
            },
        }
        self._command_attempts = [{
            "gateway": "gric",
            "service_id": service_id,
            "command": command,
        }]
        result = await self._post(
            self._tsp_host(vin),
            "/ms-remote-control/api/v1.0/remoteControl/control",
            payload,
        )
        self._command_attempts[-1]["code"] = result.get("code")
        self._command_attempts[-1]["msg"] = result.get("msg")
        if not _accepted(result):
            raise ZeekrApiError(
                f"GRIC 拒绝了指令 {service_id}：{_result_brief(result)}"
            )
        return {**result, "gateway": "gric"}

    async def _require_access_token(self) -> None:
        if self._access_token or await self.async_ensure_gw3_token():
            return
        raise ZeekrAuthError(
            "无法下发指令：没有可用的 GRIC 访问令牌，自动刷新也失败。"
            f"最后一次错误：{self._last_error or '未知'}。"
            "请在集成中重新认证以粘贴新的 refreshToken。"
        )

    async def async_set_charge_plan(self, vin: str, start_time: str,
                                    end_time: str, command: str,
                                    bc_cycle: bool = False,
                                    bc_temp: bool = False) -> dict[str, Any]:
        """Write the charging plan.

        GRIC carries the write on ``ms-charge-manage`` (the SNC path
        ``/ms-app-bff/api/v3.0/veh/charge/plan`` is a 404 here).  The body keeps
        the SNC field names because both channels are served by the same
        ``ms-charge-manage`` backend; unlike the control route, this one has not
        been exercised field-by-field against a real car, so a rejected write
        reports the gateway's own message.
        """
        await self._require_access_token()
        result = await self._post(
            self._tsp_host(vin),
            "/ms-charge-manage/api/v1.0/charge/setChargingPlan",
            {
                "vin": vin,
                "command": command,
                "startTime": start_time,
                "endTime": end_time,
                "bcCycleActive": bc_cycle,
                "bcTempActive": bc_temp,
            },
        )
        if not _accepted(result):
            raise ZeekrApiError(
                f"GRIC 拒绝了充电计划：{_result_brief(result)}"
            )
        return {**result, "gateway": "gric"}

    async def async_set_travel_plan(self, vin: str, command: str,
                                    start_time: str, scheduled_time: str,
                                    ac_preconditioning: bool = True,
                                    steering_wheel_heating: bool = False
                                    ) -> dict[str, Any]:
        """Write the travel plan (see :meth:`async_set_charge_plan`)."""
        await self._require_access_token()
        result = await self._post(
            self._tsp_host(vin),
            "/ms-charge-manage/api/v1.0/charge/setTravelPlan",
            {
                "vin": vin,
                "command": command,
                "startTime": start_time,
                "scheduledTime": scheduled_time,
                "ac": "true" if ac_preconditioning else "false",
                "bw": "1" if steering_wheel_heating else "0",
            },
        )
        if not _accepted(result):
            raise ZeekrApiError(
                f"GRIC 拒绝了行程计划：{_result_brief(result)}"
            )
        return {**result, "gateway": "gric"}

    # -- diagnostics ------------------------------------------------------

    def dump_raw(self) -> dict[str, Any]:
        """Return raw payloads for the whole account (secrets excluded)."""
        return {
            "channel": "gric",
            "device_id": self._device_id,
            "gateways": self.gateway_summary(),
            "vehicles": [{"vin": v.vin, **v.meta} for v in self._vehicles],
            "raw_payloads": self._raw_payloads,
        }
