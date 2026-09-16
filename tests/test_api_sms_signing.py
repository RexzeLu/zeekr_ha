"""Regression tests for the gateway request signatures.

GW2 and GW3 both embed ``base64(md5(body))`` in the string they sign, so the
bytes that get **signed** and the bytes that go **on the wire** have to be
byte-identical.

The scheme was reverse-engineered from the JavaScript client, where
``JSON.stringify`` emits compact JSON — no space after ``:`` or ``,``.  Handing
the payload to aiohttp as ``json=payload`` instead lets ``json.dumps`` use its
default ``", "`` / ``": "`` separators, so every POST was signed over one byte
string and sent as another.  The SNCTSP gateway answers ``079025 Signature
authentication failed`` for each of them — which broke GW3 login (so remote
control never got a token) while GETs, carrying no body, kept working.

``api_sms.py`` has no Home Assistant imports, so it loads straight from its file
(its only third-party need — pycryptodome, for VIN encryption — is stubbed).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PKG_DIR = _ROOT / "custom_components" / "zeekr_ev"


# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


def _stub_crypto_if_missing() -> None:
    """``api_sms`` needs pycryptodome only to encrypt a VIN."""

    try:
        import Crypto.Cipher  # noqa: F401
        return
    except Exception:  # noqa: BLE001 - any import failure means "not installed"
        pass

    def _missing(*args, **kwargs):  # pragma: no cover - never called here
        raise RuntimeError("pycryptodome is not installed")

    cipher = types.ModuleType("Crypto.Cipher")
    cipher.AES = types.SimpleNamespace(new=_missing, MODE_CBC=2)
    util = types.ModuleType("Crypto.Util")
    padding = types.ModuleType("Crypto.Util.Padding")
    padding.pad = _missing
    crypto = types.ModuleType("Crypto")
    crypto.Cipher = cipher
    crypto.Util = util
    util.Padding = padding
    for name, module in (
        ("Crypto", crypto),
        ("Crypto.Cipher", cipher),
        ("Crypto.Util", util),
        ("Crypto.Util.Padding", padding),
    ):
        sys.modules.setdefault(name, module)


def _load_api_sms():
    """Import ``api_sms`` inside a throwaway package so ``from .x`` resolves."""
    _stub_crypto_if_missing()
    package_name = "zeekr_ev_under_test"
    package = types.ModuleType(package_name)
    package.__path__ = [str(_PKG_DIR)]
    sys.modules[package_name] = package
    spec = importlib.util.spec_from_file_location(
        f"{package_name}.api_sms", _PKG_DIR / "api_sms.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


api_sms = _load_api_sms()


# ---------------------------------------------------------------------------
# A session that records exactly what aiohttp would be handed
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: dict):
        self._body = body
        self.status = 200

    async def json(self, content_type=None):
        return self._body

    async def text(self):
        return json.dumps(self._body)


class _FakeRequest:
    def __init__(self, response: _FakeResponse):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class _FakeSession:
    """Records the kwargs aiohttp would receive.

    ``body`` may be a single dict (returned for every call) or a list, which is
    consumed one entry per request — needed to exercise the transport fallback.
    """

    def __init__(self, body):
        self._bodies = list(body) if isinstance(body, list) else None
        self._single = None if self._bodies else body
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if self._bodies:
            body = self._bodies[min(len(self.calls) - 1, len(self._bodies) - 1)]
        else:
            body = self._single
        return _FakeRequest(_FakeResponse(body))


def _wire_body(call: dict) -> bytes | None:
    """The bytes aiohttp would actually transmit for this call."""
    if "data" in call and call["data"] is not None:
        data = call["data"]
        return data if isinstance(data, bytes) else str(data).encode()
    if call.get("json") is not None:
        # What ``json=`` does: ``json.dumps`` with its *default* separators.
        return json.dumps(call["json"]).encode()
    return None


def _canonical(method: str, path: str, headers: dict, params: dict | None,
               body: bytes | None) -> str:
    """Rebuild the GW3 canonical string the way the reference client does.

    This mirrors the Node-RED flow captured alongside the app — the ground truth
    for the algorithm — including the query substitutions and the Base64 output.
    """
    signed = api_sms.ZeekrSmsApiClient._GW3_SIGNED
    lines = []
    for key in sorted(headers, key=str.lower):
        lower = key.lower()
        if lower not in signed:
            continue
        value = headers[key]
        if lower in ("x-vin", "authorization") and not value:
            continue
        lines.append(f"{lower}:{value}\n")
    head = "".join(lines)

    query = ""
    if params:
        parts = []
        for k in sorted(params):
            v = str(params[k]).replace("*", "%2A").replace("%2F", "/").replace("%3F", "?")
            parts.append(f"{k}={v}")
        query = "&".join(parts) + "\n"

    body_part = (
        base64.b64encode(hashlib.md5(body).digest()).decode() + "\n"
        if body is not None else ""
    )
    return head + query + body_part + method.upper() + "\n" + path


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

LOGIN_PATH = "/ms-user-auth/v1.0/auth/login"
LOGIN_PAYLOAD = {
    "loginDeviceType": 1,
    "identityType": 5,
    "loginSystem": "ios",
    "loginDeviceId": "deadbeef",
    "token": "jwt-token-value",
    "loginPhoneBrand": "Apple",
}

VIN = "L6T77HCE9PF081833"

_OK = {"code": "000000", "msg": "OK", "data": {"accessToken": "gw3-token"}}


def _fake_encrypt_vin(vin: str) -> str:
    """Stand-in for the AES VIN cipher (pycryptodome is not a test dep)."""
    return f"ENC({vin})"


api_sms.ZeekrSmsApiClient._encrypt_vin = staticmethod(_fake_encrypt_vin)


def _client(body: dict = _OK):
    session = _FakeSession(body)
    client = api_sms.ZeekrSmsApiClient(session)
    client._jwt_token = "jwt-token-value"
    # Pretend the vehicle list is already known, so the auth calls can carry
    # X-VIN the way the official app does.
    client._vehicle_data[VIN] = {}
    return client, session


def _login_extra() -> dict:
    return {"Authorization": "jwt-token-value"}


# ---------------------------------------------------------------------------
# The bug: signed bytes vs transmitted bytes
# ---------------------------------------------------------------------------


def test_gw3_transmits_the_exact_bytes_it_signed():
    client, session = _client()

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    call = session.calls[0]
    assert _wire_body(call) == api_sms._json_body(LOGIN_PAYLOAD)


def test_gw3_body_is_compact_json():
    """``json=`` separators would break the md5 the gateway recomputes."""
    client, session = _client()

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    body = _wire_body(session.calls[0])
    assert body is not None
    assert b'", "' not in body and b'": "' not in body
    assert body == json.dumps(LOGIN_PAYLOAD, separators=(",", ":")).encode()


def test_gw3_signature_covers_the_transmitted_body():
    """Rebuild the canonical string from the wire and the sent signature must match."""
    client, session = _client()

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    call = session.calls[0]
    headers = call["headers"]
    canonical = _canonical("POST", LOGIN_PATH, headers, None, _wire_body(call))
    expected = base64.b64encode(
        hmac.new(api_sms._SNC_SECRET.encode(), canonical.encode(),
                 hashlib.sha256).digest()
    ).decode()
    assert headers["X-SIGNATURE"] == expected
    # The app emits Base64 (44 chars), not hex (64 chars).
    assert len(headers["X-SIGNATURE"]) == 44


def test_gw3_get_carries_no_body_and_is_signed_without_one():
    client, session = _client({"code": "000000", "data": []})

    asyncio.run(client._gw3("GET", "/ms-app-bff/api/v3.0/veh/vehicle-list",
                            params={"needSharedCar": "true"},
                            extra={"Authorization": "jwt-token-value"}))

    call = session.calls[0]
    assert _wire_body(call) is None
    headers = call["headers"]
    canonical = _canonical("GET", "/ms-app-bff/api/v3.0/veh/vehicle-list",
                           headers, {"needSharedCar": "true"}, None)
    expected = base64.b64encode(
        hmac.new(api_sms._SNC_SECRET.encode(), canonical.encode(),
                 hashlib.sha256).digest()
    ).decode()
    assert headers["X-SIGNATURE"] == expected


def test_gw2_transmits_the_exact_bytes_it_signed():
    client, session = _client({"code": "000000", "data": {}})

    asyncio.run(client._gw2("POST", "/auth/account/session/secure",
                            params={"identity_type": "zeekr"},
                            payload={"authCode": "code-123"}))

    call = session.calls[0]
    body = _wire_body(call)
    assert body == api_sms._json_body({"authCode": "code-123"})

    headers = call["headers"]
    # GW2's canonical string is fixed-format; only the body hash must line up.
    body_b64 = base64.b64encode(hashlib.md5(body).digest()).decode()
    query = "identity_type=zeekr"
    signing = "\n".join([
        "application/json;responseformat=3",
        f"x-api-signature-nonce:{headers['x-api-signature-nonce']}",
        "x-api-signature-version:1.0",
        "",
        query,
        body_b64,
        headers["x-timestamp"],
        "POST",
        "/auth/account/session/secure",
    ])
    expected = base64.b64encode(
        hmac.new(api_sms._LINE_SECRET.encode(), signing.encode(),
                 hashlib.sha1).digest()
    ).decode()
    assert headers["x-signature"] == expected


def test_gw3_reporting_helpers_do_not_leak_tokens():
    client, _ = _client()

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    shape = client.gateway_summary()["gw3_last_request"]
    assert shape["method"] == "POST"
    assert shape["path"] == LOGIN_PATH
    assert shape["app_id"] == "ZEEKRCNCH001M0001"
    assert shape["body_md5_b64"] is not None
    assert shape["has_authorization"] is True
    assert "authorization" in [h.lower() for h in shape["signed_headers"]]
    # Only header *names* — no credential values anywhere in the summary.
    blob = json.dumps(client.gateway_summary())
    assert "jwt-token-value" not in blob
    assert "gw3-token" not in blob


def test_gw3_headers_match_the_official_app():
    """The gateway looks its signing key up by X-APP-ID.

    ``ZEEKRCNCH001M0000`` used to be sent on the auth calls, which the gateway
    answered with ``079025 Signature authentication failed`` — every GW3 call
    must use the same id, and it is the one the real app sends.
    """
    client, session = _client()

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    headers = session.calls[0]["headers"]
    assert headers["X-APP-ID"] == "ZEEKRCNCH001M0001"
    assert headers["AppId"] == "ONEX97FB91F061405"
    assert headers["Content-Type"] == "application/json; charset=UTF-8"
    assert headers["X-API-SIGNATURE-VERSION"] == "2.0"
    assert headers["X-PROJECT-ID"] == "ZEEKR"
    assert headers["X-PLATFORM"] == "APP"
    assert headers["Accept-Language"] == "en-US"
    assert headers["X-APP-OS-VERSION"] == "4.9.28"
    assert headers["X-P"] == "Android"
    assert headers["User-Agent"] == "okhttp/4.12.0"
    # A plain dashed UUID, as the app sends it.
    assert len(headers["X-API-SIGNATURE-NONCE"]) == 36
    assert headers["X-API-SIGNATURE-NONCE"].count("-") == 4


def test_gw3_auth_calls_identify_the_car_but_carry_no_bearer():
    """The app authenticates login/refresh with the JWT *in the body*."""
    client, session = _client()

    asyncio.run(client.snc_login())

    headers = session.calls[0]["headers"]
    assert "Authorization" not in headers
    assert headers["X-VIN"] == f"ENC({VIN})"
    payload = json.loads(_wire_body(session.calls[0]))
    # The GW1 answer hands back "Bearer <jwt>" and the app forwards it verbatim.
    assert payload["token"] == "Bearer jwt-token-value"
    assert payload["identityType"] == 5
    assert payload["loginDeviceType"] == 1
    assert payload["loginSystem"] == "Android"
    assert payload["loginPhoneBrand"] == "Android"
    assert payload["credential"] == ""
    assert payload["loginDeviceJgId"] == ""


def test_gw3_extra_prefixes_a_bare_access_token():
    client, _ = _client()
    # The gateway hands the token back already prefixed; it must not be doubled.
    client._new_access_token = "Bearer eyJhbGci"
    assert client._gw3_extra(VIN, client._new_access_token)["Authorization"] == (
        "Bearer eyJhbGci"
    )
    client._new_access_token = "eyJhbGci"
    assert client._gw3_extra(VIN, client._new_access_token)["Authorization"] == (
        "Bearer eyJhbGci"
    )
    # Without a known VIN the header is simply left out.
    assert "X-VIN" not in client._gw3_extra(None, "t")


def test_gw3_rejected_request_is_kept_for_diagnostics():
    """A later successful GET must not bury the request that got rejected."""
    client, _ = _client({
        "code": "079025",
        "msg": "Signature authentication failed.",
    })

    asyncio.run(client._gw3("POST", LOGIN_PATH, payload=LOGIN_PAYLOAD,
                            extra=_login_extra(), retry=False))

    rejected = client.gateway_summary()["gw3_last_rejected"]
    assert rejected["path"] == LOGIN_PATH
    assert rejected["response"]["code"] == "079025"
    assert rejected["response"]["msg"] == "Signature authentication failed."

    # A later, successful GET is recorded separately and leaves the above be.
    client._session = _FakeSession({"code": "000000", "data": []})
    asyncio.run(client._gw3("GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
                            params={"latest": "false", "target": "new"},
                            extra={"X-VIN": "encrypted", "Authorization": "gw3-token"}))
    summary = client.gateway_summary()
    assert summary["gw3_last_request"]["method"] == "GET"
    assert summary["gw3_last_rejected"]["path"] == LOGIN_PATH


# ---------------------------------------------------------------------------
# Remote control transport
# ---------------------------------------------------------------------------

AC_SETTING = {
    "serviceParameters": [
        {"key": "AC", "value": "true"},
        {"key": "AC.temp", "value": "22.0"},
    ]
}


def _command_client(responses):
    session = _FakeSession(responses)
    client = api_sms.ZeekrSmsApiClient(session)
    client._jwt_token = "jwt-token-value"
    client._user_id = "uid-1"
    client._vehicle_data[VIN] = {}
    client._new_access_token = "gw3-token"
    return client, session


def test_remote_control_body_matches_the_telematics_pipe():
    client, _ = _command_client({"code": "000000"})

    body = client._telematics_body("start", "ZAF", AC_SETTING)
    assert body["command"] == "start"
    assert body["serviceId"] == "ZAF"
    assert body["serviceParameters"] == AC_SETTING["serviceParameters"]
    assert body["userId"] == "uid-1"
    assert body["creator"] == "tc"
    assert body["timestamp"].isdigit()
    # Only added when the caller asks for a timed run.
    assert "operationScheduling" not in body

    timed = client._telematics_body("start", "ZAF", {**AC_SETTING, "duration": 180})
    assert timed["operationScheduling"] == {
        "duration": 180, "interval": 0, "occurs": 1, "recurrentOperation": False,
    }


def test_remote_control_uses_the_snctsp_control_endpoint():
    """``/ms-remote-control/v1.0/remoteControl/control`` — not the invented path.

    The path that used to be hard-coded (``/ms-vehicle-control/api/v1.0/
    vehicle/control``) was answered with 404.  This one, plus the
    ``setting.serviceParameters`` nesting, comes from a working Zeekr
    integration authenticating against the same SNCTSP gateway.
    """
    client, session = _command_client({"code": "000000"})

    result = asyncio.run(
        client.async_do_remote_control(VIN, "start", "ZAF", AC_SETTING)
    )

    assert result["gateway"] == "gw3"
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == (
        "https://snc-tsp-api.zeekrlife.com"
        "/ms-remote-control/v1.0/remoteControl/control"
    )
    sent = json.loads(_wire_body(call))
    assert sent["command"] == "start"
    assert sent["serviceId"] == "ZAF"
    # serviceParameters live under "setting", not at the top level.
    assert sent["setting"] == {"serviceParameters": AC_SETTING["serviceParameters"]}
    assert "serviceParameters" not in sent


def test_remote_control_falls_back_to_the_gw2_telematics_pipe():
    client, session = _command_client([
        {"code": "079001", "msg": "[SDK]此接口未被授权，无法访问!"},
        {"code": "1000", "msg": "操作成功"},
    ])

    result = asyncio.run(
        client.async_do_remote_control(VIN, "start", "ZAF", AC_SETTING)
    )

    assert result["gateway"] == "gw2"
    assert len(session.calls) == 2
    assert session.calls[1]["method"] == "PUT"
    assert session.calls[1]["url"] == (
        f"https://api.zeekrline.com/remote-control/vehicle/telematics/{VIN}"
    )

    # The trail keeps both hops, so a diagnostics dump shows why it moved on.
    summary = client.gateway_summary()["command_attempts"]
    assert [item["gateway"] for item in summary] == ["gw3", "gw2"]
    assert summary[0]["code"] == "079001"
    assert summary[1]["code"] == "1000"


def test_remote_control_error_names_every_gateway_tried():
    client, _ = _command_client({"code": "00A01", "msg": "404 Not Found"})

    with pytest.raises(api_sms.ZeekrApiError) as err:
        asyncio.run(client.async_do_remote_control(VIN, "start", "ZAF", AC_SETTING))

    message = str(err.value)
    assert "ZAF" in message
    assert "gw2" in message and "gw3" in message
    attempts = client.gateway_summary()["command_attempts"]
    assert [item["gateway"] for item in attempts] == ["gw3", "gw2"]
