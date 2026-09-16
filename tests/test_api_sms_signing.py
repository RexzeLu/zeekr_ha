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
    def __init__(self, body: dict):
        self._response = _FakeResponse(body)
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return _FakeRequest(self._response)


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
    signed = api_sms.ZeekrSmsApiClient._GW3_SIGNED
    head = "".join(
        f"{key.lower()}:{headers[key]}\n"
        for key in sorted(
            k for k, v in headers.items() if k.lower() in signed and v
        )
    )
    query = (
        "&".join(f"{k}={v}" for k, v in sorted((params or {}).items())) + "\n"
        if params else ""
    )
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

_OK = {"code": "000000", "msg": "OK", "data": {"accessToken": "gw3-token"}}


def _client(body: dict = _OK):
    session = _FakeSession(body)
    client = api_sms.ZeekrSmsApiClient(session)
    client._jwt_token = "jwt-token-value"
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
    expected = hmac.new(api_sms._SNC_SECRET.encode(), canonical.encode(),
                        hashlib.sha256).hexdigest()
    assert headers["X-SIGNATURE"] == expected


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
    expected = hmac.new(api_sms._SNC_SECRET.encode(), canonical.encode(),
                        hashlib.sha256).hexdigest()
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
    assert shape["app_id"] == "ZEEKRCNCH001M0000"
    assert shape["body_md5_b64"] is not None
    assert shape["has_authorization"] is True
    assert "authorization" in [h.lower() for h in shape["signed_headers"]]
    # Only header *names* — no credential values anywhere in the summary.
    blob = json.dumps(client.gateway_summary())
    assert "jwt-token-value" not in blob
    assert "gw3-token" not in blob


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
