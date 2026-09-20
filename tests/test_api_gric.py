"""Regression tests for the GRIC channel (``api_gric.py``).

The signature is the load-bearing part.  Every way of getting it wrong looks
identical from the outside — the gateway answers ``00A06`` — so a signing bug, a
wrong header list and a misplaced query string are indistinguishable in the log.
These tests pin the details that cost the most time to find:

* the canonical query goes **before** the method, not after the path;
* only the 18 whitelisted headers are signed (``accept`` / ``user-agent`` are
  sent but excluded);
* a GET carries no ``base64(md5(body))`` line, a POST does;
* the body hash is taken over the bytes actually transmitted (compact JSON).

The body-hash vector is the app's own heartbeat body, captured from the running
process, so it is ground truth rather than a self-consistency check.

``api_gric`` reaches Home Assistant only through its siblings (``.const``,
``.parser``, ``.api_sms``), so it loads inside a throwaway package; pycryptodome
— needed only by ``api_sms`` to encrypt a VIN — is stubbed when absent.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac
import importlib.util
import json
import sys
import time
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PKG_DIR = _ROOT / "custom_components" / "zeekr_ev"
_PACKAGE_NAME = "zeekr_ev_under_test_gric"


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


def _load(module_name: str):
    """Import one integration module inside a throwaway package."""
    _stub_crypto_if_missing()
    package = sys.modules.get(_PACKAGE_NAME)
    if package is None:
        package = types.ModuleType(_PACKAGE_NAME)
        package.__path__ = [str(_PKG_DIR)]
        sys.modules[_PACKAGE_NAME] = package
    spec = importlib.util.spec_from_file_location(
        f"{_PACKAGE_NAME}.{module_name}", _PKG_DIR / f"{module_name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


gric = _load("api_gric")
parser = _load("parser")


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

#: The full set of signed headers with stable values, so a base string can be
#: compared literally rather than re-derived.
SIGNED = {
    "accept-language": "zh_CN",
    "authorization": "JWT",
    "x-api-signature-nonce": "nonce",
    "x-api-signature-version": "2.1",
    "x-app-id": "GEELYCNCH001M0001",
    "x-app-version": "v1.0.0",
    "x-device-brand": "GOOGLE",
    "x-device-id": "device",
    "x-device-model": "Pixel5",
    "x-device-os-version": "Android 14 (API 34)",
    "x-platform": "Android",
    "x-sales-platform": "ZEEKR",
    "x-tenant-id": "ZEEKR",
    "x-timestamp": "1234567890",
    "x-tsp-platform": "4",
    "x-vehicle-brand": "ZEEKR",
    "x-vehicle-identifier": "IDENT",
    "x-vehicle-series": "QlgxRQ==",
}

HEARTBEAT = {"deviceType": 1, "enableWakeUp": False, "hbType": 1, "ts": 1789916477924}
HEARTBEAT_BODY = b'{"deviceType":1,"enableWakeUp":false,"hbType":1,"ts":1789916477924}'
HEARTBEAT_MD5_B64 = "6/qC8AxXFnKbyYXSix4UIg=="


class _FakeResponse:
    def __init__(self, body, status=200):
        self._body = body
        self.status = status

    async def json(self, content_type=None):
        # A real response is deserialised fresh every time.  Returning the same
        # object would let the client build a self-referencing payload
        # (``raw.setdefault(key, raw)`` in the extras merge), which then blows
        # the recursion limit inside the shared parser.
        return copy.deepcopy(self._body)

    async def text(self):
        return json.dumps(self._body)


class _FakeRequest:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class _FakeSession:
    """Records the kwargs aiohttp would receive."""

    def __init__(self, body):
        self._single = body
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return _FakeRequest(_FakeResponse(self._single))


def _lower_headers(call: dict) -> set[str]:
    return {key.lower() for key in call["headers"]}


def _jwt(exp: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode())
    return f"eyJhbGciOiJSUzI1NiJ9.{payload.decode().rstrip('=')}.sig"


def _client(body=None, **tokens):
    session = _FakeSession(body if body is not None else {"code": "0", "data": []})
    client = gric.ZeekrGricApiClient(session)
    if tokens:
        client.store_tokens(tokens)
    return client, session


class _SequenceSession:
    """Hands out each response in turn (the last one repeats).

    Renewal changes the *order* of calls, so a single canned body is not enough
    to tell "renewed first" from "renewed after a refusal".
    """

    def __init__(self, responses):
        self._responses = responses
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        index = min(len(self.calls) - 1, len(self._responses) - 1)
        return _FakeRequest(_FakeResponse(copy.deepcopy(self._responses[index])))


# ---------------------------------------------------------------------------
# Signature primitives
# ---------------------------------------------------------------------------


def test_canonical_query_sorts_by_key_and_keeps_blank_values():
    assert gric.canonical_query(None) == ""
    assert gric.canonical_query({}) == ""
    assert gric.canonical_query({"tspPlatform": "4"}) == "tspPlatform=4"
    # ``latest`` is present but empty in the app's own request; dropping it
    # changes the signature.
    assert gric.canonical_query({"target": "new", "latest": ""}) == "latest=&target=new"
    assert gric.canonical_query({"b": "2", "a": "1"}) == "a=1&b=2"


def test_get_base_places_the_query_before_the_method():
    """The single most expensive detail: query first, method second."""
    base = gric.build_base(
        "GET", "/ms-app-bff/api/1.0/permissions", SIGNED, {"tspPlatform": "4"}
    )
    lines = base.split("\n")
    assert lines[:18] == [f"{key}:{SIGNED[key]}" for key in sorted(SIGNED)]
    assert lines[18] == "tspPlatform=4"
    assert lines[19] == "GET"
    assert lines[20] == "/ms-app-bff/api/1.0/permissions"
    # The path is signed without its query string.
    assert "?" not in base


def test_get_without_query_has_no_body_hash_line():
    base = gric.build_base(
        "GET", "/ms-user-manager/api/v1.0/user/get/user/info", SIGNED
    )
    assert base.endswith(
        "GET\n/ms-user-manager/api/v1.0/user/get/user/info"
    )
    assert "==" not in base.replace("QlgxRQ==", "")


def test_post_body_hash_line_matches_the_captured_app_request():
    body = gric.encode_body(HEARTBEAT)
    assert body == HEARTBEAT_BODY
    base64.b64encode(hashlib.md5(body).digest()).decode() == HEARTBEAT_MD5_B64

    base = gric.build_base(
        "POST", "/ms-app-online-center/api/v2.0/app/hb", SIGNED, None, body
    )
    lines = base.split("\n")
    assert lines[-3] == HEARTBEAT_MD5_B64
    assert lines[-2] == "POST"
    assert lines[-1] == "/ms-app-online-center/api/v2.0/app/hb"


def test_encode_body_is_compact_json():
    """The bytes hashed must be the bytes sent: no space after ``:`` or ``,``."""
    assert gric.encode_body({"b": 2, "a": 1}) == b'{"b":2,"a":1}'
    assert gric.encode_body(None) == b""
    assert gric.encode_body(b"raw") == b"raw"


def test_only_the_whitelisted_headers_are_signed():
    headers = {**SIGNED, "accept": "application/json", "user-agent": "okhttp/4.12.0"}
    base = gric.build_base("GET", "/p", headers)
    assert "user-agent" not in base
    assert "okhttp" not in base
    assert "accept-language:zh_CN" in base


def test_blank_header_values_are_left_out():
    headers = {**SIGNED, "authorization": ""}
    base = gric.build_base("GET", "/p", headers)
    assert "authorization:" not in base


def test_signature_is_base64_hmac_sha256():
    base, signature = gric.sign_request("GET", "/x", {})
    expected = base64.b64encode(
        hmac.new(gric._SIGN_KEY, base.encode(), hashlib.sha256).digest()
    ).decode()
    assert signature == expected
    # Base64 (44 chars, one pad) — not hex, not URL-safe.
    assert len(signature) == 44 and signature.endswith("=")


def test_vehicle_identifier_changes_the_signature():
    """It is a signed header, so a configured value must reach the base string."""
    without = gric.build_base("GET", "/p", {**SIGNED, "x-vehicle-identifier": ""})
    with_ident = gric.build_base("GET", "/p", SIGNED)
    assert without != with_ident


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def test_jwt_expiry_reads_unverified_claims():
    assert gric._jwt_expiry(_jwt(4102444800)) == 4102444800.0
    assert gric._jwt_expiry("not-a-jwt") is None
    assert gric._jwt_expiry(None) is None


def test_host_of_accepts_a_url_or_a_bare_host():
    assert gric._host_of("https://gric-zhf-api.geely.com") == "gric-zhf-api.geely.com"
    assert gric._host_of("gric-zhf-api.geely.com/") == "gric-zhf-api.geely.com"
    assert gric._host_of(None) is None


# ---------------------------------------------------------------------------
# Client behaviour
# ---------------------------------------------------------------------------


def test_vehicle_list_parses_meta_and_adopts_the_car_s_host():
    client, session = _client(
        {"code": "0", "data": [{
            "vin": "L6T77HCE9PF081833",
            "plateNo": "粤ADR2642",
            "nickName": "小粉",
            "modelName": "YOU版 四座后驱",
            "seriesCode": "BX1E",
            "brandCode": "ZEEKR",
            "tenantId": "ZEEKR",
            "tspHost": "https://gric-zhf-api.geely.com",
        }]},
        **{gric.STORAGE_GRIC_ACCESS_TOKEN: "A"},
    )

    vehicles = asyncio.run(client.async_get_vehicle_list())

    assert [v.vin for v in vehicles] == ["L6T77HCE9PF081833"]
    assert vehicles[0].meta["plate"] == "粤ADR2642"
    assert vehicles[0].meta["brand"] == "ZEEKR"
    assert vehicles[0].meta["series"] == "BX1E"
    # Status/control must follow the per-car host from the list.  The vehicle
    # copies its metadata, so this only works if it is set before construction.
    assert vehicles[0].meta["tsp_host"] == "gric-zhf-api.geely.com"
    assert client._tsp_host("L6T77HCE9PF081833") == "gric-zhf-api.geely.com"
    # And the list route is the one that needs no identifier.
    assert "x-vehicle-identifier" not in _lower_headers(session.calls[0])
    assert session.calls[0]["url"].endswith(
        "/ms-vehicle-core/api/v1.0/vehicle/favorite-vehicles?tspPlatform=4"
    )


def test_vehicle_list_skips_entries_without_a_vin():
    client, _ = _client(
        {"code": "0", "data": [{"plateNo": "X"}, "junk", None]},
        **{gric.STORAGE_GRIC_ACCESS_TOKEN: "A"},
    )
    assert asyncio.run(client.async_get_vehicle_list()) == []


def test_status_uses_v2_and_carries_the_identifier():
    client, session = _client(
        {"code": "0", "data": {"electricVehicleStatus": {"chargeLevel": "90.0"}}},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
        },
    )
    data = asyncio.run(client.get_vehicle_status_gric("VIN"))

    assert data == {"electricVehicleStatus": {"chargeLevel": "90.0"}}
    call = session.calls[0]
    assert "/ms-vehicle-status/api/v2.0/vehicle/status/latest" in call["url"]
    assert "latest=&target=new" in call["url"]
    headers = call["headers"]
    assert headers["x-vehicle-identifier"] == "IDENT"
    assert headers["x-signature"]
    # A GET signs no body, so no hashed payload may be sent either.
    assert "data" not in call


def test_probe_passes_a_readable_car_and_names_an_unreadable_one():
    """The config flow's gate.

    The vehicle *list* works without ``x-vehicle-identifier``, so it cannot tell
    a good identifier from a bad one — only a per-vehicle read can.  That is why
    the config flow probes before creating the entry.
    """
    client, _ = _client(
        {"code": "0", "data": {"electricVehicleStatus": {"chargeLevel": "90.0"}}},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
        },
    )
    ok, detail = asyncio.run(client.async_probe_vehicle("VIN"))
    assert ok is True
    assert detail == ""

    # A wrong identifier makes the gateway reject the decrypt and the payload
    # comes back empty: not readable, and the reason is the gateway's own code.
    bad, _ = _client(
        {"code": "00A06", "msg": "Decrypt X-VEHICLE-IDENTIFIER failed"},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "WRONG",
        },
    )
    ok, detail = asyncio.run(bad.async_probe_vehicle("VIN"))
    assert ok is False
    assert "00A06" in detail


def test_probe_raises_when_the_identifier_is_missing():
    """``00A02`` names the header it wanted — the fastest way to see it is unset."""
    client, _ = _client(
        {
            "code": "00A02",
            "msg": "Required request header 'x-vehicle-identifier' is not present",
        },
        **{gric.STORAGE_GRIC_ACCESS_TOKEN: "A"},
    )
    with pytest.raises(gric.ZeekrApiError) as err:
        asyncio.run(client.async_probe_vehicle("VIN"))
    assert "x-vehicle-identifier" in str(err.value)


def test_control_body_nests_service_parameters():
    client, session = _client(
        {"code": "0", "msg": "操作成功", "data": {"sessionId": "S"}},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
        },
    )
    setting = {"serviceParameters": [{"key": "rhl", "value": "light-flash"}]}

    result = asyncio.run(
        client.async_do_remote_control("VIN", "start", "RHL", setting)
    )

    assert result["gateway"] == "gric"
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith(
        "/ms-remote-control/api/v1.0/remoteControl/control"
    )
    # The flat ``serviceParameters`` shape belongs to GW2 and is refused here.
    assert json.loads(call["data"]) == {
        "command": "start",
        "serviceId": "RHL",
        "setting": {"serviceParameters": setting["serviceParameters"]},
    }


def test_control_rejection_raises_with_the_gateway_message():
    client, _ = _client(
        {"code": "1051P004", "msg": "参数不正确"},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
        },
    )
    with pytest.raises(gric.ZeekrApiError) as err:
        asyncio.run(client.async_do_remote_control("VIN", "start", "RHL", {}))
    assert "1051P004" in str(err.value)


def test_refresh_rotates_and_keeps_the_new_refresh_token():
    """Losing the rotated refresh token would strand the entry."""
    client, session = _client(
        {"code": "0", "data": {
            "accessToken": "A2",
            "refreshToken": "R2",
            "accessExpiresTimestamp": 1,
            "refreshExpiresTimestamp": 2,
        }},
        **{gric.STORAGE_GRIC_REFRESH_TOKEN: "R1"},
    )

    assert asyncio.run(client.async_refresh()) is True

    storage = client.get_token_storage()
    assert storage[gric.STORAGE_GRIC_ACCESS_TOKEN] == "A2"
    assert storage[gric.STORAGE_GRIC_REFRESH_TOKEN] == "R2"
    # The token endpoint is account-scoped: no per-vehicle identifier.
    assert "x-vehicle-identifier" not in _lower_headers(session.calls[0])
    assert json.loads(session.calls[0]["data"]) == {"refreshToken": "R1"}


def test_refresh_failure_is_reported_not_raised():
    client, _ = _client(
        {"code": "1018P061", "msg": "refreshToken已过期"},
        **{gric.STORAGE_GRIC_REFRESH_TOKEN: "R1"},
    )
    assert asyncio.run(client.async_refresh()) is False
    assert client.gateway_summary()["token_log"][-1]["event"] == "refresh_rejected"


def test_a_refresh_token_alone_can_bootstrap_the_channel():
    """The config flow seeds an entry with nothing but a refresh token.

    Verified against the live server: the token endpoint is authorised by the
    refresh token itself, so it must not demand the access token it exists to
    mint — otherwise there would be no way in at all.
    """
    client, session = _client(
        {"code": "0", "data": {"accessToken": "A2", "refreshToken": "R2"}},
        **{gric.STORAGE_GRIC_REFRESH_TOKEN: "R1"},
    )
    assert client.has_gw3_token is False

    assert asyncio.run(client.async_ensure_gw3_token()) is True

    assert client.has_gw3_token is True
    assert "authorization" not in _lower_headers(session.calls[0])


def test_ensure_skips_the_round_trip_when_the_access_token_is_fresh():
    """Renewal is triggered a day ahead, so "fresh" means more than a day left."""
    client, session = _client(
        {"code": "0", "data": {}},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: _jwt(int(time.time()) + 3 * 24 * 3600),
            gric.STORAGE_GRIC_REFRESH_TOKEN: "R",
        },
    )
    assert asyncio.run(client.async_ensure_gw3_token()) is True
    assert session.calls == []


def test_ensure_refreshes_an_expired_access_token():
    client, session = _client(
        {"code": "0", "data": {"accessToken": "A2", "refreshToken": "R2"}},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: _jwt(int(time.time()) + 60),
            gric.STORAGE_GRIC_REFRESH_TOKEN: "R",
        },
    )
    assert asyncio.run(client.async_ensure_gw3_token()) is True
    assert len(session.calls) == 1
    assert "refresh/token" in session.calls[0]["url"]


def test_poll_renews_the_access_token_before_the_gateway_can_refuse_it():
    """Polling is the only heartbeat a long-running Home Assistant has.

    Access tokens live 7 days.  Renewing on failure alone means the first poll
    after expiry has to be recognised as "needs a refresh" — and the code for an
    *expired* token is not necessarily the one we map to a retry.
    """
    REFRESH = {"code": "0", "data": {"accessToken": "A2", "refreshToken": "R2"}}
    session = _SequenceSession([
        REFRESH,
        {"code": "0", "data": [{
            "vin": "L6T77HCE9PF081833",
            "plateNo": "粤ADR2642",
            "seriesCode": "BX1E",
            "tspHost": "https://gric-zhf-api.geely.com",
        }]},
        {"code": "0", "data": {"electricVehicleStatus": {"chargeLevel": "90.0"}}},
    ])
    client = gric.ZeekrGricApiClient(session)
    client.store_tokens({
        # Inside the renewal margin but not yet expired.
        gric.STORAGE_GRIC_ACCESS_TOKEN: _jwt(int(time.time()) + 3600),
        gric.STORAGE_GRIC_REFRESH_TOKEN: "R1",
        gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
    })

    asyncio.run(client.async_fetch_all())

    # Renewal happens first, not after a refusal.
    assert "refresh/token" in session.calls[0]["url"]
    # ...and the rotated pair is what gets used and persisted.
    status_call = next(
        call for call in session.calls if "vehicle/status/latest" in call["url"]
    )
    assert status_call["headers"]["authorization"] == "A2"
    storage = client.get_token_storage()
    assert storage[gric.STORAGE_GRIC_ACCESS_TOKEN] == "A2"
    assert storage[gric.STORAGE_GRIC_REFRESH_TOKEN] == "R2"


def test_control_renews_an_expired_token_instead_of_sending_it():
    """An expired token is still *present* — presence is not freshness."""
    session = _SequenceSession([
        {"code": "0", "data": {"accessToken": "A2", "refreshToken": "R2"}},
        {"code": "0", "msg": "操作成功"},
    ])
    client = gric.ZeekrGricApiClient(session)
    client.store_tokens({
        gric.STORAGE_GRIC_ACCESS_TOKEN: _jwt(int(time.time()) + 60),
        gric.STORAGE_GRIC_REFRESH_TOKEN: "R1",
        gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
    })

    asyncio.run(client.async_do_remote_control(
        "VIN", "start", "RHL",
        {"serviceParameters": [{"key": "rhl", "value": "light-flash"}]},
    ))

    assert "refresh/token" in session.calls[0]["url"]
    control = session.calls[1]
    assert "remoteControl/control" in control["url"]
    assert control["headers"]["authorization"] == "A2"


def test_expired_session_triggers_one_refresh_then_replays():
    """``00A17`` means another holder rotated the pair — recover, do not fail."""
    calls: list[str] = []

    class _Sequence:
        def __init__(self, responses):
            self._responses = responses

        def request(self, method, url, **kwargs):
            calls.append(url)
            body = self._responses[min(len(calls) - 1, len(self._responses) - 1)]
            return _FakeRequest(_FakeResponse(body))

    session = _Sequence([
        {"code": "00A17", "msg": "logged in elsewhere"},
        {"code": "0", "data": {"accessToken": "A2", "refreshToken": "R2"}},
        {"code": "0", "data": {"electricVehicleStatus": {}}},
    ])
    client = gric.ZeekrGricApiClient(session)
    client.store_tokens({
        gric.STORAGE_GRIC_ACCESS_TOKEN: "A1",
        gric.STORAGE_GRIC_REFRESH_TOKEN: "R1",
        gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
    })

    data = asyncio.run(client.get_vehicle_status_gric("VIN"))

    assert data == {"electricVehicleStatus": {}}
    assert len(calls) == 3
    assert "refresh/token" in calls[1]


def test_missing_access_token_raises_auth_error():
    client, _ = _client({"code": "0", "data": []})
    with pytest.raises(gric.ZeekrAuthError):
        asyncio.run(client.get_vehicle_status_gric("VIN"))


def test_bootstrap_requires_a_refresh_token():
    client, _ = _client({"code": "0", "data": []})
    with pytest.raises(gric.ZeekrAuthError):
        asyncio.run(client.async_bootstrap())


def test_fetch_all_normalises_through_the_shared_parser():
    client, _ = _client(
        {"code": "0", "data": {
            "electricVehicleStatus": {"chargeLevel": "90.0",
                                      "distanceToEmptyOnBatteryOnly": "336"},
            "drivingSafetyStatus": {"centralLockingStatus": "2"},
            "basic": {"position": {"latitude": 23.1015, "longitude": 113.377}},
        }},
        **{
            gric.STORAGE_GRIC_ACCESS_TOKEN: "A",
            gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
        },
    )
    client._vehicles = [gric.ZeekrVehicle("L6T77HCE9PF081833", {"vin": "L6T77HCE9PF081833"})]

    data = asyncio.run(client.async_fetch_all())

    canonical = data["L6T77HCE9PF081833"]
    assert canonical["battery"]["soc"] == 90.0
    assert canonical["battery"]["range"] == 336.0
    assert canonical["locks"]["central"] is True
    # GRIC sends plain degrees, which the shared coordinate normaliser accepts.
    assert canonical["position"]["latitude"] == pytest.approx(23.1015)
    assert canonical["position"]["longitude"] == pytest.approx(113.377)


def test_charge_limit_is_normalised_to_a_percentage():
    """GRIC reports the limit in tenths — ``950`` means 95 %."""
    assert parser.normalize_vehicle_data(
        {"chargingLimit": {"soc": "950"}}
    )["battery"]["limit"] == 95.0
    # Whole-percent channels are left alone.
    assert parser.normalize_vehicle_data(
        {"chargingLimit": {"soc": "80"}}
    )["battery"]["limit"] == 80.0
    assert parser.normalize_vehicle_data({})["battery"].get("limit") is None


def test_gateway_summary_never_exposes_tokens():
    client, _ = _client(None, **{
        gric.STORAGE_GRIC_ACCESS_TOKEN: "SECRET-A",
        gric.STORAGE_GRIC_REFRESH_TOKEN: "SECRET-R",
        gric.CONF_VEHICLE_IDENTIFIER: "IDENT",
    })
    summary = json.dumps(client.gateway_summary(), ensure_ascii=False)
    assert "SECRET-A" not in summary
    assert "SECRET-R" not in summary
    assert summary.count("IDENT") == 0
