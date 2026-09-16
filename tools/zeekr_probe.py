#!/usr/bin/env python3
"""Live probe console: drive the integration's real client from the command line.

Every question left in the GW3 investigation ("which route does the China IDaaS
serve", "which login mints a token the vehicle interfaces accept") can only be
answered by a real request — and answering one through Home Assistant costs a
restart.  This tool loads **the same** ``api_sms`` module the integration ships,
replaces aiohttp with a stdlib transport (aiohttp is not installable here, and
the module never imports it anyway — it only ever calls ``session.request``),
and drives it directly.

It is a developer tool: it talks to the real gateways with real credentials and
therefore must never be pointed at anything but the owner's own account.

Usage
-----
    python tools/zeekr_probe.py --creds creds.json <command> [options]

Commands
--------
    summary                 what the client currently holds (no network)
    bootstrap               restore the stored session, load vehicles, get GW3
    status [VIN]            fetch + parse vehicle status, show the source
    probe                   the full endpoint/X-VIN probe matrix
    routes [PATH ...]       ask every tspCode candidate route, print the replies
    raw METHOD PATH         any GW3 call (``--query k=v``, ``--no-token``)
    gw1 METHOD PATH         any GW1 call (``--host``)
    sms-request PHONE       send a verification code
    sms-verify PHONE CODE   complete the login (replaces the stored tokens)
    save PATH               write the refreshed tokens back out

``creds.json`` is a config entry as stored by Home Assistant (the ``data``
object), e.g. extracted from ``.storage/core.config_entries`` in a backup.
"""

from __future__ import annotations

import argparse
import base64
import asyncio
import gzip
import importlib.util
import json
import time
import logging
import pathlib
import ssl
import sys
import types
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PKG_DIR = _ROOT / "custom_components" / "zeekr_ev"


# ---------------------------------------------------------------------------
# Loading the integration's own client code
# ---------------------------------------------------------------------------


def load_api_sms():
    """Import ``api_sms`` inside a throwaway package so ``from .x`` resolves."""
    package_name = "zeekr_probe_pkg"
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


api_sms = load_api_sms()


# ---------------------------------------------------------------------------
# A stdlib stand-in for aiohttp's ClientSession
# ---------------------------------------------------------------------------


class _Response:
    """The subset of ``aiohttp.ClientResponse`` that the client actually uses."""

    def __init__(self, status: int, body: bytes, url: str) -> None:
        self.status = status
        self._body = body
        self.url = url

    async def json(self, content_type: str | None = None) -> Any:
        return json.loads(self._body.decode("utf-8"))

    async def text(self) -> str:
        return self._body.decode("utf-8", "replace")

    async def __aenter__(self) -> _Response:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


class _Call:
    """Performs the request on ``async with`` (aiohttp semantics)."""

    def __init__(self, session: StdlibSession, method: str, url: str,
                 kwargs: dict[str, Any]) -> None:
        self._session = session
        self._method = method
        self._url = url
        self._kwargs = kwargs

    def _perform(self) -> _Response:
        return self._session.perform(self._method, self._url, self._kwargs)

    async def __aenter__(self) -> _Response:
        return self._perform()

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def __await__(self) -> Any:
        async def _run() -> _Response:
            return self._perform()

        return _run().__await__()


class StdlibSession:
    """Minimal ``session.request`` on top of ``urllib`` (no aiohttp here)."""

    def __init__(self, proxy: str | None = None, timeout: float = 25.0,
                 trace: bool = False) -> None:
        # ``trace`` prints every request/response verbatim — the whole point of
        # a probe tool is seeing what the gateway actually said.
        self.trace = trace
        handlers: list[Any] = []
        if proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}
            ))
        else:
            # Bypass any ambient proxy: the gateways answer directly.
            handlers.append(urllib.request.ProxyHandler({}))
        handlers.append(urllib.request.HTTPSHandler(
            context=ssl.create_default_context()
        ))
        self._opener = urllib.request.build_opener(*handlers)
        self._timeout = timeout
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _Call:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _Call(self, method, url, kwargs)

    def perform(self, method: str, url: str, kwargs: dict[str, Any]) -> _Response:
        response = self._perform(method, url, kwargs)
        if self.trace:
            print(f"\n---> {method.upper()} {url}")
            if kwargs.get("data"):
                print(f"     body: {kwargs['data'][:400]!r}")
            print(f"     {response.status} {response.debug_body()[:600]}")
        return response

    def _perform(self, method: str, url: str, kwargs: dict[str, Any]) -> _Response:
        data = kwargs.get("data")
        headers = dict(kwargs.get("headers") or {})
        if data is not None and "Content-Length" not in headers:
            headers["Content-Length"] = str(len(data))
        request = urllib.request.Request(
            url, data=data, headers=headers, method=method.upper()
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as raw:
                body = raw.read()
                if (raw.headers.get("Content-Encoding") or "").lower() == "gzip":
                    body = gzip.decompress(body)
                return _Response(raw.status, body, url)
        except urllib.error.HTTPError as err:
            body = err.read()
            if (err.headers.get("Content-Encoding") or "").lower() == "gzip":
                try:
                    body = gzip.decompress(body)
                except Exception:  # noqa: BLE001 - report it raw then
                    pass
            return _Response(err.code, body, url)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def redact(value: Any) -> str:
    """Never print a credential — only its shape."""
    if value is None:
        return "None"
    text = str(value)
    if len(text) <= 16:
        return repr(text)
    return f"<{len(text)} chars: {text[:8]}…>"


def show(title: str, payload: Any, limit: int = 4000) -> None:
    print(f"\n=== {title} ===")
    if isinstance(payload, str):
        print(payload)
        return
    text = json.dumps(payload, ensure_ascii=False, indent=1)
    print(text if len(text) <= limit else text[:limit] + " …(截断)")


def brief(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"raw": str(result)[:200]}
    return {
        "code": result.get("code"),
        "msg": result.get("msg") or result.get("message"),
        "success": result.get("success"),
        "top_keys": sorted(result),
        "data_keys": sorted(result["data"])[:20]
        if isinstance(result.get("data"), dict) else None,
    }


def query_params(items: list[str] | None) -> dict[str, str] | None:
    if not items:
        return None
    out: dict[str, str] = {}
    for item in items:
        key, _, value = item.partition("=")
        out[key] = value
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def build_client(args: argparse.Namespace):
    session = StdlibSession(proxy=args.proxy, timeout=args.timeout)
    client = api_sms.ZeekrSmsApiClient(session)
    if args.creds:
        data = json.loads(pathlib.Path(args.creds).read_text(encoding="utf-8"))
        if "data" in data and isinstance(data["data"], dict):
            data = data["data"]          # a whole config entry was handed over
        client.store_tokens(data)
        client.set_vehicle_token(data.get("vehicle_token"))
    return client, session


def cmd_summary(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    show("本地客户端状态", client.gateway_summary())
    print(f"\n  jwt_token        : {redact(client._jwt_token)}")
    print(f"  gw2 access_token : {redact(client._access_token)}")
    print(f"  gw2 refresh_token: {redact(client._refresh_token)}")
    print(f"  gw3 access_token : {redact(client._new_access_token)}")
    print(f"  device_id        : {client._device_id}")
    print(f"  login_device_id  : {client._login_device_id}")
    print(f"  client_id        : {redact(client._client_id)}")
    print(f"  user_id          : {client._user_id}")
    return 0


async def _bootstrap(client) -> None:
    vehicles = await client.async_bootstrap()
    show("车辆列表", [
        {"vin": v.vin, "name": getattr(v, "display_name", None), "raw_keys": sorted(v.raw or {})}
        for v in vehicles
    ])
    show("网关状态", client.gateway_summary())


def cmd_bootstrap(args: argparse.Namespace) -> int:
    client, session = build_client(args)
    try:
        asyncio.run(_bootstrap(client))
    except Exception as exc:  # noqa: BLE001 - a probe reports, never crashes
        print(f"\n!! bootstrap 失败: {type(exc).__name__}: {exc}")
        show("网关状态（失败后）", client.gateway_summary())
        return 1
    print(f"\n共发出 {len(session.calls)} 个请求")
    for call in session.calls:
        print(f"  {call['method']:4s} {call['url']}")
    return 0


async def _status(client, vin: str | None) -> None:
    if not client._vehicles:
        await client.async_get_vehicle_list()
    for vehicle in client._vehicles:
        if vin and vehicle.vin != vin:
            continue
        raw = await client.async_fetch_all(vehicle.vin) \
            if hasattr(client, "async_fetch_all") else None
        print(f"\n--- {vehicle.vin} ---")
        if raw is None:
            status = await client._fetch_raw_status(vehicle.vin)
            print("status_source:", client.gateway_summary()["status_source"])
            show("raw 顶层键", sorted(status or {}))
            climate = ((status or {}).get("additionalVehicleStatus") or {}).get("climateStatus") or {}
            show("climateStatus", climate)
        else:
            show("fetch_all", raw)


def cmd_status(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    asyncio.run(_status(client, args.vin))
    return 0


async def _probe(client) -> None:
    if not client._vehicles:
        await client.async_get_vehicle_list()
    vin = client._vehicles[0].vin
    print(f"探测目标车辆: {vin}")
    result = await client.probe_endpoints(vin)
    show("路径探测", result.get("paths"))
    cands = result.get("x_vin_candidates")
    if cands:
        for item in cands:
            item.pop("value", None)       # may be a capability secret
        show("X-VIN 候选", cands)
    show("平台令牌链", client.gateway_summary().get("platform_chain"))


def cmd_probe(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    asyncio.run(_probe(client))
    return 0


async def _routes(client, extra: list[str], host: str | None) -> None:
    """Ask every candidate route for a tspCode and print each reply."""
    candidates = list(api_sms._TSP_CODE_CANDIDATES)
    for path in extra:
        candidates.append((host or api_sms._GW1_HOST, path))
    if not client._vehicles:
        try:
            await client.async_get_vehicle_list()
        except Exception as exc:  # noqa: BLE001
            print(f"（车辆列表获取失败，跳过 X-VIN：{exc}）")

    client_ids = [cid for cid in (client._client_id, *api_sms._TSP_CLIENT_IDS) if cid]
    print(f"client_id 候选: {len(client_ids)} 个")
    for cid in client_ids:
        print(f"   {redact(cid)}")

    rows = []
    for host_name, path in candidates:
        for client_id in client_ids[:1]:
            try:
                result = await client._gw1(
                    "GET", path, params={"tspClientId": client_id}, host=host_name
                )
            except Exception as exc:  # noqa: BLE001
                rows.append({"host": host_name, "path": path,
                             "error": f"{type(exc).__name__}: {exc}"[:120]})
                continue
            info = brief(result)
            info["host"] = host_name
            info["path"] = path
            rows.append(info)
    show("tspCode 候选应答", rows, limit=12000)
    print("\n（`top_keys` 是响应体的键名：我方信封是 code/msg/success；"
          "Spring 错误体是 error/path/status/timestamp）")


def cmd_routes(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    asyncio.run(_routes(client, args.path or [], args.host))
    return 0


def cmd_raw(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    if not client._vehicles:
        try:
            asyncio.run(client.async_get_vehicle_list())
        except Exception as exc:  # noqa: BLE001
            print(f"（车辆列表获取失败：{exc}）")
    vin = args.vin or (client._vehicles[0].vin if client._vehicles else None)
    token = None if args.no_token else client._new_access_token
    if token is None and not args.no_token:
        asyncio.run(client.async_ensure_gw3_token())
        token = client._new_access_token
    result = asyncio.run(client._gw3(
        args.method.upper(), args.target, params=query_params(args.query),
        token=token, vin=vin, retry=False,
    ))
    show(f"{args.method.upper()} {args.target}", brief(result))
    print("\n完整响应（截断 2000 字符）：")
    print(json.dumps(result, ensure_ascii=False)[:2000])
    return 0


def cmd_gw1(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    result = asyncio.run(client._gw1(
        args.method.upper(), args.target,
        params=query_params(args.query), host=args.host,
    ))
    show(f"GW1 {args.method.upper()} {args.target}", brief(result))
    print("\n完整响应（截断 2000 字符）：")
    print(json.dumps(result, ensure_ascii=False)[:2000])
    return 0


async def _gw2cmd(client, args) -> int:
    """Does the GW2 control pipe actually validate what we send it?

    It answers ``1000 操作成功`` for everything so far while the car does
    nothing.  Sending a deliberately bogus ``serviceId`` tells us whether that
    is the gateway accepting anything, or our parameters being wrong — if a
    nonsense id is rejected, the real one can be found by comparison.
    """
    vin = client._first_known_vin()
    await client.async_get_vehicle_list()
    vin = vin or client._first_known_vin()
    if not vin:
        print("没有 VIN")
        return 1
    path = f"/remote-control/vehicle/telematics/{vin}"
    probes = (
        ("bogus（故意无效）", "NO_SUCH_SERVICE",
         [{"key": "AC", "value": "true"}]),
        ("ZAF+空参数", "ZAF", []),
        ("ZAF+AC=true", "ZAF", [{"key": "AC", "value": "true"}]),
        ("ZAF+AC=true+temp", "ZAF", [{"key": "AC", "value": "true"},
                                     {"key": "AC.temp", "value": "22.0"}]),
        ("ZAF+AC=1", "ZAF", [{"key": "AC", "value": "1"}]),
        ("RCE_2+rce", "RCE_2",
         [{"key": "rce.conditioner", "value": "start"}]),
    )
    for label, service_id, params in probes:
        body = {
            "command": "start", "serviceId": service_id,
            "serviceParameters": params, "creator": "tc",
            "userId": client._user_id,
            "timestamp": str(int(time.time() * 1000)),
        }
        for method in ("PUT", "POST"):
            try:
                result = await client._gw2(method, path, payload=body)
            except Exception as exc:  # noqa: BLE001
                print(f"  {label:16s} {method:4s} → {type(exc).__name__}: "
                      f"{str(exc)[:70]}")
                continue
            info = brief(result)
            print(f"  {label:16s} {method:4s} → {info.get('code')} "
                  f"{info.get('msg') or ''} | {info.get('top_keys')}")
    return 0


def cmd_gw2cmd(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    return asyncio.run(_gw2cmd(client, args))


def cmd_sms_request(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    result = asyncio.run(client.async_send_sms(args.phone))
    show("发送验证码", brief(result))
    return 0


def cmd_sms_verify(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    try:
        result = asyncio.run(client.async_full_login(args.phone, args.code))
    except Exception as exc:  # noqa: BLE001
        print(f"!! 登录失败: {type(exc).__name__}: {exc}")
        show("网关状态", client.gateway_summary())
        return 1
    show("登录结果", result)
    show("网关状态", client.gateway_summary())
    if args.save:
        tokens = client.get_token_storage()
        pathlib.Path(args.save).write_text(
            json.dumps(tokens, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        print(f"\n令牌已写出（请勿提交）: {args.save}")
    return 0


def cmd_save(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    pathlib.Path(args.path).write_text(
        json.dumps(client.get_token_storage(), ensure_ascii=False, indent=1),
        encoding="utf-8",
    )
    print(f"已写出 {args.path}")
    return 0


# ---------------------------------------------------------------------------
# The hunt: one login, then every hypothesis at once
# ---------------------------------------------------------------------------


async def _try_login(client, label: str, payload: dict[str, Any],
                     headers: dict[str, str] | None = None):
    """One login attempt; returns (label, brief, token-or-None)."""
    try:
        result = await client._gw3(
            "POST", "/ms-user-auth/v1.0/auth/login",
            payload=payload, vin=client._first_known_vin(),
            vin_encrypted=True, retry=False, headers_extra=headers,
        )
    except Exception as exc:  # noqa: BLE001
        return label, {"error": f"{type(exc).__name__}: {exc}"[:150]}, None
    info = brief(result)
    token = None
    if str(result.get("code")) == "000000":
        data = result.get("data") or {}
        if isinstance(data, dict):
            for key in ("accessToken", "access_token", "tokenValue"):
                if data.get(key):
                    token = str(data[key])
                    break
    return label, info, token


async def _opens_vehicle_interface(client, vin: str, token: str | None) -> dict:
    """The only verdict that matters: does a vehicle interface answer?"""
    if not token:
        return {"probe": "skipped (no token)"}
    try:
        result = await client._gw3(
            "GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
            params={"latest": "", "target": "new"},
            token=token, vin=vin, retry=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"probe": f"{type(exc).__name__}: {exc}"[:150]}
    info = brief(result)
    data = result.get("data")
    info["payload"] = (
        f"{len(data)} keys" if isinstance(data, dict) else type(data).__name__
    )
    return info


async def _hunt(client, args: argparse.Namespace) -> int:
    print("########## 0. 会话健康 ##########")
    gw1 = await client._gw1(
        "GET", "/zeekrlife-mp-auth2/v1/auth/accessCodeList", params={"envType": 3}
    )
    print(f"  GW1 accessCodeList → {json.dumps(brief(gw1), ensure_ascii=False)}")
    if str(gw1.get("code")) != "000000":
        print("\n!! JWT 已失效，请先 sms-request / sms-verify 重新登录")
        return 1

    print("\n########## 1. 车辆列表（GW2）##########")
    try:
        vehicles = await client.async_get_vehicle_list()
    except Exception as exc:  # noqa: BLE001
        print(f"  失败: {type(exc).__name__}: {exc}")
        vehicles = []
    print(f"  来源 = {client._vehicle_list_source}，共 {len(vehicles)} 辆")
    for vehicle in vehicles:
        print(f"   {vehicle.vin}  keys={sorted(vehicle.raw or {})[:8]}")
    if not vehicles:
        print("  （没有车辆，后续探测仍会试，但没有 VIN）")
    vin = vehicles[0].vin if vehicles else None

    print("\n########## 2. GW3 登录身份矩阵 ##########")
    jwt = client._jwt_token or ""
    candidates = [
        ("legacy id5+jwt（现状）",
         {"loginDeviceType": 1, "identityType": 5, "loginSystem": "Android",
          "loginDeviceId": client._login_device_id, "token": jwt,
          "loginPhoneBrand": "Android"}),
        ("id10+identifier=jwt",
         {"identityType": 10, "identifier": jwt, "loginDeviceType": 1,
          "loginDeviceId": client._login_device_id, "loginSystem": "Android",
          "loginPhoneBrand": "Android", "token": ""}),
        ("id10+identifier=gw2-token",
         {"identityType": 10, "identifier": client._access_token or "",
          "loginDeviceType": 1, "loginDeviceId": client._login_device_id,
          "loginSystem": "Android", "loginPhoneBrand": "Android", "token": ""}),
        ("id10+identifier=userId",
         {"identityType": 10, "identifier": client._user_id or "",
          "loginDeviceType": 1, "loginDeviceId": client._login_device_id,
          "loginSystem": "Android", "loginPhoneBrand": "Android", "token": ""}),
        ("id10+identifier=clientId",
         {"identityType": 10, "identifier": client._client_id or "",
          "loginDeviceType": 1, "loginDeviceId": client._login_device_id,
          "loginSystem": "Android", "loginPhoneBrand": "Android", "token": ""}),
        ("id5+token=gw2-token",
         {"loginDeviceType": 1, "identityType": 5, "loginSystem": "Android",
          "loginDeviceId": client._login_device_id,
          "token": client._access_token or "", "loginPhoneBrand": "Android"}),
        ("id8+identifier=jwt",
         {"identityType": 8, "identifier": jwt, "loginDeviceType": 1,
          "loginDeviceId": client._login_device_id, "loginSystem": "Android",
          "loginPhoneBrand": "Android", "token": ""}),
    ]

    results = []
    winner = None
    if getattr(args, "skip_identity", False):
        print("  （--skip-identity：跳过；每个变体登录一次都会顶掉会话）")
    for label, payload in ([] if getattr(args, "skip_identity", False)
                           else candidates):
        verdict = {"-": None}
        if token:
            verdict = await _opens_vehicle_interface(client, vin, token)
        results.append({
            "variant": name,
            "login_code": info.get("code"),
            "login_msg": info.get("msg") or info.get("error"),
            "data_keys": info.get("data_keys"),
            "token": "有" if token else "无",
            "status_probe": verdict,
        })
        print(f"  {name:26s} → {info.get('code')} {info.get('msg') or ''}"
              f" | token={'有' if token else '无'} | 状态接口={verdict.get('code')}")
        if str(verdict.get("code")) == "000000":
            winner = (name, token)
            break
    show("身份矩阵明细", results, limit=12000)

    print("\n########## 3. tspCode 候选路由 ##########")
    client_ids = [cid for cid in (client._client_id, *api_sms._TSP_CLIENT_IDS) if cid]
    rows = []
    for host_name, path in api_sms._TSP_CODE_CANDIDATES:
        for client_id in client_ids:
            try:
                result = await client._gw1(
                    "GET", path, params={"tspClientId": client_id}, host=host_name
                )
            except Exception as exc:  # noqa: BLE001
                rows.append({"host": host_name, "path": path,
                             "client_id": redact(client_id),
                             "error": f"{type(exc).__name__}: {exc}"[:100]})
                continue
            info = brief(result)
            info.update({"host": host_name, "path": path,
                         "client_id": redact(client_id)})
            if isinstance(result.get("data"), dict):
                info["code_field"] = result["data"].get("code")
            rows.append(info)
    show("tspCode 应答", rows, limit=14000)

    probe_token = (winner[1] if winner else client._new_access_token) \
        or client._access_token

    print("\n########## 4. 车辆列表 v3.0 vs v4.0（找每车令牌）##########")
    # Every snc_login invalidates the token minted before it, so the identity
    # matrix has just displaced the session we are about to measure with.
    # Re-mint one, otherwise this section only reports "logged in elsewhere".
    await client.snc_login()
    probe_token = client._new_access_token or probe_token
    print(f"  （已重新登录，令牌={redact(probe_token)}）")
    for label, path in (
        ("v3.0", "/ms-app-bff/api/v3.0/veh/vehicle-list"),
        ("v4.0", "/ms-app-bff/api/v4.0/veh/vehicle-list"),
    ):
        for mode in (None, "aes"):
            try:
                result = await client._gw3(
                    "GET", path, params={"needSharedCar": "true"},
                    token=probe_token, vin=vin if mode else None,
                    vin_encrypted=(mode == "aes"), retry=False,
                )
            except Exception as exc:  # noqa: BLE001
                print(f"  {label} x_vin={mode}: {type(exc).__name__}: {exc}")
                continue
            data = result.get("data")
            entries = data if isinstance(data, list) else (
                data.get("list") if isinstance(data, dict) else None
            )
            print(f"  {label} x_vin={mode} → {result.get('code')} "
                  f"{result.get('msg') or ''} | 条目数={len(entries) if entries else 0}")
            if entries:
                first = entries[0]
                print(f"      条目键: {sorted(first)}")
                entry = first.get("entry") or {}
                print(f"      entry 键: {sorted(entry)}")
                print(f"      全文: {json.dumps(first, ensure_ascii=False)[:900]}")

    print("\n########## 5. 同一令牌下 X-VIN 是不是唯一变量 ##########")
    await client.snc_login()
    probe_token = client._new_access_token or probe_token
    print(f"  （已重新登录，令牌={redact(probe_token)}）")
    matrix = []
    for end_name, path, params in (
        ("vehicle-list", "/ms-app-bff/api/v3.0/veh/vehicle-list",
         {"needSharedCar": "true"}),
        ("vehicle-status", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
         {"latest": "", "target": "new"}),
        ("getVehicleState", "/ms-app-bff/api/v1.0/remoteControl/getVehicleState",
         None),
    ):
        for mode, vin_arg, enc in (
            ("无 X-VIN", None, None),
            ("aes(vin)", vin, True),
            ("明文 vin", vin, False),
        ):
            if vin is None and vin_arg is not None:
                continue
            try:
                result = await client._gw3(
                    "GET", path, params=params, token=probe_token,
                    vin=vin_arg, vin_encrypted=enc, retry=False,
                )
            except Exception as exc:  # noqa: BLE001
                matrix.append({"endpoint": end_name, "x_vin": mode,
                               "error": f"{type(exc).__name__}: {exc}"[:90]})
                continue
            info = brief(result)
            info.update({"endpoint": end_name, "x_vin": mode})
            matrix.append(info)
            print(f"  {end_name:16s} {mode:8s} → {result.get('code')} "
                  f"{result.get('msg') or ''}")
    show("X-VIN 矩阵明细", matrix, limit=10000)

    print("\n########## 结论 ##########")
    if winner:
        print(f"  ✅ 打通车辆接口的登录身份：{winner[0]}")
    else:
        print("  ❌ 身份矩阵全未打通车辆接口 —— 需要换方向（见 tspCode 应答）")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    return asyncio.run(_hunt(client, args))


def decode_jwt(token: str | None) -> dict[str, Any]:
    """Read the claims of a bearer token — no verification, no secrets needed.

    The ``scope`` and ``aud`` claims are exactly what distinguishes a token the
    vehicle interfaces will accept from one that only opens the vehicle list.
    """
    if not token:
        return {}
    raw = token[7:] if token.lower().startswith("bearer ") else token
    parts = raw.split(".")
    if len(parts) < 2:
        return {"_raw": f"<not a JWT: {len(raw)} chars>"}
    try:
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(payload)
    except Exception as exc:  # noqa: BLE001
        return {"_error": str(exc)[:80]}
    keep = ("sub", "userId", "aud", "azp", "scope", "typ", "iss", "acr",
            "sid", "exp", "iat", "clientId", "client_id", "realm")
    return {k: v for k, v in claims.items() if k in keep}


async def _lab(client, args) -> int:
    """Which login yields a token the vehicle interfaces accept?

    The JWT handed back by ``ms-user-auth`` came back with ``scope: ""`` and
    ``aud: user_center_client_phone``, and every authorised interface answers
    ``079001`` for it while the vehicle list works.  So the question is no longer
    "which endpoint" but "which login mints a scoped token" — GW1 offers two
    access codes, and OAuth-style logins usually take a ``scope``.
    """
    print("########## Lab：哪条登录能拿到带 scope 的令牌 ##########")

    access = await client.get_access_code()
    codes = {k: v for k, v in (access.get("data") or {}).items() if v}
    print(f"  GW1 提供的 accessCode: {sorted(codes)}")

    status_path = "/ms-vehicle-status/api/v1.0/vehicle/status/latest"
    status_params = {"latest": "", "target": "new"}

    for label, extra_payload in (
        ("现状（无 scope）", {}),
        ("scope=all", {"scope": "all"}),
        ("scope=vehicle", {"scope": "vehicle"}),
        ("scope=tsp", {"scope": "tsp"}),
        ("scope=openid", {"scope": "openid"}),
    ):
        body = {
            "credential": "", "identifier": "", "identityType": 5,
            "loginDeviceId": client._login_device_id, "loginDeviceJgId": "",
            "loginDeviceType": 1, "loginPhoneBrand": "Android",
            "loginPhoneModel": "Android SDK built for arm64",
            "loginSystem": "Android",
            "token": client._bearer(client._jwt_token),
        }
        body.update(extra_payload)
        try:
            result = await client._gw3("POST", "/ms-user-auth/v1.0/auth/login",
                                       payload=body, retry=False,
                                       vin=client._first_known_vin(),
                                       vin_encrypted=True)
        except Exception as exc:  # noqa: BLE001
            print(f"  {label:18s} 登录异常: {type(exc).__name__}: {exc}"[:110])
            continue
        token = ((result.get("data") or {}).get("accessToken")
                 if isinstance(result, dict) else None)
        code = result.get("code")
        if not token:
            print(f"  {label:18s} 登录 {code} {result.get('msg') or ''} → 无令牌")
            continue
        claims = decode_jwt(token)
        try:
            probe = await client._gw3("GET", status_path, params=status_params,
                                      token=token, vin=None, retry=False)
            verdict = f"{probe.get('code')} {probe.get('msg') or ''}"
        except Exception as exc:  # noqa: BLE001
            verdict = f"{type(exc).__name__}: {exc}"[:60]
        print(f"  {label:18s} 登录={code} | scope={claims.get('scope')!r} "
              f"aud={claims.get('aud')} | 状态接口={verdict}")

    print("\n########## Lab：换个 accessCode 重走整条链 ##########")
    for name in sorted(codes):
        if name == "YIKAT_NEW":
            continue
        try:
            await client.ecar_login(codes[name])
        except Exception as exc:  # noqa: BLE001
            print(f"  {name}: ecar_login 失败 {type(exc).__name__}: {exc}"[:110])
            continue
        got = decode_jwt(client._access_token)
        await client.snc_login()
        claims = decode_jwt(client._new_access_token)
        try:
            probe = await client._gw3("GET", status_path, params=status_params,
                                      token=client._new_access_token, vin=None,
                                      retry=False)
            verdict = f"{probe.get('code')} {probe.get('msg') or ''}"
        except Exception as exc:  # noqa: BLE001
            verdict = f"{type(exc).__name__}: {exc}"[:60]
        print(f"  {name}: GW2 令牌={redact(client._access_token)} | "
              f"GW3 scope={claims.get('scope')!r} aud={claims.get('aud')} "
              f"| 状态接口={verdict}")
    return 0


# Where could a TSP-scoped token come from?  The one we hold answers
# ``aud: user_center_client_phone`` with an empty ``scope``, which explains the
# vehicle list working while the TSP interfaces refuse it.  These are the
# plausible exchange routes on both gateways, plus a few read-only probes.
_SCAN_GW3 = (
    "/ms-user-auth/v1.0/auth/login",
    "/ms-user-auth/v1.0/user/tspCode",
    "/ms-user-auth/v1.0/tspCode",
    "/ms-user-auth/v1.0/oauth/token",
    "/ms-user-auth/v1.0/oauth/info",
    "/ms-user-auth/v1.0/auth/tspCode",
    "/ms-user-auth/v1.0/user/auth/tspCode",
    "/ms-app-bff/api/v3.0/veh/vehicle-list",
    "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
)
_SCAN_GW2 = (
    "/auth/account/session/secure",
    "/auth/account/info",
    "/auth/account/tsp/token",
    "/auth/account/tspCode",
    "/user/tspCode",
    "/remote-control/vehicle/status/{vin}",
    "/remote-control/vehicle/telematics/{vin}",
    "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
)


async def _scan(client, args) -> int:
    # A stored token is usually stale: some earlier login will have displaced
    # it, and without the vehicle list there is no VIN to substitute.
    await client.async_get_vehicle_list()
    await client.snc_login()
    vin = client._first_known_vin() or ""
    print("########## 端点扫描：找一个能换出 TSP 令牌的路由 ##########")
    print(f"  VIN={vin} GW3 令牌={redact(client._new_access_token)}")

    for label, runner, paths, params in (
        ("GW3", client._gw3, _SCAN_GW3, {"latest": "", "target": "new"}),
        ("GW2", client._gw2, _SCAN_GW2, None),
    ):
        print(f"\n--- {label} ---")
        for path in paths:
            target = path.replace("{vin}", vin)
            if "{vin}" in path and not vin:
                continue
            try:
                if label == "GW3":
                    result = await runner("GET", target, params=params,
                                          token=client._new_access_token,
                                          vin=vin, retry=False)
                else:
                    result = await runner("GET", target, params=params)
            except Exception as exc:  # noqa: BLE001
                print(f"  {target:62s} {type(exc).__name__}: {str(exc)[:60]}")
                continue
            info = brief(result)
            print(f"  {target:62s} {info.get('code')} "
                  f"{info.get('msg') or ''} | {info.get('top_keys')}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    return asyncio.run(_scan(client, args))


def cmd_lab(args: argparse.Namespace) -> int:
    client, _ = build_client(args)
    return asyncio.run(_lab(client, args))


COMMANDS = {
    "lab": (cmd_lab, "令牌实验：哪条登录能拿到带 scope 的令牌"),
    "scan": (cmd_scan, "扫描可能换出 TSP 令牌的路由"),
    "gw2cmd": (cmd_gw2cmd, "GW2 控制通道是否真的校验 serviceId"),
    "summary": (cmd_summary, "查看本地持有的凭据（不发请求）"),
    "bootstrap": (cmd_bootstrap, "恢复会话 + 车辆列表 + 取 GW3 令牌"),
    "status": (cmd_status, "拉取并解析车辆状态"),
    "probe": (cmd_probe, "端点 / X-VIN 完整探测矩阵"),
    "routes": (cmd_routes, "逐个询问 tspCode 候选路由"),
    "hunt": (cmd_hunt, "一次登录后跑完整实验矩阵"),
    "raw": (cmd_raw, "任意 GW3 调用"),
    "gw1": (cmd_gw1, "任意 GW1 调用"),
    "sms-request": (cmd_sms_request, "发送短信验证码"),
    "sms-verify": (cmd_sms_verify, "用验证码完成登录"),
    "save": (cmd_save, "导出当前令牌"),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="极氪集成 —— 命令行实时探测工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--creds", help="配置项 data 的 JSON（含令牌）")
    parser.add_argument("--proxy", help="显式代理；默认直连")
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="打印集成内部的 debug 日志")
    parser.add_argument("--trace", action="store_true",
                        help="打印每一次请求与应答的原始内容")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("summary")
    sub.add_parser("bootstrap")
    sub.add_parser("lab", help="哪条登录能拿到带 scope 的令牌")
    sub.add_parser("scan", help="扫描两个网关上可能换出 TSP 令牌的路由")
    sub.add_parser("gw2cmd", help="探测 GW2 控制通道是否真的校验 serviceId")

    p_status = sub.add_parser("status")
    p_status.add_argument("vin", nargs="?")

    sub.add_parser("probe")

    p_routes = sub.add_parser("routes")
    p_routes.add_argument("path", nargs="*", help="额外要试的路径")
    p_routes.add_argument("--host")

    p_hunt = sub.add_parser("hunt")
    p_hunt.add_argument("--skip-identity", action="store_true",
                        help="跳过登录身份矩阵（它会反复顶掉会话）")

    for name in ("raw", "gw1"):
        p = sub.add_parser(name)
        p.add_argument("method")
        p.add_argument("target")
        p.add_argument("--query", action="append")
        p.add_argument("--host")
        p.add_argument("--vin")
        p.add_argument("--no-token", action="store_true")

    p_req = sub.add_parser("sms-request")
    p_req.add_argument("phone")

    p_ver = sub.add_parser("sms-verify")
    p_ver.add_argument("phone")
    p_ver.add_argument("code")
    p_ver.add_argument("--save")

    p_save = sub.add_parser("save")
    p_save.add_argument("path")

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    handler, _ = COMMANDS[args.command]
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
