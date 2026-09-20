#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GRIC 签名端到端验证（只读；心跳 + 车辆状态）。

签名基串（2026-09-21 确认）——与 nikagl/zeekr_ev_api 的
`src/zeekr_ev_api/zeekr_app_sig.calculate_sig` 完全一致，并经真机内存逐字节复核：

    基串 = 白名单头 "name:value\\n"（按 name 升序拼接）
         + [查询串 + "\\n"]          # "k=v" 按 key 升序、以 "&" 连接；不带前导 "?"；仅当有查询
         + [base64(md5(body)) + "\\n"]   # 仅当有 body（GET 无 body ⇒ 无此行）
         + METHOD + "\\n"
         + PATH                      # 纯路径，不含查询串

    签名 = base64(HMAC-SHA256(key, 基串))
    密钥 = e70024ed24bda3cbd4a6295ed3fac5aa   （app 私有目录 mmkv/ble_sdk 的 dkAppSecret）

签名白名单（GRIC 实测 18 个；注意不含 accept / content-type / host / user-agent）：
  accept-language, authorization, x-api-signature-nonce, x-api-signature-version,
  x-app-id, x-app-version, x-device-brand, x-device-id, x-device-model,
  x-device-os-version, x-platform, x-sales-platform, x-tenant-id, x-timestamp,
  x-tsp-platform, x-vehicle-brand, x-vehicle-identifier, x-vehicle-series

oracle：`00A06` = 验签失败；其余（尤其 code:"0" / HTTP 200 + 业务数据）= 验签通过。
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from urllib.parse import parse_qs

TOKENS = json.load(open(os.path.join(os.environ.get("TEMP", "."), "zeekr_gric_tokens.json"), encoding="utf-8"))
TOKEN = TOKENS["gric_access"]

HOST = "gric-zhf-api.geely.com"
KEY = b"e70024ed24bda3cbd4a6295ed3fac5aa"
DEVICE_ID = "93460179-528e-432c-89dd-0284740737a4"
VIN_IDENT = "l1oQt6DQLAWGk8VKjbFBdxXaNr6FhF1h6obO8pgzLw4="
VIN = "L6T77HCE9PF081833"

SIGNED = [
    "accept-language", "authorization", "x-api-signature-nonce",
    "x-api-signature-version", "x-app-id", "x-app-version", "x-device-brand",
    "x-device-id", "x-device-model", "x-device-os-version", "x-platform",
    "x-sales-platform", "x-tenant-id", "x-timestamp", "x-tsp-platform",
    "x-vehicle-brand", "x-vehicle-identifier", "x-vehicle-series",
]


def headers(nonce: str, ts: str) -> dict[str, str]:
    return {
        # —— 参与签名 ——
        "accept-language": "zh_CN",
        "authorization": TOKEN,
        "x-api-signature-nonce": nonce,
        "x-api-signature-version": "2.1",
        "x-app-id": "GEELYCNCH001M0001",
        "x-app-version": "v1.0.0",
        "x-device-brand": "GOOGLE",
        "x-device-id": DEVICE_ID,
        "x-device-model": "Pixel5",
        "x-device-os-version": "Android 14 (API 34)",
        "x-platform": "Android",
        "x-sales-platform": "ZEEKR",
        "x-tenant-id": "ZEEKR",
        "x-timestamp": ts,
        "x-tsp-platform": "4",
        "x-vehicle-brand": "ZEEKR",
        "x-vehicle-identifier": VIN_IDENT,
        "x-vehicle-series": "QlgxRQ==",
        # —— 不参与签名，但 app 会带 ——
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json; charset=UTF-8",
        "accept-encoding": "identity",
        "user-agent": "okhttp/4.12.0",
    }


def canonical_query(query: str) -> str:
    """按 key 升序的 'k=v' 以 '&' 连接（与 app 一致）。"""
    if not query:
        return ""
    p = parse_qs(query, keep_blank_values=True)
    segs = []
    for k in sorted(p):
        v = p[k][0] if p[k] else ""
        v = v.replace("%2F", "/").replace("%3F", "?").replace("*", "%2A")
        segs.append(f"{k}={v}")
    return "&".join(segs)


def sign(key: bytes, method: str, path: str, hdr: dict[str, str],
         query: str = "", body: bytes = b"") -> tuple[str, str]:
    """返回 (base, signature)。顺序：headers + query + bodyhash + METHOD + path。"""
    parts = ["".join(f"{k}:{hdr[k]}\n" for k in sorted(SIGNED))]
    q = canonical_query(query)
    if q:
        parts.append(q + "\n")
    if body:
        parts.append(base64.b64encode(hashlib.md5(body).digest()).decode() + "\n")
    parts.append(f"{method.upper()}\n")
    parts.append(path)
    base = "".join(parts)
    sig = base64.b64encode(hmac.new(key, base.encode(), hashlib.sha256).digest()).decode()
    return base, sig


def send(method: str, path: str, query: str, hdr: dict[str, str], sig: str, body: bytes = b""):
    url = f"https://{HOST}{path}" + (f"?{query}" if query else "")
    req = urllib.request.Request(url, method=method, data=body or None)
    for k, v in hdr.items():
        req.add_header(k, v)
    req.add_header("x-signature", sig)
    try:
        with urllib.request.urlopen(req, timeout=25, context=ssl.create_default_context()) as r:
            raw = r.read()
            enc = (r.headers.get("Content-Encoding") or "").lower()
            st = r.status
    except urllib.error.HTTPError as e:
        raw, enc, st = e.read(), (e.headers.get("Content-Encoding") or "").lower(), e.code
    except Exception as e:  # noqa: BLE001
        return None, f"EXC {e!r}", None
    if "gzip" in enc:
        try:
            raw = gzip.decompress(raw)
        except Exception:  # noqa: BLE001
            pass
    return st, raw.decode("utf-8", "replace"), url


def run(tag: str, method: str, path: str, query: str = "", body: bytes = b"",
        key: bytes = KEY, show: int = 400, dump_json: bool = False):
    nonce, ts = str(uuid.uuid4()), str(time.time_ns() // 1_000_000)
    hdr = headers(nonce, ts)
    base, sig = sign(key, method, path, hdr, query, body)
    st, resp, url = send(method, path, query, hdr, sig, body)
    ok = resp is not None and "00A06" not in resp
    print(f"[{'OK ' if ok else 'BAD'}] {tag}")
    print(f"      {method} {url}")
    print(f"      base_tail={base[-150:]!r}")
    print(f"      sig={sig[:28]}… st={st}")
    if dump_json:
        try:
            obj = json.loads(resp)
            print("      keys:", list(obj)[:20])
            print("      data keys:", list(obj.get("data") or {})[:40] if isinstance(obj.get("data"), dict) else type(obj.get("data")).__name__)
            print("      json:", json.dumps(obj, ensure_ascii=False)[:show])
        except Exception:  # noqa: BLE001
            print(f"      resp={resp[:show]}")
    else:
        print(f"      resp={resp[:show]}")
    return ok, resp


def hb_body() -> bytes:
    return (f'{{"deviceType":1,"enableWakeUp":false,"hbType":1,"ts":{time.time_ns() // 1_000_000}}}').encode()


def main():
    print(f"# key={KEY.decode()}  host={HOST}  vin={VIN}")

    print("\n===== 1) 对照组：正确装配 + 错误密钥（应 00A06）=====")
    run("control wrong-key",
        "POST", "/ms-app-online-center/api/v2.0/app/hb", body=hb_body(), key=b"0" * 32)

    print("\n===== 2) 心跳 POST：与 app 完全同形（应 code:0）=====")
    run("hb heartbeat", "POST", "/ms-app-online-center/api/v2.0/app/hb", body=hb_body())

    print("\n===== 3) GET 带查询串：查询在 METHOD 之前（权威顺序）=====")
    run("permissions", "GET", "/ms-app-bff/api/1.0/permissions", query="tspPlatform=4")

    print("\n===== 4) 目标：车辆状态（只读）=====")
    run("vehicle-status",
        "GET", "/ms-vehicle-status/api/v2.0/vehicle/status/latest",
        query="latest=&target=new", dump_json=True)


if __name__ == "__main__":
    main()
