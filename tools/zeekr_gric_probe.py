#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用「真机内存里取到的 GRIC 令牌 + 候选密钥/签名装配」直接打 GRIC 只读接口，
以服务端返回码做 oracle 判定签名是否被接受。

oracle 语义（来自 docs/zeekr_research_2026-09-18.md）：
  `00A06` = 该 app-id 已注册但**验签失败**（我们的签名不对）
  其它码 / code":"0" = **签名通过**（应用层继续走）
  `00A22` = app 未注册（不验签）—— 只能说明 app-id 不存在
只读：只发 GET，不触碰任何写/控车接口。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.request
import uuid
from urllib.parse import urlparse, parse_qs

TMP = os.environ.get("TEMP", ".")
TOKENS = json.load(open(os.path.join(TMP, "zeekr_gric_tokens.json"), encoding="utf-8"))
TOKEN = TOKENS["gric_access"]

HOST = "gric-zhf-api.geely.com"
PATHQ = "/ms-app-bff/api/1.0/permissions?tspPlatform=4"
METHOD = "GET"

# 我们自己设备的 deviceId（取自 GRIC 令牌的 deviceId 声明）
DEVICE_ID = "93460179-528e-432c-89dd-0284740737a4"
VIN_IDENT = "l1oQt6DQLAWGk8VKjbFBdxXaNr6FhF1h6obO8pgzLw4="

S1 = "c6163310f263911af87194dd290247fd"
S2 = ("QrMgt8GGYI6T52ZY5AnhtxkLzb8egpFn3j5JELI8H6wtACbUnZ5cc3aYTsTRbmkAkRJeYbtx92LPBWm"
      "7nBO9UIl7y5i5MQNmUZNf5QENurR5tGyo7yJ2G0MBjWvy6iAtlAbacKP0SwOUeUWx5dsBdyhxa7Id1AP"
      "tybSdDgicBDuNjI0mlZFUzZSS9dmN8lBD0WTVOMz0pRZbR3cysomRXOO1ghqjJdTcyDIxzpNAEszN8RMG"
      "jrzyU7Hjbmwi6YNK")

KEYS: list[tuple[str, bytes]] = [
    ("S1_ascii", S1.encode()),
    ("S1_raw16", bytes.fromhex(S1)),
    ("S2_ascii", S2.encode()),
    ("mmkv128", b"vU/tGrG6q0tAimsJFbgC6y7lk8L09La+Ghcn5oYdHv4DF3pnC1h4Is1e9tZ2yecMO6CBq/amRPn8g7/ds13uMsqCB2fimj0tNhd4gp1ObmV3CV6oLAL7DvKyZR7ddAol"),
]
try:
    for k, v in json.load(open(r"C:\Users\rexze\Documents\OPPO 互联\zeekr_secrets.json", encoding="utf-8")).items():
        if isinstance(v, str):
            KEYS.append(("secrets:" + k, v.encode()))
except Exception as e:
    print("# secrets.json:", e)

ESSENTIAL = ["x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
             "x-api-signature-version", "authorization", "accept-language"]
EXTRA = ["x-tenant-id", "x-sales-platform", "x-device-brand", "x-device-model",
         "x-device-os-version", "x-app-version", "x-device-id", "x-platform",
         "x-vehicle-identifier", "x-vehicle-brand", "x-vehicle-series", "x-tsp-platform"]

ALLOWLISTS = {
    "snc": ["x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
            "x-api-signature-version", "x-project-id", "authorization",
            "accept-language", "x-vin", "x-device-id", "x-platform"],
    "gric_all": ESSENTIAL + EXTRA,
    "gric_noauth": [h for h in ESSENTIAL + EXTRA if h != "authorization"],
    "gric_min": ["x-app-id", "x-api-signature-nonce", "x-timestamp",
                 "x-api-signature-version", "authorization", "content-type",
                 "accept", "accept-language", "x-device-id", "x-platform"],
    "gric_min2": ["x-app-id", "x-api-signature-nonce", "x-timestamp",
                  "x-api-signature-version", "x-device-id", "accept-language", "content-type"],
}


def fresh_headers(allow):
    h = {
        "x-tenant-id": "ZEEKR",
        "x-platform": "Android",
        "x-sales-platform": "ZEEKR",
        "x-device-brand": "google",
        "x-device-model": "Pixel 5",
        "x-device-os-version": "Android 14 (API 34)",
        "x-app-version": "v1.0.0",
        "x-app-id": "GEELYCNCH001M0001",
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json; charset=UTF-8",
        "accept-language": "zh_CN",
        "authorization": TOKEN,
        "x-api-signature-version": "2.1",
        "x-api-signature-nonce": str(uuid.uuid4()),
        "x-timestamp": str(time.time_ns() // 1000000),
        "x-device-id": DEVICE_ID,
        "x-vehicle-identifier": VIN_IDENT,
        "x-vehicle-brand": "ZEEKR",
        "x-vehicle-series": "QlgxRQ==",
        "x-tsp-platform": "4",
        "accept-encoding": "gzip",
        "user-agent": "okhttp/4.12.0",
    }
    return h


def build_base(headers, allow, sep, method, pathq):
    hl = {k.lower(): v for k, v in headers.items()}
    chosen = sorted((k, hl[k]) for k in hl if k in allow)
    hs = "".join(f"{k}{sep}{v}\n" for k, v in chosen)
    out = [hs]
    u = urlparse(pathq)
    if u.query:
        params = parse_qs(u.query, keep_blank_values=True)
        segs = []
        for k in sorted(params):
            v = params[k][0] if params[k] else ""
            segs.append(("&" if segs else "") + f"{k}={v}")
        out.append("".join(segs))
        out.append("\n")
    out.append(method.upper())
    out.append("\n")
    out.append(u.path.rstrip())
    return "".join(out)


def send(headers, sig):
    h = dict(headers)
    h["x-signature"] = sig
    req = urllib.request.Request(f"https://{HOST}{PATHQ}", method=METHOD)
    for k, v in h.items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return r.status, r.read()[:400].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:400].decode("utf-8", "replace")
    except Exception as e:
        return None, f"EXC {e!r}"


def main():
    print(f"# token aud=azp=auth_client_zeekr_phone, endpoint {METHOD} {HOST}{PATHQ}")

    # 0) 对照：故意用错误签名（应为 00A06）
    allow = ALLOWLISTS["gric_all"]
    h = fresh_headers(allow)
    st, body = send(h, base64.b64encode(b"\x00" * 32).decode())
    print(f"[CONTROL wrong-sig  allow=gric_all] status={st} body={body[:160]}")

    # 1) 矩阵：key x allowlist
    tried = 0
    for kname, kb in KEYS:
        for aname, allow in ALLOWLISTS.items():
            h = fresh_headers(allow)
            base = build_base(h, allow, ":", METHOD, PATHQ)
            sig = base64.b64encode(hmac.new(kb, base.encode(), hashlib.sha256).digest()).decode()
            st, body = send(h, sig)
            tried += 1
            mark = "  "
            if "00A06" not in body:
                mark = "**"
            print(f"[{mark}] key={kname:32s} allow={aname:12s} status={st} {body[:150]}")
    print(f"# tried {tried}")


if __name__ == "__main__":
    main()
