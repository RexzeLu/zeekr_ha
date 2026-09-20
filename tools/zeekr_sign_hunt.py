#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用抓包样本 + 候选密钥池，暴力还原 GRIC/SNC 的 X-SIGNATURE 2.1 共享密钥。

算法依据 zeekr_ev_api/zeekr_app_sig.py（规范化头 + 排序 + query + body-md5 + METHOD\\nPATH，
HMAC-SHA256 → base64）。头白名单存在多个候选变体，逐个尝试。只读。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from urllib.parse import urlparse, parse_qs

CAPTURE = r"D:\zeekr_ha\capture\extracted.json"
CANDS = r"D:\zeekr_ha\_cmp\cand.txt"

# 头白名单变体
OSS_LIST = [
    "x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
    "x-api-signature-version", "x-project-id", "authorization",
    "accept-language", "x-vin", "x-device-id", "x-platform",
]
EXTRA = [
    "x-tenant-id", "x-sales-platform", "x-device-brand", "x-device-model",
    "x-device-os-version", "x-app-version", "x-vehicle-identifier",
    "x-vehicle-brand", "x-vehicle-series", "x-tsp-platform",
]
ALLOWLISTS = {
    "oss": OSS_LIST,
    "oss+vin": OSS_LIST + ["x-vehicle-identifier"],
    "oss+extra": OSS_LIST + EXTRA,
    "extra_only": EXTRA + ["content-type", "authorization", "accept-language",
                           "x-api-signature-nonce", "x-timestamp",
                           "x-api-signature-version", "x-app-id"],
    "noauth": [h for h in OSS_LIST + EXTRA if h != "authorization"],
}
SKIP = {"host", "content-length", "accept-encoding", "user-agent", "accept",
        "connection", "x-signature"}


def query_string_of(url: str) -> str:
    u = urlparse(url)
    if not u.query:
        return ""
    params = parse_qs(u.query, keep_blank_values=True)
    parts = []
    for k in sorted(params):
        v = params[k][0] if params[k] else ""
        v = v.replace("%2F", "/").replace("%3F", "?").replace("*", "%2A")
        parts.append(f"{k}={v}")
    return "&".join(parts)


def body_hash_b64(headers: dict, body: str) -> str:
    if "application/json" not in headers.get("content-type", "").lower():
        return ""
    if not body:
        return ""
    try:
        obj = json.loads(body)
        canon = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    except Exception:
        canon = body
    return base64.b64encode(hashlib.md5(canon.encode()).digest()).decode()


def build_base(req: dict, allow: list[str], sep: str = ":") -> str:
    headers = {k.lower(): v for k, v in req["headers"].items()}
    chosen = sorted((k, headers[k]) for k in headers if k in allow)
    sb = []
    for k, v in chosen:
        sb.append(f"{k}{sep}{v}\n")
    header_string = "".join(sb)
    qs = query_string_of("https://x" + req["path"])
    bh = body_hash_b64(headers, req.get("body") or "")
    out = []
    if header_string:
        out.append(header_string)
    if qs:
        out.append(qs)
        out.append("\n")
    if bh:
        out.append(bh)
        out.append("\n")
    out.append(req["method"].upper())
    out.append("\n")
    out.append(urlparse("https://x" + req["path"]).path.rstrip())
    return "".join(out)


def load_keys() -> list[str]:
    keys = []
    seen = set()

    def add(s):
        if s and 4 <= len(s) <= 200 and s not in seen:
            seen.add(s)
            keys.append(s)

    try:
        with open(CANDS, encoding="utf-8", errors="ignore") as f:
            for ln in f:
                add(ln.rstrip("\n"))
    except FileNotFoundError:
        pass
    # 已知/历史候选
    extra = [
        "890efe3207af95348b95f66b2ee7da04", "03d1cd020062469e90ed63416c5c0fda",
        "e70024ed24bda3cbd4a6295ed3fac5aa",
        "hnpigl1f13fcb6a3ac834895b9e403c08cd895ce",
        "7dbae691d53f4f3c9fab905368370d80",
        "GEELYCNCH001M0001", "ZEEKRCNCH001M0001", "zeekr_tis",
        "2014052600006128", "aebd1811194e82d9",
        "vU/tGrG6q0tAimsJFbgC6y7lk8L09La+Ghcn5oYdHv4DF3pnC1h4Is1e9tZ2yecMO6CBq/amRPn8g7/ds13uMsqCB2fimj0tNhd4gp1ObmV3CV6oLAL7DvKyZR7ddAol",
        "c74c3abc6a35ad3698e7aae103a0274b04c41372606c01f3688385d0783affe7",
        "3JNFf4F3eWUDs3h6jDixQyoyvj1",
    ]
    try:
        sj = json.load(open(r"C:\Users\rexze\Documents\OPPO 互联\zeekr_secrets.json", encoding="utf-8"))
        for v in sj.values():
            if isinstance(v, str):
                add(v)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str):
                        add(x)
    except Exception:
        pass
    for e in extra:
        add(e)
    return keys


def main():
    reqs = json.load(open(CAPTURE, encoding="utf-8"))
    samples = [r for r in reqs if "x-signature" in {k.lower() for k in r.get("headers", {})}]
    print(f"# {len(samples)} signed requests in capture")
    keys = load_keys()
    print(f"# candidate keys: {len(keys)}")

    # 选一个样本做主要验证（优先无 body 的 GET，减少不确定因素）
    samples.sort(key=lambda r: (bool(r.get("body")), r["method"] != "GET"))
    head = samples[:6]

    found = []
    for req in head:
        sig = next(v for k, v in req["headers"].items() if k.lower() == "x-signature")
        for aname, allow in ALLOWLISTS.items():
            for sep_name, sep in (("colon", ":"), ("eq", "=")):
                base = build_base(req, allow, sep)
                b = base.encode()
                for k in keys:
                    try:
                        h = hmac.new(k.encode(), b, hashlib.sha256).digest()
                    except Exception:
                        continue
                    if base64.b64encode(h).decode() == sig:
                        msg = (f"*** MATCH  key={k!r}  allowlist={aname} sep={sep_name}  "
                               f"req={req['method']} {req['path']}")
                        print(msg)
                        found.append(msg)
    print(f"\n# matches: {len(found)}")


if __name__ == "__main__":
    main()
