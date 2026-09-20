#!/usr/bin/env python3
"""用候选密钥验证极氪 App 的 x-signature —— 同时确认「密钥正确」与「规范串算法正确」。

场景：frida/其他手段拿到一个疑似签名密钥后，拿它去重算抓包里某个真实请求的
x-signature。命中即说明密钥与算法**同时**确认，接入 HA 就变成纯工程工作。

用法：
    python tools/zeekr_sig_verify.py --key 03d1cd020062469e90ed63416c5c0fda
    python tools/zeekr_sig_verify.py --keys-file keys.txt --all
    python tools/zeekr_sig_verify.py --request my_request.json --key <值>

请求样本格式（与 capture/extracted.json 的单条元素一致）：
    {"method": "POST", "path": "/ms-remote-control/api/v1.0/remoteControl/control",
     "headers": {"x-app-id": "...", "x-signature": "...", ...}, "body": "..."}
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import pathlib
import sys
from urllib.parse import parse_qs, urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE = ROOT / "capture" / "extracted.json"

ALLOWED = ["x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
           "x-api-signature-version", "x-project-id", "authorization",
           "accept-language", "x-vin", "x-device-id", "x-platform"]
CN_EXTRA = ["x-tenant-id", "x-sales-platform", "x-tsp-platform", "x-vehicle-identifier",
            "x-vehicle-brand", "x-vehicle-series", "x-app-version", "x-device-brand",
            "x-device-model", "x-device-os-version"]


def build_canonical(req: dict, allowed: list[str], qm: str, tail: str, body_mode: str) -> bytes:
    """按 zeekr_app_sig 的语义构造规范串。"""
    hdrs = {k.lower(): v for k, v in req["headers"].items()}
    url = urlparse("https://x" + req["path"])
    body = req.get("body") or ""
    rows = sorted([(k, v) for k, v in hdrs.items()
                   if k in allowed and k != "x-signature"
                   and (v or k not in ("x-vin", "authorization"))], key=lambda kv: kv[0])
    out = "".join(f"{k}:{v}\n" for k, v in rows)
    if qm == "as_is":
        q = url.query
    elif qm == "sorted":
        q = "&".join(f"{k}={v[0] if v else ''}"
                     for k, v in sorted(parse_qs(url.query, keep_blank_values=True).items()))
    else:
        q = ""
    if q:
        out += q + "\n"
    if body:
        if body_mode == "md5canon":
            cj = json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
            out += base64.b64encode(hashlib.md5(cj.encode()).digest()).decode() + "\n"
        elif body_mode == "md5raw":
            out += base64.b64encode(hashlib.md5(body.encode()).digest()).decode() + "\n"
    out += (f"{req['method'].upper()}\n{url.path.rstrip()}" if tail == "path_only"
            else f"{req['method'].upper()}\n{req['path']}")
    return out.encode()


VARIANTS = [(qm, tail, bm)
            for qm in ("as_is", "sorted", "none")
            for tail in ("path_only", "path_query")
            for bm in ("md5canon", "md5raw")]


def load_samples(args) -> list[dict]:
    if args.request:
        req = json.loads(pathlib.Path(args.request).read_text(encoding="utf-8"))
        return [req if isinstance(req, dict) else req[0]]
    path = pathlib.Path(args.sample)
    if not path.exists():
        raise SystemExit(f"样本文件不存在: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    out, seen = [], set()
    for e in data:
        if not isinstance(e, dict) or "headers" not in e:
            continue
        if "x-signature" not in {k.lower() for k in e["headers"]}:
            continue
        if not e.get("path"):
            continue
        key = e["path"].split("?")[0]
        if key in seen and not args.all:
            continue
        seen.add(key)
        out.append(e)
    if not args.all:
        out = out[: args.limit]
    return out


def parse_key(spec: str) -> bytes:
    """支持三种写法：hex:<hex串> / b64:<base64串> / 其它按 utf-8 原样。"""
    spec = spec.strip()
    if spec.startswith("hex:"):
        return bytes.fromhex(spec[4:].replace(" ", ""))
    if spec.startswith("b64:"):
        body = spec[4:].strip()
        return base64.b64decode(body + "=" * (-len(body) % 4))
    return spec.encode()


def main() -> int:
    ap = argparse.ArgumentParser(description="验证候选密钥能复现 x-signature")
    ap.add_argument("--key", action="append", default=[], help="候选密钥（可重复，支持 hex:/b64: 前缀）")
    ap.add_argument("--keys-file", help="每行一个候选密钥的文件（同样支持 hex:/b64:）")
    ap.add_argument("--sample", default=str(DEFAULT_SAMPLE), help="请求样本 json")
    ap.add_argument("--request", help="单个请求 json（优先于 --sample）")
    ap.add_argument("--all", action="store_true", help="对样本里每个请求都试（默认每路径只取一条）")
    ap.add_argument("--limit", type=int, default=3, help="默认只试前 N 条请求")
    args = ap.parse_args()

    keys: list[bytes] = []
    for k in args.key:
        keys.append(parse_key(k))
    if args.keys_file:
        for line in pathlib.Path(args.keys_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                keys.append(parse_key(line))
    if not keys:
        raise SystemExit("请用 --key 或 --keys-file 提供至少一个候选密钥。")
    uniq, seen = [], set()
    for k in keys:
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    keys = uniq

    samples = load_samples(args)
    if not samples:
        raise SystemExit("样本里没有带 x-signature 的请求。")

    print(f"候选密钥 {len(keys)} 条；请求样本 {len(samples)} 条；变体 {len(VARIANTS)} 种")
    tried = 0
    for i, req in enumerate(samples, 1):
        hdrs = {k.lower(): v for k, v in req["headers"].items()}
        try:
            target = base64.b64decode(hdrs["x-signature"])
        except Exception as exc:
            print(f"[{i}] x-signature 无法 base64 解码: {exc}")
            continue
        hdr_keys = sorted({k.lower() for k in req["headers"]} - {"x-signature"})
        sets = {"ALLOWED": ALLOWED, "ALLOWED+CN": ALLOWED + CN_EXTRA,
                "x_only": hdr_keys, "CN_only": CN_EXTRA}
        print(f"\n[{i}] {req.get('method', 'POST')} {req['path']}")

        for sname, allowed in sets.items():
            for qm, tail, bm in VARIANTS:
                can = build_canonical(req, allowed, qm, tail, bm)
                for cand in keys:
                    tried += 1
                    if hmac.new(cand, can, hashlib.sha256).digest() == target:
                        print("\n*** 命中 ***")
                        print(f"  密钥        = {cand.decode()!r}")
                        print(f"  头集合      = {sname}（{len(allowed)} 个候选头）")
                        print(f"  query 模式  = {qm}")
                        print(f"  尾部        = {tail}")
                        print(f"  body 摘要   = {bm}")
                        print("  canonical 串:")
                        for line in can.decode().splitlines():
                            print(f"    | {line}")
                        return 0

        print(f"    未命中（已试 {len(keys)} 密钥 × {len(VARIANTS)} 变体 × {len(sets)} 头集合）")

    print(f"\n全部未命中（共 {tried} 次 HMAC 比对）。")
    print("说明：密钥不对，或请求头集合不在已枚举的空间里 —— 请把该请求的完整头列表发我重排变体。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
