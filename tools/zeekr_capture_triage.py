"""Triage a captured App session: find the request that actually controls the car.

The `[SDK]` gate rejects our token but accepts the App's, so the App must carry a
different credential.  This tool reads a capture (HAR from Reqable/Charles/
mitmproxy, or a native mitmproxy ``.flow`` dump) and prints, for every request to
the Zeekr gateways, the **shape** of the call: which host, which path, which
auth-ish headers, and the token's unverified claims (``azp``/``aud``/``scope``).

Secrets are masked; only the JWT claims (already public to whoever holds the
token) and a short fingerprint are printed, which is what we need to compare
"the App's client identity" against ours.

Usage:
    python tools/zeekr_capture_triage.py capture.har
    python tools/zeekr_capture_triage.py capture.flow --filter control
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys

INTERESTING_HOSTS = (
    "snc-tsp-api.zeekrlife.com", "api-gw-toc.zeekrlife.com", "api.zeekrline.com",
    "gateway-pub.zeekrlife.com", "snc-api-gw", "zeekrlife.com",
)
AUTH_HEADERS = ("authorization", "x-app-id", "appid", "app_code", "app-type",
                "x-vin", "x-project-id", "x-tsp-platform", "x-region-id",
                "x-tenant-id", "sign", "signature", "x-signature", "nonce",
                "x-device-id", "user-agent", "x-app-version", "x-ota-version")


def mask(value: str, keep: int = 8) -> str:
    if len(value) <= keep * 2:
        return f"<{len(value)}B>"
    return f"{value[:keep]}…{value[-4:]}({len(value)}B)"


def jwt_claims(value: str) -> dict | None:
    raw = re.sub(r"^(Bearer|bearer)\s+", "", value.strip())
    if raw.count(".") != 2:
        return None
    try:
        payload = raw.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001 - not a JWT, that is the answer too
        return None


def describe(host: str, method: str, path: str, headers: dict, body: str) -> list[str]:
    lines = [f"  {'=' * 66}",
             f"  {method} {host}{path}"]
    for name in AUTH_HEADERS:
        for key, value in headers.items():
            if key.lower() == name:
                claims = jwt_claims(str(value)) if name == "authorization" else None
                if claims:
                    lines.append(f"    {key}: <JWT> azp={claims.get('aud')!r} "
                                 f"scope={claims.get('scope')!r} "
                                 f"iss={str(claims.get('iss'))[-38:]!r}")
                else:
                    lines.append(f"    {key}: {str(value)[:70]}")
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                shape = {k: type(v).__name__ for k, v in parsed.items()}
                lines.append(f"    body keys: {json.dumps(shape, ensure_ascii=False)}")
                for k, v in parsed.items():
                    if isinstance(v, (str, int, float)) and len(str(v)) < 60:
                        lines.append(f"      {k} = {v!r}")
            else:
                lines.append(f"    body: {str(parsed)[:160]}")
        except Exception:  # noqa: BLE001
            lines.append(f"    body(raw {len(body)}B): {body[:120]}")
    return lines


def from_har(path: pathlib.Path) -> list[tuple[str, str, str, dict, str]]:
    har = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    out = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")
        m = re.match(r"https?://([^/]+)(/.*)?$", url)
        if not m:
            continue
        host, path = m.group(1), m.group(2) or "/"
        headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
        body = (req.get("postData") or {}).get("text", "") or ""
        out.append((host, req.get("method", "?"), path, headers, body))
    return out


def from_flow(path: pathlib.Path) -> list[tuple[str, str, str, dict, str]]:
    try:
        from mitmproxy import io as mitm_io  # type: ignore
    except ImportError:
        raise SystemExit("读取 .flow 需要 mitmproxy："
                         "C:/Users/rexze/.workbuddy/binaries/python/envs/mitm/Scripts/python.exe")
    out = []
    with path.open("rb") as fh:
        for flow in mitm_io.FlowReader(fh).stream():
            req = getattr(flow, "request", None)
            if req is None:
                continue
            headers = dict(req.headers)
            body = ""
            try:
                body = req.get_text(strict=False) or ""
            except Exception:  # noqa: BLE001
                pass
            host = req.pretty_host
            out.append((host, req.method, req.path, headers, body))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=pathlib.Path)
    parser.add_argument("--filter", default="", help="只看路径含此子串的请求")
    parser.add_argument("--all-hosts", action="store_true")
    args = parser.parse_args(argv)

    reader = from_flow if args.capture.suffix == ".flow" else from_har
    entries = reader(args.capture)
    print(f"共 {len(entries)} 条请求（来自 {args.capture.name}）\n")

    shown = 0
    summary: dict[str, int] = {}
    for host, method, path, headers, body in entries:
        if not args.all_hosts and not any(h in host for h in INTERESTING_HOSTS):
            continue
        if args.filter and args.filter not in path:
            continue
        shown += 1
        for line in describe(host, method, path, headers, body):
            print(line)
        auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
        claims = jwt_claims(auth) if auth else None
        key = f"{claims.get('aud')!r}|scope={claims.get('scope')!r}" if claims else "无JWT"
        summary[key] = summary.get(key, 0) + 1

    print(f"\n{'=' * 68}\n命中 {shown} 条（极氪网关）")
    print("\n=== 令牌身份分布（这就是我们要的答案）===")
    for key, count in sorted(summary.items(), key=lambda kv: -kv[1]):
        print(f"  {count:4} 次  azp/aud | scope = {key}")
    if len(summary) > 1:
        print("\n⇒ 出现多种令牌身份：找到与 `user_center_client_phone` 不同的那一份，"
              "就是 SDK 令牌的来源线索。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
