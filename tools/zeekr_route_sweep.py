"""Sweep every known control-plane route and record what the gateways answer.

Read-only by construction: only ``GET`` is issued, so a write endpoint merely
answers "method not allowed" and nothing is actuated.  The result is a table of
``route -> code`` per gateway, which is the fastest way to see which interfaces
are open to a given token and which sit behind the ``[SDK]`` gate.

Routes come from ``scratch/route_inventory.py`` (dex string pool).  Pass a file
with one route per line, or the full inventory markdown with ``--from-md``.

Usage:
    python tools/zeekr_route_sweep.py --creds tokens.json --routes routes.txt \
        --out docs/zeekr_route_probe_results.md [--gateways gw1,gw3]
        [--extra-hosts gateway-pub.zeekrlife.com]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import re
import sys
import time
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import zeekr_probe as zp  # noqa: E402

VIN_DEFAULT = "L6T77HCE9PF081833"


def load_routes(path: pathlib.Path, from_md: bool) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if from_md:
        # Inside ``` fences only, so headings and prose are ignored.
        routes = []
        for block in re.findall(r"```\n(.*?)```", text, re.S):
            routes.extend(l.strip() for l in block.splitlines())
    else:
        routes = [l.strip() for l in text.splitlines()]
    out = []
    for r in routes:
        if not r.startswith("/") or "{" in r:
            continue
        if r not in out:
            out.append(r)
    return out


async def probe_one(client, gw: str, route: str, token: str | None, vin: str,
                    extra_hosts: list[str]) -> dict[str, str]:
    """Return ``{gateway: "code msg"}`` for one route."""
    result: dict[str, str] = {}

    async def call(name: str, coro) -> None:
        try:
            data = await coro
        except Exception as exc:  # noqa: BLE001 - report, never abort the sweep
            result[name] = f"ERR {type(exc).__name__}: {str(exc)[:60]}"
            return
        code = data.get("code") or data.get("error_code") or data.get("message")
        msg = data.get("msg") or data.get("error_msg") or ""
        result[name] = f"{code} {str(msg)[:70]}".strip()

    if gw == "gw1":
        await call("gw1", client._gw1("GET", route))
    elif gw == "gw3":
        await call("gw3", client._gw3("GET", route, token=token, vin=vin, retry=False))
    elif gw == "gw2":
        await call("gw2", client._gw2("GET", route))
    elif gw == "extra":
        for host in extra_hosts:
            await call(f"host:{host}", client._gw1("GET", route, host=host))
    return result


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds", required=True)
    parser.add_argument("--routes", required=True, type=pathlib.Path)
    parser.add_argument("--from-md", action="store_true")
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--gateways", default="gw1,gw3")
    parser.add_argument("--extra-hosts", default="")
    parser.add_argument("--vin", default=VIN_DEFAULT)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args(argv)

    routes = load_routes(args.routes, args.from_md)
    gateways = [g.strip() for g in args.gateways.split(",") if g.strip()]
    extra_hosts = [h.strip() for h in args.extra_hosts.split(",") if h.strip()]
    print(f"{len(routes)} routes x {gateways + (['extra'] if extra_hosts else [])}")

    client, _ = zp.build_client(types.SimpleNamespace(
        creds=args.creds, trace=False, proxy=None, timeout=30, host=None, vin=None))
    await client.snc_login()
    token = client._new_access_token
    print(f"gw3 token: {'yes' if token else 'NO'}")

    rows: dict[str, dict[str, str]] = {}
    sem = asyncio.Semaphore(max(1, args.concurrency))

    async def worker(route: str) -> None:
        async with sem:
            merged: dict[str, str] = {}
            for gw in gateways:
                merged.update(await probe_one(client, gw, route, token, args.vin, extra_hosts))
            if extra_hosts:
                merged.update(await probe_one(client, "extra", route, token, args.vin, extra_hosts))
            rows[route] = merged

    started = time.time()
    await asyncio.gather(*(worker(r) for r in routes))
    print(f"swept in {time.time() - started:.0f}s")

    # Group by service prefix for readability.
    grouped: dict[str, list[str]] = {}
    for route in routes:
        svc = route.split("/")[1]
        grouped.setdefault(svc, []).append(route)

    cols = list(gateways) + ([f"host:{h}" for h in extra_hosts] if extra_hosts else [])
    lines = [
        "# 控制平面路由实测结果",
        "",
        f"由 `tools/zeekr_route_sweep.py` 生成（**只发 GET，无写操作**）。",
        f"共 {len(routes)} 条路由 × {len(cols)} 个目标，耗时 {time.time() - started:.0f}s。",
        "",
        f"目标：{', '.join(cols)}　VIN: `{args.vin}`",
        "",
        "判读：`000000` 可用；`079001` SDK 门禁；`000010` 动词不符（可能是写接口）；",
        "`00A01/404` 该网关无此服务；`000002` 过鉴权、缺参数。",
        "",
    ]
    for svc in sorted(grouped):
        lines += [f"## {svc}", "", "| 路由 | " + " | ".join(cols) + " |",
                  "| --- | " + " | ".join("---" for _ in cols) + " |"]
        for route in sorted(grouped[svc]):
            cells = [rows[route].get(c, "—").replace("|", "/") for c in cols]
            lines.append(f"| `{route}` | " + " | ".join(cells) + " |")
        lines.append("")

    args.out.write_text("\n".join(lines), encoding="utf-8")
    ok = sum(1 for r in rows.values() if any(v.startswith("000000") for v in r.values()))
    print(f"{ok} routes answered 000000 on at least one gateway -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
