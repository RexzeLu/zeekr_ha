"""One-shot checkpoint of the ``[SDK]`` interface gate.

Answers exactly one question: **which interfaces does this token open, and did
anything change since the last run?**  Every probe is read-only — GET, or POST
with an empty body so the service can only answer "parameter missing".  Nothing
is actuated.

Typical use:

    # before the experiment: record a baseline
    python tools/zeekr_gate_check.py --creds tokens.json --save docs/zeekr_gate_baseline.json

    # after the owner re-shares the car, compare
    python tools/zeekr_gate_check.py --creds tokens.json --compare docs/zeekr_gate_baseline.json

Exit code is 1 when any gated interface flipped open, so a caller can act on it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import zeekr_probe as zp  # noqa: E402

VIN_DEFAULT = "L6T77HCE9PF081833"
GATE_CODE = "079001"
GATE_MARK = "[SDK]"

# (label, method, path, params, payload) — everything here is read-only.
PROBES: list[tuple[str, str, str, dict | None, dict | None]] = [
    # --- control plane, expected SDK-gated ---
    ("控制:车辆状态v2",      "GET",  "/ms-vehicle-status/api/v2.0/vehicle/status/latest", None, None),
    ("控制:车辆状态qrvs",    "GET",  "/ms-vehicle-status/api/v1.0/vehicle/status/qrvs", None, None),
    ("控制:车辆状态vtm",     "GET",  "/ms-vehicle-status/api/v1.0/vehicle/status/vtm", None, None),
    ("控制:发送指令",        "POST", "/ms-remote-control/v1.0/remoteControl/control", None, {}),
    ("控制:指令入口(带api)", "POST", "/ms-remote-control/api/v1.0/remoteControl/control", None, {}),
    ("控制:空调AI",          "POST", "/ms-remote-control/api/v1.0/remoteControl/aiClimate", None, {}),
    ("控制:空调查询",        "GET",  "/ms-remote-control/api/v1.0/remoteControl/queryAiClimate", None, None),
    ("账号:权限清单",        "GET",  "/ms-app-bff/api/1.0/permissions", {"tspPlatform": "1"}, None),
    ("账号:车辆详情",        "GET",  "/ms-vehicle-account/api/v1.0/vehicle-detail", None, None),
    ("车主授权码",           "POST", "/ms-app-bff/api/v1.0/mntmode/authCode/ownerAuthorization", None, {}),
    ("车辆证书",             "POST", "/ms-app-bff/api/v1.0/certificate-center/getVehicleCertificate", None, {}),
    ("分享:可分享服务",      "GET",  "/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/services", None, None),
    ("分享:校验账号",        "GET",  "/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/check-share", None, None),
    ("轨迹:行程分页",        "POST", "/ms-vehicle-trail/api/v1.0/journalLog/trip/listForPage", None, {}),
    ("轨迹:轨迹点",          "GET",  "/ms-vehicle-trail/api/v1.0/journalLog/trackpoint/list",
     {"tripReportTime": "20260901"}, None),
    ("围栏:分页",            "POST", "/ms-vehicle-defence/api/v1.0/fence/page", None, {}),
    ("数字钥匙:绑定用户",    "POST", "/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-bind-user-list", None, {}),
    ("数字钥匙:剩余槽位",    "POST", "/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-remaining-slot-quantity", None, {}),
    ("充电:最新SOC",         "GET",  "/ms-charge-manage/api/v1.0/charge/getLatestSoc", None, None),
    ("充电:行程计划v2",      "POST", "/ms-charge-manage/api/v2.0/charge/getTravelPlan", None, {}),
    ("人脸:已注册",          "GET",  "/ms-user-auth/api/v1.0/face/registered", None, None),
    ("IoT:设备",             "GET",  "/ms-iot-device/api/v1.0/iot/device", None, None),
    ("哨兵:图片列表",        "GET",  "/sentinel-monitoring-service/api/v2.0/pic/list", None, None),
    # --- known-open controls: if these fail, the token/session is broken ---
    ("基线:指令结果查询",    "GET",  "/ms-remote-control/v1.0/remoteControl/queryProcessResult", None, None),
    ("基线:分享列表(我收到)","GET",  "/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-list", None, None),
    ("基线:分享列表(我发出)","GET",  "/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-list", None, None),
    ("基线:用户车辆设置",    "POST", "/ms-tsp-user-setting/api/v1.0/userVeh/setting/query", None, {}),
    ("基线:临时码",          "GET",  "/ms-user-auth/api/v1.0/auth/cloud/temp/code", None, None),
]

BASELINE_LABELS = ("基线:",)
GATED_LABELS = ("控制:", "账号:", "车主授权码", "车辆证书", "分享:可服务", "分享:校验",
                "轨迹:", "围栏:", "数字钥匙:", "充电:", "人脸:", "IoT:")


async def run(creds: str, vin: str) -> dict[str, dict[str, str]]:
    client, _ = zp.build_client(types.SimpleNamespace(
        creds=creds, trace=False, proxy=None, timeout=30, host=None, vin=None))
    ok = await client.snc_login()
    token = client._new_access_token
    print(f"登录: {ok}  令牌: {'有' if token else '无'}\n")

    out: dict[str, dict[str, str]] = {}
    for label, method, path, params, payload in PROBES:
        try:
            data = await client._gw3(method, path, params=params, payload=payload,
                                     token=token, vin=vin, retry=False)
            code = str(data.get("code") or data.get("error_code") or data.get("message") or "")
            msg = str(data.get("msg") or data.get("error_msg") or "")
        except Exception as exc:  # noqa: BLE001
            code, msg = "ERR", f"{type(exc).__name__}: {str(exc)[:60]}"
        gated = code == GATE_CODE or GATE_MARK in msg
        if gated:
            verdict = "门禁"
        elif code in ("000000", "0"):
            verdict = "可用"
        elif code in ("000010", "000002", "34A02", "67A02", "56A02"):
            verdict = "放行"          # reached the service: params/method only
        else:
            verdict = "其他"
        out[label] = {"method": method, "path": path, "code": code,
                      "msg": msg[:120], "verdict": verdict, "gated": str(gated)}
        print(f"  [{verdict}] {label:22} {code:8} {msg[:58]}")
    return out


def report(results: dict[str, dict[str, str]], baseline: dict[str, dict[str, str]] | None) -> int:
    print("\n=== 汇总 ===")
    for group, labels in (("门禁内", GATED_LABELS), ("基线(应可用)", BASELINE_LABELS)):
        rows = [(l, results[l]) for l in results if l.startswith(labels)]
        blocked = sum(1 for _, r in rows if r["gated"] == "True")
        print(f"  {group}: {len(rows)} 项，其中仍被门禁 {blocked} 项")

    flipped: list[str] = []
    if baseline:
        print("\n=== 与基线对比 ===")
        for label, now in results.items():
            was = baseline.get(label)
            if not was:
                continue
            if was["gated"] == "True" and now["gated"] == "False":
                print(f"  ** 解除门禁 ** {label}: {was['code']} -> {now['code']} {now['msg'][:50]}")
                flipped.append(label)
            elif was["verdict"] != now["verdict"]:
                print(f"  变化 {label}: {was['verdict']}({was['code']}) -> "
                      f"{now['verdict']}({now['code']})")
        if not flipped:
            print("  没有任何接口从门禁状态变为放行。")

    print("\n判读：")
    print("  · 门禁项全部还是 079001 ⇒ 与账号车辆权限无关，需要 SDK 令牌（换令牌链）。")
    print("  · 有门禁项变为 放行/可用 ⇒ 门禁与账号权限有关，重分享生效，可开始接入车控。")
    print("  · 基线项若不可用 ⇒ 令牌/会话有问题，先解决登录再谈门禁。")
    return 1 if flipped else 0


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds", required=True)
    parser.add_argument("--vin", default=VIN_DEFAULT)
    parser.add_argument("--save", type=pathlib.Path)
    parser.add_argument("--compare", type=pathlib.Path)
    args = parser.parse_args(argv)

    results = await run(args.creds, args.vin)
    baseline = None
    if args.compare and args.compare.exists():
        baseline = json.loads(args.compare.read_text(encoding="utf-8"))
    elif args.compare:
        print(f"(对比文件不存在：{args.compare})")

    if args.save:
        args.save.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n已保存快照 -> {args.save}")
    return report(results, baseline)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
