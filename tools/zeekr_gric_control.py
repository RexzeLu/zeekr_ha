#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GRIC 车控（真车指令下发）—— 2026-09-21 实测打通。

契约（来自 app dex 的 `RemoteControlReq` + 本仓库实体表）：

    POST https://gric-zhf-api.geely.com/ms-remote-control/api/v1.0/remoteControl/control
    body = {"command": "start"|"stop",
            "serviceId": "<短码>",
            "setting": {"serviceParameters": [{"key": k, "value": v}, ...]}}
    → {"code":"0","msg":"操作成功","data":{"sessionId":"PF081833…"}}

签名与令牌见 `zeekr_gric_verify.py`（同一套 18 头白名单 + HMAC-SHA256）。

⚠️ 这是真车指令，会实际动作。用法（必须显式点命令名）：

    python tools/zeekr_gric_control.py flash       # 闪灯（瞬时，最安全）
    python tools/zeekr_gric_control.py honk        # 鸣笛并闪灯
    python tools/zeekr_gric_control.py lock        # 落锁
    python tools/zeekr_gric_control.py unlock      # 解锁
    python tools/zeekr_gric_control.py list        # 只列出命令表，不下发

不带参数 = 只打印命令表，绝不发指令。
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gric", os.path.join(_HERE, "zeekr_gric_verify.py"))
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

CTRL = "/ms-remote-control/api/v1.0/remoteControl/control"

# serviceId 短码 → 车端服务
#   RDL 落锁 / RDU 解锁 / RHL 灯光喇叭 / RWS 车窗遮阳帘 / RCS 充电 / ZAF 空调 / PCM 驻车舒适
CMDS: dict[str, tuple[str, str, dict]] = {
    "flash":  ("start", "RHL", {"serviceParameters": [{"key": "rhl", "value": "light-flash"}]}),
    "honk":   ("start", "RHL", {"serviceParameters": [{"key": "rhl", "value": "horn-light-flash"}]}),
    "lock":   ("start", "RDL", {"serviceParameters": [{"key": "door", "value": "all"}]}),
    "unlock": ("stop", "RDU", {"serviceParameters": [{"key": "door", "value": "all"}]}),
    "ac_on":  ("start", "ZAF", {"serviceParameters": [{"key": "AC", "value": "true"}]}),
    "ac_off": ("start", "ZAF", {"serviceParameters": [{"key": "AC", "value": "false"}]}),
}


def control(name: str) -> tuple[bool, str]:
    command, sid, setting = CMDS[name]
    body = json.dumps({"command": command, "serviceId": sid, "setting": setting}).encode()
    ok, resp = V.run(f"control:{name}", "POST", CTRL, body=body, show=500)
    return ok, resp


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("list", "-h", "--help"):
        print("可用命令（需显式指定才会下发）:")
        for k, (c, s, st) in CMDS.items():
            print(f"  {k:8s} command={c:5s} serviceId={s:4s} params={st['serviceParameters']}")
        print("\n用法: python tools/zeekr_gric_control.py <命令名>")
        return 0
    name = sys.argv[1]
    if name not in CMDS:
        print(f"未知命令 {name!r}；可用: {', '.join(CMDS)}")
        return 2
    print(f"# host={V.HOST} vin={V.VIN}")
    ok, resp = control(name)
    try:
        o = json.loads(resp)
        print(f"    code={o.get('code')} msg={o.get('msg')!r} "
              f"sessionId={(o.get('data') or {}).get('sessionId')}")
    except Exception:  # noqa: BLE001
        pass
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
