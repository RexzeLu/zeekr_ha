#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GRIC 令牌自助续期 —— 脱离手机 App 独立运行的令牌链。

契约（2026-09-21 实测）：
    POST https://gric-api.geely.com/ms-midground-user/api/v1.0/user/auth/refresh/token
    body {"refreshToken": "<当前 refresh JWT>"}
    → {"code":"0","data":{"accessToken":…,"refreshToken":…,
                          "accessExpiresTimestamp":…,"refreshExpiresTimestamp":…}}

关键特性（会影响架构，务必知道）：
  * **服务端会轮换**：每次 refresh 都下发**新的 refresh token**（jti 变），并把
    refresh 有效期重新拉满 **30 天**；`sid` 保持不变。
  * **轮换会作废同会话里的其它令牌**：App 私有目录里那份旧 access 轮换后立刻
    返回 `00A17 已在别处登录` ⇒ **一个会话只能有一个「持有者」**。
    谁最后 refresh，谁拥有；另一方被登出。
  * ⇒ 只要 **≤7 天刷一次**（access 寿命 7 天），链就**无限续期**，集成可完全独立运行。
    代价：手机 App 会掉线，需要短信重登（重登很可能反过来顶掉我们 ⇒ 二者取一）。

用法：
    python tools/zeekr_gric_token.py show      # 只读：显示两条令牌的剩余有效期
    python tools/zeekr_gric_token.py refresh   # 轮换一次并持久化
    python tools/zeekr_gric_token.py ensure    # access 剩余 <24h 才刷（给定时任务用）
    python tools/zeekr_gric_token.py form      # 导出 HA 配置表单要填的两个值（写到桌面）
    python tools/zeekr_gric_token.py form --print        # 额外在终端打出明文
    python tools/zeekr_gric_token.py form --ident <值>   # 顺手把按车标识存进令牌文件

`form` 解决的是「用户自己去抓包根本拿不到值」：本机已经从 root 手机里取到过
`refreshToken` 与 `x-vehicle-identifier`，`form` 把它们写成一份可直接复制粘贴的文件。

⚠️ 令牌只从本地文件读、打印一律脱敏（`--print` 除外，那是你自己要看明文）。
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gric", os.path.join(_HERE, "zeekr_gric_verify.py"))
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)

AUTH_HOST = "gric-api.geely.com"
REFRESH_PATH = "/ms-midground-user/api/v1.0/user/auth/refresh/token"

PRIMARY = os.environ.get("ZEEKR_GRIC_TOKENS") or os.path.join(tempfile.gettempdir(), "zeekr_gric_tokens.json")
# 第二份镜像（防 %TEMP% 被清理；目录不存在则跳过）
MIRROR = os.path.join("C:/Users/rexze/Documents/OPPO 互联", "zeekr_gric_tokens.json")

ENSURE_WITHIN_H = 24.0

# `form` 导出文件的默认落点：桌面最好找；没有桌面就退回 %TEMP%。
_DESKTOP = os.path.join(os.path.expanduser("~"), "Desktop")
FORM_OUT = os.environ.get("ZEEKR_GRIC_FORM_OUT") or os.path.join(
    _DESKTOP if os.path.isdir(_DESKTOP) else tempfile.gettempdir(),
    "zeekr_ha_表单填写.txt",
)


def red(s: str | None) -> str:
    return f"{s[:14]}…({len(s)})" if s else "(空)"


def claims(tok: str | None) -> dict:
    if not tok:
        return {}
    try:
        p = tok.split(".")
        return json.loads(base64.urlsafe_b64decode(p[1] + "=" * (-len(p[1]) % 4)))
    except Exception:  # noqa: BLE001
        return {}


def load() -> dict:
    for p in (PRIMARY, MIRROR):
        if os.path.exists(p):
            try:
                return json.load(open(p, encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
    raise SystemExit(f"✗ 找不到令牌文件：{PRIMARY}")


def save(d: dict) -> list[str]:
    written = []
    for p in (PRIMARY, MIRROR):
        d2 = os.path.dirname(p)
        if p is MIRROR and not os.path.isdir(d2):
            continue
        try:
            os.makedirs(d2, exist_ok=True)
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, ensure_ascii=False, indent=2)
            os.replace(tmp, p)
            written.append(p)
        except Exception as e:  # noqa: BLE001
            print(f"# ⚠️ 写入失败 {p}: {e!r}")
    return written


def show(d: dict | None = None) -> float:
    """打印两条令牌状态，返回 access 剩余小时数。"""
    d = d or load()
    now = time.time()
    hours = -1.0
    for key, label in (("gric_access", "access"), ("gric_refresh", "refresh")):
        c = claims(d.get(key))
        exp = c.get("exp")
        if not exp:
            print(f"  {label:8s} {red(d.get(key))}  （无法解析 exp）")
            continue
        left = (exp - now) / 3600
        if key == "gric_access":
            hours = left
        state = "有效" if left > 0 else "❌ 已过期"
        print(f"  {label:8s} {red(d.get(key))}  jti={c.get('jti')}  "
              f"剩余 {left/24:.2f} 天 ({left:.1f} h)  {state}  到期 {time.ctime(exp)}")
    print(f"  sid={claims(d.get('gric_access')).get('sid')}  "
          f"刷新时间={d.get('refreshed_at') or d.get('captured_at') or '未知'}")
    return hours


def refresh(d: dict) -> dict:
    ref = d.get("gric_refresh")
    if not ref:
        raise SystemExit("✗ 令牌文件缺少 gric_refresh")
    # 备份
    bak = PRIMARY.replace(".json", f".bak.{time.strftime('%Y%m%d-%H%M%S')}.json")
    try:
        shutil.copy2(PRIMARY, bak)
        print(f"# 备份 → {bak}")
    except Exception:  # noqa: BLE001
        pass

    body = json.dumps({"refreshToken": ref}).encode()
    saved_host = V.HOST
    V.HOST = AUTH_HOST
    try:
        nonce, ts = str(__import__("uuid").uuid4()), str(time.time_ns() // 1_000_000)
        hdr = V.headers(nonce, ts)
        _base, sig = V.sign(V.KEY, "POST", REFRESH_PATH, hdr, "", body)
        st, resp, url = V.send("POST", REFRESH_PATH, "", hdr, sig, body)
    finally:
        V.HOST = saved_host

    print(f"# POST {url}  →  http={st}")
    try:
        o = json.loads(resp or "")
    except Exception:  # noqa: BLE001
        raise SystemExit(f"✗ 响应非 JSON：{(resp or '')[:200]}")

    if o.get("code") != "0":
        raise SystemExit(f"✗ 刷新失败：code={o.get('code')} msg={o.get('msg')!r}（令牌文件未改）")

    data = o.get("data") or {}
    new = copy.deepcopy(d)
    # 按声明区分 access / refresh（access 带 userId，refresh 不带）
    for v in data.values():
        if isinstance(v, str) and v.count(".") == 2:
            if "userId" in claims(v):
                new["gric_access"] = v
            else:
                new["gric_refresh"] = v
    new["refreshed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    new["refresh_response_keys"] = sorted(data)
    if new.get("gric_refresh") == ref:
        print("# ✓ 服务端**未轮换** refresh（同一条继续有效）")
    else:
        print("# ⚠️ 服务端**已轮换** refresh —— 旧的那条作废，同会话其它令牌也会被顶掉")

    for p in save(new):
        print(f"# 已写 {p}")
    return new


def form(d: dict, out: str | None = None, print_plain: bool = False,
         ident: str | None = None) -> str:
    """导出 HA 配置表单（GRIC 通道）要填的两个值。

    返回值是写出的文件路径。默认**不在终端打印明文**，只给脱敏预览，
    因为 refreshToken 等价于账号的接入权。
    """
    if ident:
        d["vehicle_identifier"] = ident.strip()
        for p in save(d):
            print(f"# 按车标识已存进 {p}")
        d = load()

    ref = (d.get("gric_refresh") or "").strip()
    vehicle_ident = (d.get("vehicle_identifier") or "").strip()
    missing = [name for name, value in (("refreshToken", ref),
                                        ("x-vehicle-identifier", vehicle_ident)) if not value]
    if missing:
        raise SystemExit("✗ 令牌文件里缺少：" + "、".join(missing)
                         + "\n  refreshToken 需从手机 App 登录态重新取（见 docs/zeekr_root_playbook.md）；"
                           "\n  取到后用 `form --ident <值>` 把按车标识一起存下来。")

    plate = d.get("plate") or "未知车牌"
    vin = d.get("vin") or "未知 VIN"
    text = "\n".join([
        "极氪 HA 集成 —— GRIC 通道「添加集成」表单要填的两个值",
        f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"车辆：{plate}  VIN {vin}",
        "",
        "【字段 1】refreshToken   →  粘贴到表单第一个框（整行复制，别带空格）",
        ref,
        "",
        "【字段 2】x-vehicle-identifier   →  粘贴到表单第二个框",
        vehicle_ident,
        "",
        "填完之后的注意事项：",
        "  * 保存后 HA 会立刻用它换一对新令牌 —— 本机这份文件里的 refresh 随之作废，属正常现象。",
        "  * 手机 App 别再登这个账号：同一会话只有一个持有者，两边会互相把对方顶下线。",
        "  * 万一以后 HA 侧的令牌失效，需要回到手机上短信重登，再重新取一次这两个值。",
        "",
    ])

    out = out or FORM_OUT
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, out)
    print(f"# 已写出：{out}")
    print(f"#   refreshToken           {red(ref)}")
    print(f"#   x-vehicle-identifier   {vehicle_ident}")
    if print_plain:
        print("\n" + text)
    return out


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    if cmd == "show":
        print(f"# 令牌文件 {PRIMARY}")
        show()
        return 0
    if cmd == "refresh":
        d = load()
        print("# 刷新前："); show(d)
        d = refresh(d)
        print("# 刷新后："); show(d)
        return 0
    if cmd == "ensure":
        d = load()
        left = show(d)
        if left < 0:
            print("# access 已过期 → 立即刷新")
        elif left <= ENSURE_WITHIN_H:
            print(f"# access 剩余 {left:.1f}h ≤ {ENSURE_WITHIN_H}h → 刷新")
        else:
            print(f"# access 剩余 {left:.1f}h > {ENSURE_WITHIN_H}h → 无需刷新")
            return 0
        print()
        refresh(d)
        return 0
    if cmd == "form":
        args = sys.argv[2:]
        out = None
        ident = None
        print_plain = False
        for i, arg in enumerate(args):
            if arg == "--print":
                print_plain = True
            elif arg == "--out" and i + 1 < len(args):
                out = args[i + 1]
            elif arg == "--ident" and i + 1 < len(args):
                ident = args[i + 1]
        form(load(), out=out, print_plain=print_plain, ident=ident)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
