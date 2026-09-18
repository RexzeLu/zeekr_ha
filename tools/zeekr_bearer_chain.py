"""极氪中国区「bearer token」链路一键脚本。

背景（来自 zeekr_ev_api 海外版实现，中国区应为同构）：
  1) GW1 手机验证码登录  → JWT
  2) GET  /zeekrlife-app-user/v1/user/tspCode   → tspCode
  3) POST /ms-user-auth/v1.0/auth/login
         {identifier: tspCode, identityType: 10, ...}  → accessToken（bearer）
  4) 用 bearer token 调 ms-* 业务接口（vehicle-status / remote-control ...）

本脚本把 1→4 串起来，并在第 4 步对一批只读接口做探针，判定 `079001`
（SDK 门禁）是否因令牌身份改变而消失。

用法：
  # 第一步：发验证码（用户会收到短信）
  python tools/zeekr_bearer_chain.py --send-sms --phone 16620192335

  # 第二步：带验证码跑完整链路
  python tools/zeekr_bearer_chain.py --phone 16620192335 --code 123456

注意：一个账号只能在线一个设备。跑本脚本会顶掉手机上极氪 App 的会话；
      执行期间请勿在手机上打开 App，否则会反过来顶掉脚本的会话。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import zeekr_probe as zp  # noqa: E402

VIN = "L6T77HCE9PF081833"
TSPCODE_PATHS = (
    "/zeekrlife-app-user/v1/user/tspCode",
    "/zeekrlife-app-user/v1/user/toc/tspCode",
    "/zeekrlife-app-user/v1/user/pub/tspCode",
)
# 只读探针：不含任何会动作车的写接口
PROBES = (
    "/ms-vehicle-status/api/v2.0/vehicle/status/latest",
    "/ms-vehicle-status/api/v1.0/vehicle/status/qrvs",
    "/ms-vehicle-core/api/v1.0/vehicle/favorite-vehicles",
    "/ms-app-bff/api/1.0/permissions",
    "/ms-remote-control/v1.0/remoteControl/queryProcessResult",
)


def brief(obj, n: int = 600) -> str:
    return json.dumps(obj, ensure_ascii=False)[:n] if isinstance(obj, (dict, list)) else str(obj)[:n]


def find_jwt(obj) -> str | None:
    """从登录响应里挖出 JWT（深度遍历找三段式字符串）。"""
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, str) and v.count(".") == 2 and len(v) > 80:
                    return v
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


def find_field(obj, names: tuple[str, ...]) -> str | None:
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k in names and isinstance(v, str) and v:
                    return v
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return None


async def main() -> None:
    ap = argparse.ArgumentParser(description="极氪 CN bearer 链路")
    ap.add_argument("--creds", default="C:/Users/rexze/AppData/Local/Temp/zeekr_bak/tokens.json")
    ap.add_argument("--phone", default="16620192335")
    ap.add_argument("--code", help="短信验证码")
    ap.add_argument("--send-sms", action="store_true", help="只发验证码")
    ap.add_argument("--vin", default=VIN)
    args = ap.parse_args()

    ns = types.SimpleNamespace(creds=args.creds, trace=False, proxy=None,
                               timeout=30, host=None, vin=None)
    client, _ = zp.build_client(ns)

    # ---------- 步骤 1：发验证码 ----------
    if args.send_sms:
        r = await client.async_send_sms(args.phone)
        print("发验证码 ->", brief(r))
        print("\n请把收到的验证码用 --code 传入再跑一次。")
        return

    if not args.code:
        print("需要 --code（或用 --send-sms 先发验证码）")
        return

    # ---------- 步骤 2：GW1 手机登录 ----------
    print("=" * 66)
    print("[1] GW1 手机验证码登录")
    login = await client._gw1_login(args.phone, args.code)
    print("    ->", brief(login))
    jwt = find_jwt(login)
    if not jwt:
        print("    [!!] 未从响应里找到 JWT，后续无法继续。完整响应：")
        print("    ", brief(login, 1200))
        return
    client._jwt_token = jwt
    print(f"    JWT 已获取（{len(jwt)} 字符）")

    # ---------- 步骤 3：拿 tspCode ----------
    print("\n[2] 获取 tspCode")
    tsp_code = None
    for path in TSPCODE_PATHS:
        for params in ({"tspClientId": "1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc"}, None):
            try:
                r = await client._gw1("GET", path, params=params)
            except Exception as exc:  # noqa: BLE001
                print(f"    {path:52} ERR {str(exc)[:50]}")
                continue
            code = str(r.get("code") or r.get("error_code") or "")
            if code == "000000":
                tsp_code = find_field(r, ("tspCode", "code", "tspToken"))
                print(f"    {path:52} -> 000000  tspCode={tsp_code}")
                break
            print(f"    {path:52} -> {code} {str(r.get('msg') or '')[:44]}")
        if tsp_code:
            break
    if not tsp_code:
        print("    [!!] 未拿到 tspCode —— 后续 bearer 登录无法进行（该路径可能需别的前缀）")
        return

    # ---------- 步骤 4：identityType 换 bearer token ----------
    print("\n[3] 用 tspCode 换 bearer token（identityType 10 / 对照 5）")
    base_body = {
        "loginDeviceJgId": "",
        "loginDeviceId": client._login_device_id,
        "loginDeviceType": 1,
        "loginPhoneBrand": "OPPO",
        "loginPhoneModel": "PLJ110",
        "loginSystem": "Android",
    }
    bearer = None
    for it in (10, 5, 11, 12, 6):
        body = dict(base_body, identifier=tsp_code, identityType=it)
        if it == 5:
            body["token"] = client._bearer(jwt)
        try:
            r = await client._gw3("POST", "/ms-user-auth/v1.0/auth/login", payload=body,
                                  vin=args.vin, vin_encrypted=True, retry=False)
        except Exception as exc:  # noqa: BLE001
            print(f"    identityType={it:3} ERR {str(exc)[:70]}")
            continue
        tok = ((r.get("data") or {}).get("accessToken") or "")
        print(f"    identityType={it:3} -> {r.get('code')} {str(r.get('msg'))[:52]}"
              f"{'  [拿到令牌]' if tok else ''}")
        if tok and not bearer:
            bearer = tok
    if not bearer:
        print("    [!!] 没拿到 bearer token")
        return

    # ---------- 步骤 5：用 bearer token 探只读接口 ----------
    print(f"\n[4] 用 bearer token（{len(bearer)} 字符）探只读接口")
    for path in PROBES:
        try:
            r = await client._gw3("GET", path, token=bearer, vin=args.vin, retry=False)
            print(f"    {path:62} -> {r.get('code')} {str(r.get('msg'))[:44]}")
        except Exception as exc:  # noqa: BLE001
            print(f"    {path:62} -> ERR {str(exc)[:40]}")
    print("\n判读：任何一项从 079001 变为 000000 / 参数级错误 ⇒ 链路成立。")


if __name__ == "__main__":
    asyncio.run(main())
