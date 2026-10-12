#!/usr/bin/env python3
"""从已 root 的安卓设备上只读提取极氪 App 私有数据，并扫描关键凭据。

用途：拿下 GRIC 体系的签名共享密钥、auth_client_zeekr_phone 令牌与其来源。

安全性：全流程只读。只在设备 /data/local/tmp 下留一个临时 tar 包（可 --clean 删除），
不修改 App 数据、不重启 App、不需要重新登录（因此不会顶掉手机上的会话）。

用法：
    python tools/zeekr_device_pull.py                 # 全流程：拉取 + 解包 + 扫描
    python tools/zeekr_device_pull.py --gric          # 额外抠出最新的一对 GRIC 令牌（脱敏打印）
    python tools/zeekr_device_pull.py --gric --write-tokens   # 并写进工具链的令牌文件（自动备份）
    python tools/zeekr_device_pull.py --scan-only DIR --gric  # 只扫描已解包目录并取令牌
    python tools/zeekr_device_pull.py --clean         # 清理设备上的临时 tar
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ADB = os.environ.get("ADB", r"C:\ADB\adb.exe")
PKG = "com.zeekrlife.mobile"
REMOTE_TMP = "/data/local/tmp/zeekr_pull.tar.gz"

RE_JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}")
RE_HEX32 = re.compile(rb"\b[0-9a-f]{32}\b")
RE_HEX40 = re.compile(rb"\b[0-9a-f]{40}\b")

KEYWORDS = [
    b"GEELYCNCH", b"gric-", b"gric_", b"auth_client_zeekr_phone", b"user_center_client_phone",
    b"x-signature", b"x-app-id", b"SecretKey", b"secretKey", b"appSecret", b"app_secret",
    b"HttpSecretKey", b"signatureKey", b"signKey", b"privateKey", b"refresh_token",
    b"access_token", b"accessToken", b"snc-tsp-api", b"api-gw-toc",
]

MAX_READ = 64 * 1024 * 1024


def adb(*args: str, check: bool = True, timeout: int = 180) -> str:
    cmd = [ADB, *args]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} 退出码 {p.returncode}: {err.strip()}")
    return out + (("\n[stderr] " + err) if err.strip() and not check else "")


def sh(cmd: str, check: bool = True, timeout: int = 180) -> str:
    return adb("shell", cmd, check=check, timeout=timeout)


def pick_device(explicit: str | None) -> str:
    if explicit:
        return explicit
    out = adb("devices")
    devs = [l.split()[0] for l in out.splitlines()[1:] if l.strip() and "\tdevice" in l]
    if not devs:
        raise SystemExit(
            "没有检测到已授权设备。请确认：① 手机已用 USB 连接并选了「文件传输/MTP」模式；"
            "② 开发者选项里已打开 USB 调试；③ 手机屏幕上点过「允许 USB 调试」。"
        )
    if len(devs) > 1:
        raise SystemExit(f"检测到多台设备 {devs}，请用 --serial 指定。")
    return devs[0]


def device_info(serial: str) -> dict:
    props = {}
    for k in ("ro.product.model", "ro.product.manufacturer", "ro.build.version.release",
              "ro.build.version.sdk", "ro.product.cpu.abi", "ro.product.cpu.abilist"):
        props[k] = sh(f"getprop {k}").strip()
    idout = sh("id").strip()
    props["adb_shell_id"] = idout
    props["selinux"] = sh("getenforce", check=False).strip()
    return props


def have_root(serial: str) -> str:
    """返回 'adb-root' / 'su' / '' —— 表示可用的提权方式。"""
    if sh("id").strip().startswith("uid=0"):
        return "adb-root"
    try:
        adb("root", check=False, timeout=60)
        time.sleep(2)
        if sh("id").strip().startswith("uid=0"):
            return "adb-root"
    except Exception:
        pass
    out = sh("su -c id", check=False).strip()
    if "uid=0" in out:
        return "su"
    return ""


def su_wrap(root: str, inner: str) -> str:
    if root == "adb-root":
        return inner
    return f"su -c \"{inner}\""


def pull_app_data(serial: str, pkg: str, root: str, out_dir: Path) -> Path | None:
    """把 App 私有目录打成 tar 拉到本地。返回本地 tar 路径（失败返回 None）。"""
    candidates = [f"/data/data/{pkg}", f"/data/user/0/{pkg}"]
    for remote_dir in candidates:
        exists = sh(su_wrap(root, f"ls -d {remote_dir} 2>/dev/null"), check=False).strip()
        if remote_dir not in exists:
            continue
        sh(su_wrap(root, f"rm -f {REMOTE_TMP}"), check=False)
        cmd = su_wrap(root, f"cd {remote_dir} && tar -czf {REMOTE_TMP} . 2>/dev/null")
        sh(cmd, check=False, timeout=600)
        size = sh(su_wrap(root, f"stat -c %s {REMOTE_TMP} 2>/dev/null"), check=False).strip()
        if not size.isdigit() or int(size) < 1024:
            print(f"  [warn] {remote_dir} 打包失败或过小（size={size!r}）", file=sys.stderr)
            continue
        local_tar = out_dir / "app_data.tar.gz"
        adb("pull", REMOTE_TMP, str(local_tar), timeout=600)
        print(f"  已拉取 {remote_dir} → {local_tar} ({int(size)/1048576:.1f} MB)")
        return local_tar
    return None


def pull_external(serial: str, pkg: str, out_dir: Path) -> None:
    remote = f"/sdcard/Android/data/{pkg}"
    if not sh(f"ls -d {remote} 2>/dev/null", check=False).strip():
        return
    sh(f"cd {remote} && tar -czf /sdcard/zeekr_ext.tar.gz . 2>/dev/null", check=False, timeout=600)
    size = sh("stat -c %s /sdcard/zeekr_ext.tar.gz 2>/dev/null", check=False).strip()
    if size.isdigit() and int(size) > 1024:
        adb("pull", "/sdcard/zeekr_ext.tar.gz", str(out_dir / "external.tar.gz"), timeout=600)
        sh("rm -f /sdcard/zeekr_ext.tar.gz", check=False)
        print(f"  已拉取外部存储 ({int(size)/1048576:.1f} MB)")


def safe_extract(tar_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    dest_res = str(dest.resolve())

    def _filter(member, _dest=None):
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            return None
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            return None
        target = str((dest / name).resolve())
        if not target.startswith(dest_res):
            return None
        return member

    with tarfile.open(tar_path, "r:gz") as tf:
        tf.extractall(dest, filter=_filter)


def decode_jwt(tok: bytes) -> dict:
    """解出 JWT 的关键声明，不返回整串（避免日志泄露）。"""
    try:
        parts = tok.decode("ascii", "replace").split(".")
        if len(parts) < 2:
            return {}
        pad = "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        keep = ("azp", "aud", "iss", "sub", "userId", "brand", "env", "exp", "scope")
        out = {k: payload[k] for k in keep if k in payload}
        exp = payload.get("exp")
        if isinstance(exp, int):
            out["exp_readable"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(exp))
        return out
    except Exception:
        return {}


GRIC_KEYS = (b"MODULE_LOGIN_ACCESS_TOKEN", b"MODULE_LOGIN_REFRESH_TOKEN")


def _jwt_iat(tok: bytes) -> int:
    try:
        parts = tok.decode("ascii", "replace").split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return int(payload.get("iat") or 0)
    except Exception:  # noqa: BLE001
        return 0


def find_gric_tokens(root_dir: Path) -> dict:
    """从 App 数据里挑出**最新**的一对 GRIC 令牌。

    登录态存在 ``files/mmkv/MOD_LOGIN``（键 ``MODULE_LOGIN_ACCESS_TOKEN`` /
    ``MODULE_LOGIN_REFRESH_TOKEN``）。MMKV 是 **append-only** 日志，同一个键会出现
    多次，**必须按 ``iat`` 取最新** —— 否则会拿回一条已被轮换作废的旧令牌，
    表现为「刚取的值一刷新就 1018P061 已过期」。
    """
    best: dict[str, tuple[int, str]] = {}
    where = ""
    for path in sorted(root_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_READ:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if not any(k in data for k in GRIC_KEYS):
            continue
        for m in RE_JWT.finditer(data):
            tok = m.group(0).decode("ascii", "replace")
            kind = "access" if len(tok) > 1000 else "refresh"
            iat = _jwt_iat(m.group(0))
            if kind not in best or iat > best[kind][0]:
                best[kind] = (iat, tok)
                where = str(path.relative_to(root_dir))
    return {
        "access": best.get("access", (0, ""))[1],
        "refresh": best.get("refresh", (0, ""))[1],
        "where": where,
    }


def write_gric_tokens(refresh: str, access: str, source: str) -> list[str]:
    """把这对令牌写进工具链的两份令牌文件（各自先备份）。"""
    targets = [
        os.path.join(tempfile.gettempdir(), "zeekr_gric_tokens.json"),
        "C:/Users/rexze/Documents/OPPO 互联/zeekr_gric_tokens.json",
    ]
    written: list[str] = []
    for target in dict.fromkeys(targets):
        try:
            data: dict = {}
            if os.path.exists(target):
                shutil.copyfile(target, target + ".bak-" + time.strftime("%Y%m%d-%H%M%S"))
                with open(target, encoding="utf-8") as fh:
                    data = json.load(fh)
            data["gric_access"] = access
            data["gric_refresh"] = refresh
            data["captured_from"] = source
            data["captured_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            tmp = target + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, target)
            written.append(target)
        except OSError as exc:
            print(f"  [warn] 写入失败 {target}: {exc}", file=sys.stderr)
    return written


def report_gric(info: dict, write: bool) -> None:
    """脱敏打印取到的令牌；``write`` 时顺带写进令牌文件。"""
    access = info.get("access") or ""
    refresh = info.get("refresh") or ""
    if not access and not refresh:
        print("  （未找到 GRIC 令牌：App 可能没登录，或登录态不在 mmkv/MOD_LOGIN 里）")
        return
    for label, tok in (("access", access), ("refresh", refresh)):
        if not tok:
            print(f"  {label:<8} 缺失")
            continue
        meta = decode_jwt(tok.encode())
        left = ""
        exp = meta.get("exp")
        if isinstance(exp, int):
            days = (exp - time.time()) / 86400
            left = f"剩余 {days:.2f} 天" + ("" if days > 0 else "  ❌ 已过期")
        print(f"  {label:<8} {tok[:14]}…({len(tok)})  {left}  到期 {meta.get('exp_readable')}")
    print(f"  来源 {info.get('where') or '?'}（同键多次出现时按 iat 取最新）")
    if write:
        source = f"phone mmkv MOD_LOGIN @{time.strftime('%Y-%m-%d %H:%M')}"
        for target in write_gric_tokens(refresh, access, source):
            print(f"  ✔ 已写入 {target}")
    else:
        print("  （只读：要写进令牌文件请加 --write-tokens）")


def scan(root_dir: Path, report: Path) -> dict:
    findings: dict[str, list[str]] = {"jwt": [], "hex32": [], "hex40": [], "keywords": []}
    jwt_seen: dict[str, dict] = {}
    hex_seen: dict[str, list[str]] = {}
    kw_seen: dict[str, list[str]] = {}
    files_scanned = 0

    for path in sorted(root_dir.rglob("*")):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_READ:
                continue
        except OSError:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        files_scanned += 1
        rel = str(path.relative_to(root_dir))

        for m in RE_JWT.finditer(data):
            tok = m.group(0)
            info = decode_jwt(tok)
            key = info.get("azp") or info.get("aud") or tok[:24].decode("ascii", "replace")
            sig = json.dumps(info, sort_keys=True, ensure_ascii=False)
            if sig not in jwt_seen:
                jwt_seen[sig] = {"where": rel, "info": info, "len": len(tok)}
            jwt_seen[sig].setdefault("also", [])
            if rel not in jwt_seen[sig]["also"]:
                jwt_seen[sig]["also"].append(rel)

        for m in RE_HEX32.finditer(data):
            v = m.group(0).decode()
            hex_seen.setdefault(v, [])
            if rel not in hex_seen[v] and len(hex_seen[v]) < 8:
                hex_seen[v].append(rel)

        for m in RE_HEX40.finditer(data):
            v = m.group(0).decode()
            hex_seen.setdefault(v, [])
            if rel not in hex_seen[v] and len(hex_seen[v]) < 8:
                hex_seen[v].append(rel)

        low = data.lower()
        for kw in KEYWORDS:
            if kw.lower() in low:
                kw_seen.setdefault(kw.decode(), [])
                if rel not in kw_seen[kw.decode()] and len(kw_seen[kw.decode()]) < 12:
                    kw_seen[kw.decode()].append(rel)

    lines: list[str] = []
    lines.append("# 极氪 App 私有数据扫描报告")
    lines.append(f"扫描文件数: {files_scanned}")
    lines.append("")

    lines.append("## 1. 令牌（JWT）")
    if jwt_seen:
        for i, (sig, ent) in enumerate(jwt_seen.items(), 1):
            lines.append(f"### Token {i}  len={ent['len']}")
            lines.append(f"  声明: {sig}")
            lines.append(f"  出现位置: {', '.join(ent['also'][:8])}")
    else:
        lines.append("  （未发现 JWT 明文，可能被 MMKV/加密存储或只驻留内存）")
    lines.append("")

    lines.append("## 2. 32/40 位 hex 串（密钥候选）")
    if hex_seen:
        for v, locs in sorted(hex_seen.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"  {v}  ({len(v)}位)  <- {', '.join(locs[:3])}")
    else:
        lines.append("  （无）")
    lines.append("")

    lines.append("## 3. 关键词命中位置")
    if kw_seen:
        for k, locs in sorted(kw_seen.items()):
            lines.append(f"  {k}: {', '.join(locs[:6])}")
    else:
        lines.append("  （无）")
    lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")
    return {"jwt": list(jwt_seen.values()), "hex": hex_seen, "kw": kw_seen, "report": lines}


def main() -> int:
    ap = argparse.ArgumentParser(description="只读提取并扫描极氪 App 私有数据")
    ap.add_argument("--serial", help="adb 设备序列号（多设备时必填）")
    ap.add_argument("--pkg", default=PKG, help=f"App 包名（默认 {PKG}）")
    ap.add_argument("--out", help="输出目录（默认 %%TEMP%%\\zeekr_device\\<时间戳>）")
    ap.add_argument("--scan-only", metavar="DIR", help="跳过拉取，扫描已解包的目录")
    ap.add_argument("--from-tar", metavar="TAR", help="跳过拉取，直接解包并扫描既有的 tar.gz")
    ap.add_argument("--clean", action="store_true", help="只清理设备上的临时 tar 后退出")
    ap.add_argument("--gric", action="store_true",
                    help="额外提取 App 里最新的一对 GRIC 令牌（脱敏打印，按 iat 取最新）")
    ap.add_argument("--write-tokens", action="store_true",
                    help="配合 --gric：把提取到的令牌写进工具链的令牌文件（写入前自动备份）")
    args = ap.parse_args()

    if args.clean:
        serial = pick_device(args.serial)
        root = have_root(serial)
        if root:
            sh(su_wrap(root, f"rm -f {REMOTE_TMP}"), check=False)
        print("已清理设备上的临时文件。")
        return 0

    if args.scan_only:
        d = Path(args.scan_only)
        if not d.is_dir():
            raise SystemExit(f"目录不存在: {d}")
        res = scan(d, d / "scan_report.txt")
        print("\n".join(res["report"]))
        if args.gric or args.write_tokens:
            print("\n== GRIC 令牌（取最新） ==")
            report_gric(find_gric_tokens(d), args.write_tokens)
        return 0

    if args.from_tar:
        tar_path = Path(args.from_tar)
        if not tar_path.is_file():
            raise SystemExit(f"tar 不存在: {tar_path}")
        out_dir = Path(args.out) if args.out else tar_path.parent
        data_dir = out_dir / "data"
        print(f"== 解包既有 tar: {tar_path} ==")
        safe_extract(tar_path, data_dir)
        print(f"  → {data_dir}")
        print("== 扫描 ==")
        res = scan(data_dir, out_dir / "scan_report.txt")
        print("\n".join(res["report"]))
        print(f"\n报告: {out_dir / 'scan_report.txt'}")
        return 0

    serial = pick_device(args.serial)
    out_dir = Path(args.out) if args.out else Path(tempfile.gettempdir()) / "zeekr_device" / time.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)

    print("== 设备信息 ==")
    info = device_info(serial)
    for k, v in info.items():
        print(f"  {k}: {v}")

    root = have_root(serial)
    print(f"== 提权方式: {root or '不可用'} ==")
    if not root:
        raise SystemExit(
            "无法提权。请确认手机已 root，并在手机上给 adb/shell 授予 su 权限"
            "（Magisk 里给「Shell」授权，或打开「超级用户 → adb shell」）。"
        )

    print("== 拉取 App 私有数据 ==")
    tar_path = pull_app_data(serial, args.pkg, root, out_dir)
    pull_external(serial, args.pkg, out_dir)

    if not tar_path:
        raise SystemExit("App 私有目录打包失败，请把上面的输出发我。")

    print("== 解包 ==")
    data_dir = out_dir / "data"
    safe_extract(tar_path, data_dir)
    print(f"  → {data_dir}")

    print("== 扫描 ==")
    res = scan(data_dir, out_dir / "scan_report.txt")

    print()
    print("\n".join(res["report"]))
    print(f"\n报告已写入: {out_dir / 'scan_report.txt'}")
    print(f"原始数据目录: {data_dir}")

    if args.gric or args.write_tokens:
        print("\n== GRIC 令牌（取最新） ==")
        report_gric(find_gric_tokens(data_dir), args.write_tokens)

    print(f"（清理设备临时文件：python tools/zeekr_device_pull.py --clean）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
