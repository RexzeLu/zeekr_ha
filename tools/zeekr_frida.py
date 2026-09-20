#!/usr/bin/env python3
"""在已 root 的安卓设备上部署 frida-server 并运行 zeekr_hook.js，提取签名密钥与令牌。

默认走「adb 端口转发 + frida remote」模式，绕开 Windows 上 frida USB 驱动的老问题。

用法：
    # 1) 部署 frida-server（只需做一次，重启手机后需重跑 --start-server）
    python tools/zeekr_frida.py --setup

    # 2) 列出设备与进程，确认能看到 App
    python tools/zeekr_frida.py --list

    # 3) 带钩子冷启动 App（推荐：能抓到启动期写入的密钥）
    python tools/zeekr_frida.py --spawn

    # 或附加到正在运行的 App（不重启 App）
    python tools/zeekr_frida.py --attach

    然后按提示在手机上操作 App（打开车辆页 / 点一次车控），密钥与令牌会实时打印。
"""

from __future__ import annotations

import argparse
import json
import lzma
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ADB = os.environ.get("ADB", r"C:\ADB\adb.exe")
PKG = "com.zeekrlife.mobile"
DEVICE_PATH = "/data/local/tmp/frida-server"
PORT = 27042
HOOK_JS = Path(__file__).with_name("zeekr_hook.js")


def find_java_bridge() -> Path | None:
    """定位 frida-tools 自带的 Java 桥打包文件。

    frida 17 起运行时不再内置 Java/ObjC 桥（脚本里既没有全局 `Java`，也没有 `require`），
    桥必须以 frida-tools 的 bridges/java.js（一个 `var bridge = ...` 形式的 bundle）拼进脚本。
    """
    try:
        import frida_tools  # type: ignore
    except ImportError:
        return None
    p = Path(frida_tools.__file__).parent / "bridges" / "java.js"
    return p if p.is_file() else None


def build_hook_source(mode: str = "full") -> str:
    """把 Java 桥 bundle 与本项目钩子拼成一份可注入的脚本。

    mode="minimal" 时只装 SSL_write 明文捕获 —— 本 App 的 libkadp.so 会做代码完整性
    校验，钩子越多越容易被它发现并自杀；minimal 是「单点原生钩子」，最不容易被查出来。
    """
    src = HOOK_JS.read_text(encoding="utf-8")
    head = f"var ZKR_MODE = '{mode}';\n"
    bridge = find_java_bridge()
    if bridge is None:
        print("[warn] 没找到 frida-tools 自带的 java.js 桥，脚本会报「Java 未定义」。")
        print("[warn] 修复：pip install -U frida-tools")
        return head + src
    bridge_src = bridge.read_text(encoding="utf-8")
    print(f"Java 桥: {bridge} ({len(bridge_src) / 1024:.0f} KB)")
    return head + bridge_src + "\nvar Java = bridge;\n" + src


def adb(*args: str, check: bool = True, timeout: int = 300) -> str:
    p = subprocess.run([ADB, *args], capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} 退出码 {p.returncode}: {err.strip()}")
    return out


def sh(cmd: str, check: bool = True, timeout: int = 300) -> str:
    return adb("shell", cmd, check=check, timeout=timeout)


def pick_device(serial: str | None) -> str:
    if serial:
        return serial
    out = adb("devices")
    devs = [l.split()[0] for l in out.splitlines()[1:] if l.strip() and "\tdevice" in l]
    if not devs:
        raise SystemExit("没有检测到已授权设备（检查 USB 调试与手机上的授权弹窗）。")
    return devs[0]


def have_root(serial: str) -> bool:
    if sh("id").strip().startswith("uid=0"):
        return True
    adb("root", check=False, timeout=60)
    time.sleep(2)
    if sh("id").strip().startswith("uid=0"):
        return True
    return "uid=0" in sh("su -c id", check=False)


def su(cmd: str) -> str:
    if sh("id").strip().startswith("uid=0"):
        return sh(cmd, check=False)
    return sh(f'su -c "{cmd}"', check=False)


def abi_to_frida_arch(abi: str) -> str:
    abi = abi.strip()
    if abi.startswith("arm64"):
        return "arm64"
    if abi.startswith("armeabi"):
        return "arm"
    if abi.startswith("x86_64"):
        return "x86_64"
    if abi.startswith("x86"):
        return "x86"
    raise SystemExit(f"未知 CPU 架构: {abi}")


def download_server(version: str, arch: str) -> Path:
    name = f"frida-server-{version}-android-{arch}.xz"
    url = f"https://github.com/frida/frida/releases/download/{version}/{name}"
    cache = Path(os.environ.get("TEMP", ".")) / "frida_server_cache"
    cache.mkdir(parents=True, exist_ok=True)
    xz_path = cache / name
    bin_path = cache / f"frida-server-{version}-android-{arch}"

    proxy = os.environ.get("https_proxy") or os.environ.get("http_proxy")
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)

    if not xz_path.exists() or xz_path.stat().st_size < 1024:
        print(f"  下载 {url}")
        with opener.open(url, timeout=300) as r, open(xz_path, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
    if not bin_path.exists():
        print("  解压 .xz ...")
        with lzma.open(xz_path, "rb") as src, open(bin_path, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
    return bin_path


def setup(serial: str) -> None:
    import frida

    if not have_root(serial):
        raise SystemExit("设备没有 root 权限，无法运行 frida-server。")

    abi = sh("getprop ro.product.cpu.abi").strip()
    arch = abi_to_frida_arch(abi)
    ver = frida.__version__
    print(f"== 部署 frida-server ==")
    print(f"  设备架构: {abi} → {arch}")
    print(f"  frida 版本: {ver}")

    bin_path = download_server(ver, arch)
    print(f"  推送到设备: {DEVICE_PATH}")
    adb("push", str(bin_path), DEVICE_PATH, timeout=600)
    su(f"chmod 755 {DEVICE_PATH}")
    su(f"chcon u:object_r:shell_exec:s0 {DEVICE_PATH} 2>/dev/null")

    # 进程名 = 落盘文件名的 basename（改名规避检测时不能再用 pidof frida-server）
    proc_name = Path(DEVICE_PATH).name

    # 先杀掉旧的，再以 root 身份后台启动
    su(f"pkill -f {proc_name} 2>/dev/null")
    su("pkill -f frida-server 2>/dev/null")
    time.sleep(1)
    su(f"setsid {DEVICE_PATH} -l 0.0.0.0:{PORT} >/dev/null 2>&1 < /dev/null &")
    time.sleep(3)

    running = su(f"pidof {proc_name}").strip()
    if not running:
        raise SystemExit(
            "frida-server 没起来。可能被 SELinux/厂商安全中心拦截。"
            f"请手动在手机终端里跑一次： su -c '{DEVICE_PATH} -l 0.0.0.0:{PORT}'"
        )
    pid = running.split()[0]
    uid_line = su(f"grep -E '^Uid' /proc/{pid}/status").strip()
    if not uid_line.startswith("Uid:\t0"):
        raise SystemExit(
            f"frida-server 不是 root 身份（{uid_line}）⇒ 附加 App 会被 PermissionDenied 拒绝。\n"
            "多半是启动时漏了 su，请重跑 --setup；仍不行就手动跑："
            f" su -c '{DEVICE_PATH} -l 0.0.0.0:{PORT}'"
        )
    print(f"  frida-server 运行中 (pid {pid}, root，{uid_line})")

    adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
    print(f"  adb 端口转发已建立 tcp:{PORT}")
    print("== 就绪 ==")


def connect(serial: str, use_usb: bool):
    import frida

    if use_usb:
        return frida.get_usb_device(timeout=10), "usb"
    adb("forward", f"tcp:{PORT}", f"tcp:{PORT}")
    mgr = frida.get_device_manager()
    dev = mgr.add_remote_device(f"127.0.0.1:{PORT}")
    dev.enumerate_processes()  # 触发一次握手，失败会抛错
    return dev, f"remote 127.0.0.1:{PORT}"


def do_list(serial: str, use_usb: bool) -> None:
    dev, how = connect(serial, use_usb)
    print(f"== 设备连接方式: {how} ==")
    procs = dev.enumerate_processes()
    print(f"进程总数: {len(procs)}")
    # 注意：frida 把 App 进程的名字显示成**应用标签**（本 App 是「极氪」），
    # 按 "zeekr" 过滤一定是空 —— 以 adb ps 的真实 cmdline 为准。
    raw = sh(f"ps -A -o PID,NAME | grep {PKG}", check=False)
    found = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            found[int(parts[0])] = parts[1]
    if found:
        for pid in sorted(found):
            fname = next((p.name for p in procs if p.pid == pid), "<frida 表里没有>")
            print(f"  pid={pid}  {found[pid]}    (frida 侧名字: {fname})")
    else:
        print("  （未发现极氪相关进程，App 可能没在运行）")


def launch_and_wait_pid(serial: str, timeout: int = 25) -> int:
    """用 am 拉起 App，并轮询拿到它的主进程 pid。"""
    sh(f"am force-stop {PKG}", check=False)
    time.sleep(1)
    sh(f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1", check=False)
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = sh(f"pidof {PKG}", check=False).strip()
        if out:
            return int(out.split()[0])
        time.sleep(0.5)
    raise SystemExit(f"拉起 {PKG} 后 {timeout} 秒内没拿到 pid，请手动打开 App 后改用 --attach。")


def run_hooks(serial: str, use_usb: bool, mode: str, out: Path | None,
              duration: int = 0, hook_main: bool = False, script_mode: str = "full") -> None:
    js = build_hook_source(script_mode)
    log_path = out or (Path(os.environ.get("TEMP", ".")) / f"zeekr_hook_{time.strftime('%Y%m%d-%H%M%S')}.log")
    fh = open(log_path, "w", encoding="utf-8")

    def emit(obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        print(line, flush=True)
        fh.write(line + "\n")
        fh.flush()

    dev, how = connect(serial, use_usb)
    print(f"== 连接方式: {how} ==")

    sessions: dict[int, tuple] = {}

    def load_into(session, name: str):
        """把同一份钩子脚本注入一个 session，并把消息转发到日志。"""

        def on_message(message, data, _name=name):
            if message.get("type") == "send":
                payload = message.get("payload") or {}
                kind = payload.get("kind", "?")
                if kind == "class-count":
                    return
                emit({"t": time.strftime("%H:%M:%S"), "proc": _name,
                      "kind": kind, "data": payload.get("data")})
            elif message.get("type") == "error":
                emit({"t": time.strftime("%H:%M:%S"), "proc": _name, "kind": "script-error",
                      "data": (message.get("description") or "") + "\n" + (message.get("stack") or "")})

        script = session.create_script(js)
        script.on("message", on_message)
        script.load()
        return script

    if mode == "spawn":
        # 首选 frida 原生 spawn：进程在跑第一行代码之前就被挂起，脚本在这个窗口里注入，
        # 反调试（native ptrace 自附着 / Java isDebuggerConnected）都还没来得及执行。
        # 早期这里失败过，其实原因是 frida 17 的 Java 桥，不是 spawn 本身被拒。
        # force-stop 不会登出，也不会触发 logoutOtherDevices。
        print("尝试 frida spawn（在 App 跑起来之前注入）...")
        sh(f"am force-stop {PKG}", check=False)
        time.sleep(1)
        try:
            pid = int(dev.spawn([PKG]))
            print(f"  spawn 成功，pid {pid}（已暂停，等待注入）")
            session = dev.attach(pid)
            load_into(session, PKG)
            sessions[pid] = (session, PKG)
            dev.resume(pid)
            print("  已注入并恢复运行 —— 反调试被抢先关闭")
        except Exception as exc:
            print(f"  [warn] spawn 失败：{exc}")
            print("  回退为：am 拉起 + 附加（此时反调试可能已生效，主进程有被杀的风险）")
            sh(f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1", check=False)

    def app_procs() -> dict[int, str]:
        """发现 App 的全部进程。

        三个坑：
        1. frida 的进程表把 App 进程的名字换成了**应用标签**（本 App 是「极氪」），
           不是 com.zeekrlife.mobile[:xxx] —— 所以绝对不能靠名字过滤，
           必须以 adb ps 给出的真实 cmdline 为准，再用 pid 去 frida 表里对齐。
        2. 主进程有反调试：事后附加会被杀。所以默认走 frida spawn（运行前注入）。
        3. 主进程默认不参与「事后附加」，只钩子进程；spawn 已经覆盖主进程。
        """
        out: dict[int, str] = {}
        try:
            raw = sh(f"ps -A -o PID,NAME | grep {PKG}", check=False)
        except Exception:
            raw = ""
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].isdigit():
                out[int(parts[0])] = parts[1]
        # frida 表里名字可能是应用标签，只能靠 pid 对齐；只有 ps 也没覆盖到的才按名字兜底
        try:
            for p in dev.enumerate_processes():
                if p.pid in out:
                    continue
                name = p.name or ""
                if name == PKG or name.startswith(PKG + ":"):
                    out[p.pid] = name
        except Exception as exc:
            print(f"[warn] 枚举进程失败: {exc}")
        if not hook_main:
            out = {pid: n for pid, n in out.items() if n != PKG}
        return out

    def attach_new() -> int:
        added = 0
        for pid, name in app_procs().items():
            if pid in sessions:
                continue
            try:
                session = dev.attach(pid)
            except Exception as exc:
                print(f"[warn] 附加 {name} (pid {pid}) 失败: {exc}")
                continue

            try:
                load_into(session, name)
            except Exception as exc:
                print(f"[warn] 注入 {name} (pid {pid}) 失败: {exc}")
                try:
                    session.detach()
                except Exception:
                    pass
                continue
            sessions[pid] = (session, name)
            print(f"  已注入 {name} (pid {pid})")
            added += 1
        return added

    print("等待 App 进程出现并注入钩子 ...")
    banner_shown = False
    deadline = time.time() + duration if duration else None
    last_poll = 0.0
    try:
        while True:
            now = time.time()
            if now - last_poll >= 2:
                last_poll = now
                attach_new()
                if sessions and not banner_shown:
                    banner_shown = True
                    print()
                    print("====== 现在请在手机上操作极氪 App ======")
                    print("  ① 进「车辆」页，等车况刷出来")
                    print("  ② 点一次最轻的车控（闪灯 / 鸣笛）")
                    print("  ③ 再切一次车况页刷新")
                    print(f"  {'采集将在 %d 秒后自动结束' % duration if duration else '按 Ctrl+C 结束'}")
                    print(f"  日志: {log_path}")
                    print("========================================")
            if deadline and now >= deadline:
                print(f"\n已达到 {duration} 秒，自动结束采集。")
                break
            if deadline is None and not sessions and now > last_poll + 30:
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n结束采集。")
    finally:
        fh.close()
        for _pid, (session, _name) in sessions.items():
            try:
                session.detach()
            except Exception:
                pass
        print(f"共注入 {len(sessions)} 个进程。")
        summarize(log_path)


def summarize(log_path: Path) -> None:
    """扫一遍日志，把最关键的几类命中挑出来打印。"""
    if not log_path.is_file():
        return
    keys, cands, reqs, auths, errs = [], [], [], [], []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        kind = rec.get("kind")
        data = rec.get("data")
        if kind == "CRYPTO-KEY":
            keys.append(data)
        elif kind == "KEY-CANDIDATE":
            cands.append(data)
        elif kind == "FULL-REQUEST":
            reqs.append(data)
        elif kind == "AUTH-HEADER":
            auths.append(data)
        elif kind == "script-error":
            errs.append(data)

    print()
    print("================ 本次采集小结 ================")
    print(f"  密钥命中 (CRYPTO-KEY)   : {len(keys)}")
    for k in keys[:8]:
        print(f"      - {k.get('api')} alg={k.get('alg')} len={k.get('len')}")
        print(f"        hex  : {k.get('hex')}")
        print(f"        ascii: {k.get('ascii')}")
    print(f"  类方法返回值候选        : {len(cands)}")
    for c in cands[:8]:
        print(f"      - {c}")
    print(f"  抓到的请求 (FULL-REQUEST): {len(reqs)}")
    for r in reqs[:6]:
        print(f"      - {r.get('method')} {r.get('url')}")
    print(f"  令牌身份 (AUTH-HEADER)  : {len(auths)}")
    for a in auths[:4]:
        print(f"      - azp={a.get('azp')} iss={a.get('iss')} exp={a.get('exp_readable')}")
    if errs:
        print(f"  脚本错误: {len(errs)}")
        print("      " + str(errs[0])[:300])
    print(f"  完整日志: {log_path}")
    print("=============================================")


def main() -> int:
    global PORT, DEVICE_PATH
    ap = argparse.ArgumentParser(description="frida 动态提取极氪 App 密钥/令牌")
    ap.add_argument("--serial", help="adb 设备序列号")
    ap.add_argument("--usb", action="store_true", help="用 frida USB 模式（默认走 adb 转发 remote）")
    ap.add_argument("--setup", action="store_true", help="部署并启动 frida-server")
    ap.add_argument("--list", action="store_true", help="列出设备进程")
    ap.add_argument("--spawn", action="store_true", help="带钩子冷启动 App（默认）")
    ap.add_argument("--attach", action="store_true", help="附加到运行中的 App")
    ap.add_argument("--out", help="日志输出路径")
    ap.add_argument("--duration", type=int, default=0,
                    help="采集 N 秒后自动结束（0=一直跑到 Ctrl+C）")
    ap.add_argument("--main", action="store_true",
                    help="也尝试附加主进程（默认关闭：主进程有反调试，附加会把 App 杀掉）")
    ap.add_argument("--port", type=int, default=PORT,
                    help=f"frida-server 监听端口（默认 {PORT}；被反调试检测时换个冷门端口）")
    ap.add_argument("--device-path", default=DEVICE_PATH,
                    help=f"设备上 frida-server 的落盘路径（默认 {DEVICE_PATH}；可改名规避检测）")
    ap.add_argument("--mode", choices=["full", "sanitize", "minimal"], default="full",
                    help="脚本模式：full=全部钩子；sanitize=maps 洗白 + SSL_write（对付 libkadp 反调试）；"
                         "minimal=只装 SSL_write")
    args = ap.parse_args()

    PORT = args.port
    DEVICE_PATH = args.device_path

    if sys.platform == "win32" and not Path(ADB).exists():
        raise SystemExit(f"找不到 adb: {ADB}（用环境变量 ADB 指定）")

    serial = pick_device(args.serial)
    print(f"设备: {serial}")

    if args.setup:
        setup(serial)
        return 0
    if args.list:
        do_list(serial, args.usb)
        return 0

    mode = "attach" if args.attach else "spawn"
    run_hooks(serial, args.usb, mode, Path(args.out) if args.out else None,
              args.duration, args.main, args.mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
