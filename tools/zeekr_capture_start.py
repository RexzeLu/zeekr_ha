"""Start the LAN capture proxy for the Zeekr App, with everything pre-filled.

Detects this machine's LAN address, launches ``mitmdump`` bound to it, writes a
timestamped flow file under ``capture/``, and prints the exact phone-side steps
with the address already substituted.  Ctrl+C stops and reports the file.

Usage:
    python tools/zeekr_capture_start.py                 # 抓全部
    python tools/zeekr_capture_start.py --zeekr-only    # 只代理极氪域名（App 其它模块严格校验时用）
    python tools/zeekr_capture_start.py --port 8080
"""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import shutil
import socket
import subprocess
import sys

MITM_PY = pathlib.Path("C:/Users/rexze/.workbuddy/binaries/python/envs/mitm/Scripts")
CA = pathlib.Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"

ZEEKR_HOSTS = (
    "snc-tsp-api.zeekrlife.com",
    "api-gw-toc.zeekrlife.com",
    "api.zeekrline.com",
    "gateway-pub.zeekrlife.com",
    ".*\\.zeekrlife\\.com",
)


def lan_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 80))          # no traffic, just picks a route
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--zeekr-only", action="store_true")
    parser.add_argument("--outdir", type=pathlib.Path,
                        default=pathlib.Path("D:/zeekr_ha/capture"))
    args = parser.parse_args(argv)

    mitmdump = MITM_PY / "mitmdump.exe"
    if not mitmdump.exists():
        print(f"找不到 mitmdump：{mitmdump}\n（应先创建 mitm venv 并 pip install mitmproxy）")
        return 2

    ip = lan_ip()
    args.outdir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    flow = args.outdir / f"zeekr-{stamp}.flow"

    cmd = [str(mitmdump), "--listen-host", ip, "-p", str(args.port),
           "-w", str(flow), "--set", "block_global=false",
           "--set", "connection_strategy=lazy"]
    if args.zeekr_only:
        cmd += ["--allow-hosts", ",".join(ZEEKR_HOSTS)]

    print("=" * 68)
    print("极氪 App 抓包代理已启动")
    print("=" * 68)
    print(f"  代理地址      {ip}:{args.port}")
    print(f"  抓包文件      {flow}")
    print(f"  CA 证书       {CA}")
    print(f"  代理范围      {'仅极氪域名（--zeekr-only）' if args.zeekr_only else '全部流量'}")
    print()
    print("手机侧操作：")
    print(f"  1. 手机连上和本机同一个 WiFi（网段需为 {'.'.join(ip.split('.')[:3])}.x）")
    print(f"  2. WLAN → 当前网络 → 代理 → 手动 → 主机 {ip} 端口 {args.port}")
    print("  3. 浏览器打开 http://mitm.it → Android → 下载 → 设置里装为「VPN 和应用」")
    print("  4. 打开极氪 App，确认能正常用车")
    print("  5. 做一次车控（闪灯 / 锁车）—— 做成功的那一次")
    print()
    print("抓完按 Ctrl+C，我会用 tools/zeekr_capture_triage.py 解析这个文件。")
    print("=" * 68, flush=True)

    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        pass

    size = flow.stat().st_size if flow.exists() else 0
    print(f"\n已停止。抓包文件 {flow}（{size / 1024:.0f} KB）")
    if size:
        print(f"下一步：python tools/zeekr_capture_triage.py \"{flow}\" "
              f"（需用 mitm venv 的 python 读 .flow）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
