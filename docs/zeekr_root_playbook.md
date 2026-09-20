# 极氪 App 动态提取作战手册（root 手机版）

> 目标：拿到 `GEELYCNCH001M0001` 的签名共享密钥 + `auth_client_zeekr_phone` 令牌的来源链路。
> 前置条件：一台已 root 的安卓手机，App 处于**已登录**状态，用 USB 连到本机。

## 为什么这次大概率能成

1. **运行时 hook 完全绕过 dex 加固**。静态解析看不到的类，App 跑起来后都是明文的 —— 
   加固壳只保护磁盘上的字节，保护不了内存里的类和方法。
2. **不需要重新登录**。手机上 App 是登录态，密钥与令牌都在内存/私有目录里，
   直接读现成的即可，因此**不会顶掉你自己手机上的会话**（`logoutOtherDevices: true` 不触发）。
3. **失败也有兜底**：即使 hook 不到密钥，阶段 1 拉下来的私有数据里至少有令牌与其存储结构，
   能直接回答「GRIC 令牌从哪来」这一半问题。

---

## 零、前置检查

### 手机侧
1. 设置 → 关于手机 → 连点「版本号」7 次，打开开发者选项。
2. 开发者选项 → 打开 **USB 调试**。
3. 用数据线连电脑，手机弹「允许 USB 调试吗」→ **允许**（勾选「始终允许」）。
4. 下拉通知栏，把 USB 用途从「仅充电」改成 **文件传输 / MTP**。
5. **Magisk 里给 shell 授权**：打开 Magisk → 超级用户 → 看列表里有没有 `Shell`，
   没有就在下次弹窗时允许。这一步是阶段 1、2 的前提。

### 电脑侧
```bash
export PATH="/c/Users/rexze/.workbuddy/binaries/PortableGit/versions/1.2.0/cmd:/c/Users/rexze/.workbuddy/binaries/PortableGit/versions/1.2.0/usr/bin:/usr/bin:/bin:$PATH"
cd /d/zeekr_ha
PY="C:/Users/rexze/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
/c/ADB/adb devices -l      # 应看到一行 <serial>  device
```

已就绪的依赖（无需再装）：`adb 35.0.1`（`C:\ADB\adb.exe`）、
`frida 17.18.0` + `frida-tools 14.10.4`（本机 default venv）、
`frida-server 17.18.0 android-arm64` 已缓存（`%TEMP%\frida_server_cache\`，58.8 MB）。

---

## 阶段 1：先拉私有数据（不需要 frida，最省事）

```bash
$PY tools/zeekr_device_pull.py
```

脚本会：识别设备与架构 → 提权（先试 `adb root`，不行再走 `su -c`）→ 
把 `/data/data/com.zeekrlife.mobile` 打成 tar 拉到本地 → 解包 → 扫描并输出报告。

产物在 `%TEMP%\zeekr_device\<时间戳>\`：
- `data/` —— App 私有目录全文（shared_prefs / databases / files / no_backup）
- `scan_report.txt` —— JWT 令牌（含 `azp`/`iss`/`scope`/有效期，令牌本身脱敏）、
  32/40 位 hex 密钥候选、以及 `GEELYCNCH` / `gric-` / `SecretKey` / `auth_client_zeekr_phone`
  等关键词的命中位置

**判读要点**：
- 若报告里出现 `azp = auth_client_zeekr_phone` 的 JWT ⇒ 我们直接拿到了 App 用的那份令牌，
  剩下只要照抄它的换取方式即可。
- 若某个 32 位 hex 串出现在 `shared_prefs` 且附近有 `SecretKey` 字样 ⇒ 极可能就是签名密钥，
  立刻进阶段 3 验证。

清理设备临时文件：`$PY tools/zeekr_device_pull.py --clean`

---

## 阶段 2：frida 动态 hook

### 2.1 部署 frida-server（每次手机重启后需重跑）
```bash
$PY tools/zeekr_frida.py --setup
```
下载/推送/授权/后台启动 frida-server，并建立 `adb forward tcp:27042`。
走的是 **remote 模式而非 USB 模式**，避开 Windows 上 frida USB 驱动的老坑。

### 2.2 确认能连上、能看到 App
```bash
$PY tools/zeekr_frida.py --list
```

### 2.3 带钩子冷启动 App（推荐）
```bash
$PY tools/zeekr_frida.py --spawn
```
冷启动能抓到启动期 `setSecretKey` 这类一次性写入 —— 这是拿密钥的最佳时机。
App 重启不影响登录态（会话在磁盘上），**也不会导致顶号**。

如果 App 有反 frida 检测（启动即崩、或 hook 后无任何输出），换冷门端口与文件名：
```bash
$PY tools/zeekr_frida.py --setup  --port 8899 --device-path /data/local/tmp/fsd
$PY tools/zeekr_frida.py --spawn  --port 8899 --device-path /data/local/tmp/fsd
```

### 2.4 按提示在手机上操作
```
① 打开 App，进入车辆页，等它加载完
② 点一次车控，最轻的动作即可（闪灯 / 鸣笛）
③ 回到电脑按 Ctrl+C
```
日志实时打印并落盘到 `%TEMP%\zeekr_hook_<时间戳>.log`。

### 输出里的关键标记
| 标记 | 含义 |
| --- | --- |
| `KEY-CANDIDATE` | **疑似密钥已出现** —— 最想要的东西 |
| `class-found` / `class-hits` | 运行时发现的签名/加密相关类（静态看不见的） |
| `AUTH-HEADER` | App 实际使用的令牌身份（azp/iss/scope，令牌本体脱敏） |
| `AUTH-URL` | 认证类请求 URL —— 用于定位令牌来源端点 |
| `SIGN-HEADER` | 实时签名头（x-signature / nonce / timestamp / app-id） |
| `native-hits` | 原生库里带 SecretKey/Sign 字样的导出函数 |
| `hook-miss` | 某个钩子没装上（不致命，继续看其他标记） |

---

## 阶段 3：验证密钥（关键一步）

拿到候选密钥后，立刻用抓包里的真实请求验证 —— 命中即**同时**证明密钥对和算法对：

```bash
$PY tools/zeekr_sig_verify.py --key <候选密钥>
# 或者把 frida 日志里的候选批量喂进去
$PY tools/zeekr_sig_verify.py --keys-file candidates.txt --all
```

工具会遍历 4 种请求头集合 × 12 种规范串变体，命中时打印完整 canonical 串。
已通过自造请求做过回环测试（命中路径正常），并用真样本做过负例对照。

**命中之后就没悬念了**：GRIC 调用链已逐字节掌握（网关、路径、全部请求头、请求体、
`x-vehicle-identifier` 生成方式、`sessionId` + `queryProcessResult` 闭环），
剩下的全是把 `api_sms.py` 的签名实现换一套密钥头参数的工程活。

---

## 常见故障

| 现象 | 原因与处理 |
| --- | --- |
| `adb devices` 空 | USB 调试没开 / 没在手机上点允许 / 线只供电不带数据 |
| `--setup` 报「设备没有 root」 | Magisk 没给 Shell 授权；或机型限制 `adb root`，脚本会自动回退 `su -c` |
| frida-server 起不来 | 被 SELinux 或厂商安全中心拦。在手机终端手动跑 `su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042'` 看报错 |
| `--list` 连不上 | 端口转发没建，重跑 `--setup`；或换端口避开 27042 |
| hook 后无任何输出 | App 有反调试。换 `--port`/`--device-path` 再试；仍不行改 `--attach` 附加到已运行的 App |
| 输出刷屏 | `class-hits` 已被 `class-count` 之外的逻辑限流；如仍太多，用 `--out` 落盘后再筛 |

## 红线

- 全流程**只读**，不修改 App 数据、不触碰车控写操作（阶段 2 请你手动点的那一次除外）。
- 期间**不要退出登录**。真要重新登录时先在电脑侧确认没有正在跑的探测脚本，
  否则两边会互相顶号（`079021`）。
- 抓下来的数据里有完整令牌，**绝不提交进仓库**（`%TEMP%` 与 `capture/` 均已在 gitignore 覆盖范围内）。
