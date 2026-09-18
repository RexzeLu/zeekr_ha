# 抓包作战手册 — 拿到 App 真正使用的令牌

> 目的：`[SDK]` 门禁按**令牌的客户端身份**判定，我们的令牌（`azp=user_center_client_phone`、`scope=""`）
> 被拒，而同一账号在 App 里能正常控车。所以 App 一定带了**另一份凭据**。
> 静态逆向已到尽头（dex 里没有 `/snc/`、`/vcl/` 这类明文的 SDK 路径；URL 是代码拼的），
> **唯一能给出确定答案的手段是抓一次 App 的真实控制请求。**

---

## 0. 先决条件（选定后不要再犹豫）

> **⚠️ 绝对不要把账号登进模拟器**：GW1 JWT 里 `accountLoginInfoDTO.logoutOtherDevices = true`
> 已被实测确认 ⇒ **模拟器一登录，用户手机上的 App 立刻被顶下线**。
> 本场景必须**直接抓用户自己手机上的流量**。
>
> **好消息**：SNC SDK 自带 `TrustAllCerts`
> （`com/geely/snc/network/http/auth/TrustAllCerts`、
> `com/zeekr/snc/vehicle/core/net/http/auth/TrustAllCerts`，均为 **[dex]** 确认）
> ⇒ 车控请求**很可能不校验证书**，因此**不需要 root、也不需要去证书固定**。
> 用户级 CA 大概率就够。

| 项 | 说明 |
| --- | --- |
| 用哪个账号 | **`16620192335`**（HA 那个号）。它**不是**你主力机上的账号 ⇒ 抓包不会打扰你日常使用；代价是期间 HA 的车控会话被顶掉，随时可恢复。 |
| 要抓什么 | **一次最简单的车控动作**：闪灯 / 鸣笛 / 开关空调任选一个。只要一次成功/失败的请求就够。 |
| 交付什么 | 抓包文件（`.har` 或 `.flow`）**或**截图里那条请求的 URL / 请求头 / body。我会用 `tools/zeekr_capture_triage.py` 直接解析。 |

---

## 0.5 方案 0（人在外面也能做）：手机自带抓包 App，**不需要电脑、不需要同一网络**

适用于「用户不在家 / 只想用手机」的场景。走 VPN 模式，**手机用自己的流量也能抓**。

1. 手机装一个支持 VPN 模式抓包的 App（**Reqable**、HttpCanary/小黄鸟 同类皆可）。
2. 首次启动会引导**安装它的 CA 证书**（装成「VPN 和应用」/用户证书即可）——
   本 App 大概率够用，因为车控段走 SNC SDK 的 `TrustAllCerts`。
3. 开始抓包 → 打开极氪 App → **做一次车控（闪灯 / 锁车）**。
4. 在抓包列表里找 **`snc-tsp-api.zeekrlife.com`** 的请求（车控那一条），点进去。
5. **截图给我这三样**：
   - **请求头**（要能看到完整的 `Authorization`、`X-APP-ID`、`X-VIN` 及其它 `X-*`）；
   - **请求体**（那段 JSON）；
   - 请求行（`POST` + 完整路径）。

> 我需要的就是「App 到底带了什么」。拿到 `Authorization` 我就能解出它的 `azp`/`scope`，
> 与我们的 `user_center_client_phone` / `""` 一对比，答案立刻出来。

---

## 1. 方案 A（推荐，人在家时用）：抓用户自己手机的流量（免 root）

**一键启动（推荐）**：

```bash
cd /d/zeekr_ha
C:/Users/rexze/.workbuddy/binaries/python/versions/3.13.12/python.exe tools/zeekr_capture_start.py
# 若 App 其它模块严格校验证书，改用只代理极氪域名：  ... --zeekr-only
```

脚本会自动检测本机局域网 IP、绑定并启动代理、把手机侧步骤连 IP 一起打印出来。
以下参数表供手工操作时对照：

| 项 | 值 |
| --- | --- |
| 抓包主机 IP | **192.168.6.21** |
| 代理端口 | **8080** |
| CA 证书（给 Android 装） | `C:\Users\rexze\.mitmproxy\mitmproxy-ca-cert.cer` |
| 抓包输出 | `D:/zeekr_ha/capture/zeekr.flow` |
| mitmdump 可执行 | `C:/Users/rexze/.workbuddy/binaries/python/envs/mitm/Scripts/mitmdump.exe` |

步骤：

1. **手机与电脑连同一个 WiFi**（网段 `192.168.6.x`）。
2. **手机设置代理**：WLAN → 当前网络 → 代理 → 手动
   - 主机名 `192.168.6.21`，端口 `8080`，保存。
3. **手机装 CA**：手机浏览器打开 **`http://mitm.it`** → 选 Android →
   下载证书（或直接把 `mitmproxy-ca-cert.cer` 传进手机安装）→
   设置 → 安全 → 从存储设备安装 → 选 **`VPN 和应用`**（用户证书即可）。
4. 打开极氪 App，确认能正常用车（说明代理链路通）。
5. **做一次车控动作**（闪灯 / 锁车）。
6. 停止抓包（我这边停 mitmdump 即可），然后我用
   `tools/zeekr_capture_triage.py` 解析。

> 若第 4 步 App 报网络错误：说明它对该域名确实做了校验。
> 先试**只对 `snc-tsp-api.zeekrlife.com` 走代理**（用 mitmproxy 的 `--allow-hosts`），
> 因为车控那一段是 SNC SDK 发的（TrustAllCerts），而 App 其它模块可能严格校验。

---

### 存档：Android 模拟器方案（**本场景不适用**）

模拟器天生可 root、系统分区可写，能把 mitmproxy 的 CA 装成**系统级证书**
（`-writable-system` + `adb root` + `adb remount` + 按 `<hash>.0` 命名推入
`/system/etc/security/cacerts`）。但如 §0 所述，**登录模拟器会顶掉用户手机**，
所以只在「账号可以随便顶掉」时使用。

### 1.1 起模拟器（Windows）

```bash
# 用 Android Studio 的 avdmanager 建一个 Pixel 系统镜像（API 30+ 皆可）
# 关键：-writable-system 让 /system 可写
emulator -avd Pixel_API34 -writable-system -no-snapshot-load
```

### 1.2 装系统级 CA

```bash
adb root
adb remount

# mitmproxy 首次运行会在 confdir 生成 mitmproxy-ca-cert.pem
MITM=C:/Users/rexze/.workbuddy/binaries/python/envs/mitm
"$MITM/Scripts/mitmdump.exe" --version          # 触发 CA 生成
# CA 默认位置：%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem

# 计算 Android 需要的 <hash>.0 文件名
HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$USERPROFILE/.mitmproxy/mitmproxy-ca-cert.pem" | head -1)
adb push "$USERPROFILE/.mitmproxy/mitmproxy-ca-cert.pem" /sdcard/
adb shell "mkdir -p /system/etc/security/cacerts"
adb shell "cp /sdcard/mitmproxy-ca-cert.pem /system/etc/security/cacerts/$HASH.0"
adb shell "chmod 644 /system/etc/security/cacerts/$HASH.0"
adb shell "ls -l /system/etc/security/cacerts/$HASH.0"     # 确认存在
adb reboot                                                  # 重启后系统证书生效
```

### 1.3 起代理并让模拟器走代理

```bash
# 终端 1：抓包（-w 写到文件，方便回传分析）
"$MITM/Scripts/mitmdump.exe" -p 8080 -w D:/zeekr_ha/capture/zeekr.flow \
    --set block_global=false

# 终端 2：模拟器把代理指向宿主机（10.0.2.2 是模拟器里看到的本机地址）
adb shell settings put global http_proxy 10.0.2.2:8080
```

### 1.4 操作与验收

1. 在模拟器里装极氪 App（用 APK 直接 adb install，或应用商店）。
2. **用 `16620192335` + 短信验证码登录**（验证码我这边收不到，需要你提供或你在这个号上收）。
3. 确认能正常进入车辆页（说明网络通）。
4. **做一次车控动作**（闪灯 / 鸣笛）。
5. 回到终端按 `Ctrl+C` 停止抓包，把 `capture/zeekr.flow` 给我。

### 1.5 如果 App 做了证书固定（pinning）

症状：mitmproxy 里能看到连接，但 App 报网络错误 / 看不到 HTTPS 内容。

```bash
# 用 frida 在模拟器上禁用 pinning（模拟器可 root，直接跑 frida-server 即可）
adb push frida-server-<ver>-android-x86_64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
# 宿主机装 frida-tools（同一个 mitm venv 即可），用通用 unpinning 脚本挂钩
objection -g com.zeekrlife.mobile explore --startup-command "android sslpinning disable"
```

---

## 2. 方案 B（更省事，但可能失败）：真机 + 免 root 抓包 App

- 装 **Reqable**（原 Charles 移动版）或 HttpCanary 同类，用其 **VPN 模式**抓包；
- 手机需安装并信任其证书（用户级证书）；
- **成功前提**：App 不校验证书链固定。极氪 App 有可能固定 ⇒ 失败就转方案 A。

优点：5 分钟就能试；缺点：很可能抓不到 HTTPS 内容。

---

## 3. 抓完之后我做什么（你只管把文件给我）

```bash
PY=C:/Users/rexze/.workbuddy/binaries/python/envs/default/Scripts/python.exe
cd /d/zeekr_ha

# .flow（mitmproxy 原生，分析需用 mitm venv 的 python）
C:/Users/rexze/.workbuddy/binaries/python/envs/mitm/Scripts/python.exe \
    tools/zeekr_capture_triage.py capture/zeekr.flow --filter remoteControl

# .har（Reqable / Charles / mitmproxy 都可导出）
$PY tools/zeekr_capture_triage.py capture/zeekr.har
```

工具会**自动打印**：

- 每条极氪网关请求的 `method / host / path`；
- 所有身份类请求头（`Authorization`、`X-APP-ID`、`app_code`、`X-VIN`、`sign` …）；
- **`Authorization` 里那份 JWT 的 `azp` / `aud` / `scope`**；
- 最后给一张「**令牌身份分布表**」。

### 判读

| 抓包结果 | 结论 | 下一步 |
| --- | --- | --- |
| 出现 `azp != user_center_client_phone` 的令牌 | 找到 SDK 客户端身份，问题定性完成 | 逆向「如何获取该令牌」（起点已锁定为该 client） |
| 只有 `user_center_client_phone`，但带了某个我们没发的头 | 门禁认的是头部 | 把该头加入请求即可 |
| 只有 `user_center_client_phone`，头也一致 | 门禁认的是别的维度（如 X-VIN 派生、请求体签名） | 逐字段比对 body 差异 |

---

## 4. 目录约定

```
D:/zeekr_ha/capture/          <- 抓包文件放这里（.flow / .har）
```

`capture/` 已在 `.gitignore` 之外仅本机使用；**内含令牌，绝不提交到仓库。**
