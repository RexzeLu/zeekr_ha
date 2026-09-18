# 极氪 HA 攻坚研究记录 — 2026-09-18 夜

> 本文是 2026-09-18 通宵自主研究的结构化成果，供次日直接进入测试。
> 来源标注：**[实测]** = 本机对真实网关发起请求得到的原始返回码；
> **[dex]** = APK v5.0.5 `classes.dex` 明文字符串池；**[推断]** = 由证据推导，未直接验证。

---

## 0. 一句话结论

**`079001 [SDK]此接口未被授权，无法访问!` 不是参数问题、也不是账号车辆权限问题，而是「接口级 SDK 白名单」——
同一服务内控制类接口被拒、查询类放行。因此 2026-09-16/17 在 GW2 侧摸索 `serviceParameters` 参数的路线已无价值，
唯一有效方向是拿到「SDK 身份的令牌」。**

---

## 1. 核心机制：`[SDK]` 门禁

### 1.1 现象（[实测]，同一份 GW3 令牌）

| 接口 | 返回 | 归类 |
| --- | --- | --- |
| `POST /ms-remote-control/v1.0/remoteControl/control` | `079001 [SDK]…` | 门禁 |
| `GET /ms-vehicle-status/api/v2.0/vehicle/status/latest` | `079001 [SDK]…` | 门禁 |
| `GET /ms-vehicle-status/api/v1.0/vehicle/status/{qrvs,vtm}` | `079001 [SDK]…` | 门禁 |
| `GET /ms-vehicle-account/api/v1.0/vehicle-detail` | `079001 [SDK]…` | 门禁 |
| `GET /ms-app-bff/api/1.0/permissions` | `079001 [SDK]…` | 门禁 |
| `POST /ms-app-bff/.../mntmode/authCode/ownerAuthorization` | `079001 [SDK]…` | 门禁 |
| `POST /ms-app-bff/.../certificate-center/getVehicleCertificate` | `079001 [SDK]…` | 门禁 |
| `GET .../vehicle-shares/{services,check-share}` | `079001 [SDK]…` | 门禁 |
| `POST /ms-vehicle-trail/.../journalLog/trip/listForPage` | `079001 [SDK]…` | 门禁 |
| `GET .../journalLog/trackpoint/list?tripReportTime=20260917` | `079001 [SDK]…` | 门禁 |
| `POST /ms-vehicle-defence/api/v1.0/fence/page` | `079001 [SDK]…` | 门禁 |
| `POST .../digital-key-center/{get-bind-user-list,get-remaining-slot-quantity}` | `079001 [SDK]…` | 门禁 |
| `GET /ms-charge-manage/api/v1.0/charge/getLatestSoc` | `079001 [SDK]…` | 门禁 |
| `GET /ms-user-auth/api/v1.0/face/registered` | `079001 [SDK]…` | 门禁 |
| —— | —— | —— |
| `GET /ms-remote-control/v1.0/remoteControl/queryProcessResult` | `000002 sessionId 缺失` | **放行** |
| `GET .../vehicle-shares/{owner/share-list,owner/share-histories,share/accept-list,share/accept-histories}` | `000000 ok` | **可用** |
| `POST /ms-tsp-user-setting/api/v1.0/userVeh/setting/query` | `000000 ok` | **可用** |
| `GET /ms-user-auth/api/v1.0/auth/cloud/temp/code` | `000000 ok` | **可用** |
| `GET /sentinel-monitoring-service/api/v2.0/pic/list` | `0 success` | **可用** |
| `GET /map-d2d-auto-service/api/v1/app/preciseMap/city/getAll` | `000000` | **可用** |
| `GET /scenario-mate-management-service/api/v1.0/mate/query/app/all/icon` | `000000` | **可用** |
| `POST /ms-tsp-dkbs-geely/.../digital-key-center/key-list` | `000002 signature/deviceid 不能为空` | 放行 |
| `POST /ms-user-auth/api/v1.0/auth/scanLogin` | `000002 登录数据不能为空` | 放行 |

### 1.2 门禁的判定位置（[实测]，重要）

- 对**同一路由**：`GET /ms-vehicle-trail/.../trip/listForPage` → `000010 method not allowed`；
  `POST` 同路径 → `079001 [SDK]`。
- `GET .../trackpoint/list`（缺参）→ `000002 The request parameter tripReportTime is missing`；
  换成合法格式 `20260917` → `079001 [SDK]`。

⇒ **顺序是「路由 → 参数校验 → SDK 白名单」，门禁由微服务内部判定**，不是网关层。
副作用：**`079001` 可以当作「参数已正确」的 oracle 使用**（拿到它说明参数被接受了）。

### 1.3 已排除的解释

| 假设 | 结论 |
| --- | --- |
| 参数 `serviceParameters` 写法不对 | 排除。门禁与参数无关（§1.2）。 |
| `X-VIN` 编码/内容不对 | 排除。历史对照实验已确认 enc/明文/内容全对。 |
| 账号没有车辆控制权限 | **存疑**。车控在 App 内可用同一账号操作，但接口仍拒绝；见 §5 假设 B。 |
| 需要特定请求头 | 未穷尽；`[SDK]` 字面更像「调用方身份」而非「请求头」。见 §5 假设 A。 |

---

## 2. 网关与服务地图（[实测] + [dex]）

### 2.1 三个网关的分工（[实测]，本轮**首次确认**）

- **GW1 `api-gw-toc.zeekrlife.com`**：只承载 `/zeekrlife-*` 前缀服务。
  本轮把 203 条 `ms-*`/`scenario-*` 路由全量打 GW1，**全部 404**。
- **GW2 `api.zeekrline.com`**：仅 `/remote-control/` 老族（`no Route matched` 对 `ms-*`）。
- **GW3 `snc-tsp-api.zeekrlife.com`**：**所有 `ms-*` / `scenario-*` / `sentinel-*` / `map-*` 微服务**。

### 2.2 微服务清单（[dex]，54 个前缀 / 660 条路由，见 `docs/zeekr_endpoints_full.md`）

控制相关服务的完整路由已入档，含 `ms-remote-control`(10)、`ms-vehicle-status`(6)、
`ms-charge-manage`(12)、`ms-tsp-dkbs-geely`(52 数字钥匙)、`ms-vehicle-defence`(5 电子围栏)、
`ms-vehicle-trail`(5 行程轨迹)、`sentinel-monitoring-service`(6 哨兵)、
`map-d2d-auto-service`(10 高精地图/AVP)、`scenario-personalization`(12 场景编排)、
`scenario-mate-management-service`(2)、`ms-app-bff`(8)。

### 2.3 仍未定位宿主（[实测] GW1/GW2/GW3 全 404）

`ms-vehicle-core`(5)、`ms-iot-control`(2)、`ms-tsp-bks-geely`(9)、`ms-midground-user`(5)、
`snc-remote-config`(2)、`ms-lbs-service`(1)、`ms-user-manager`(1)、`ms-vehicle-guard`(1)、
`ms-vehicle-extend`(1)、`ms-app-online-center`、`ms-app-message-center`、`ms-ai-cloud`、
`ms-iot-status`、`map-service`。

候选主机（[dex] `docs/zeekr_endpoints_full.md` 主机表）：
`gateway-pub.zeekrlife.com`、`gateway-int-test.zeekrlife.com`、`zeekr-m.zeekrlife.com`、
`galaxy-api-gw-toc.geely.com`、`gric-api.geely.com`、`galaxy-user-api.geely.com`、`galaxy-vc.geely.com`。
本轮试了前几个：`gateway-pub` 返回无 `code` 的信封；`m./app.zeekrlife.com` 返回网页（非 API）；
`zeekrgo-api` 返回 `-1`。⇒ **未找到**。

### 2.4 本轮新确认可用的接口（[实测]）

- `POST /ms-tsp-user-setting/api/v1.0/userVeh/setting/query`
  → `{"setting":[{"carName":"小粉","vin":"L6T77HCE9PF081833"}], ...}`
  **价值：拿到 App 侧的车辆昵称，可用于实体命名。**
- `GET /ms-user-auth/api/v1.0/auth/cloud/temp/code` → `{"code":"<32位hex>"}`（扫码/临时码）。
- `GET /map-d2d-auto-service/api/v1/app/preciseMap/city/getAll` → 高精地图覆盖城市全量列表。
- `GET /scenario-mate-management-service/api/v1.0/mate/query/app/all/icon` → 场景图标清单（含 CDN url+md5）。
- `GET /sentinel-monitoring-service/api/v2.0/pic/list` → `0 success`（哨兵图片，参数待补）。
- `POST /ms-vehicle-shares/share-status`，**「唯一标识」参数名 = `traceId`**
  （试了 14 个候选，只有它不报「唯一标识不可为空」）。对应 `GlCarShareLoopReqBean(traceId=)`。

### 2.5 参数名/格式 oracle（[实测]）

| 接口 | 已知参数 | 备注 |
| --- | --- | --- |
| `/zeekrlife-app-user/v1/user/toc/authCodeByServiceCode` | **`scene`** | `{"scene":"1"}` → `300035 不在业务范围!`；场景值 0–60 与关键词全部 300035（[实测]未找到合法值） |
| `/zeekrlife-app-user/v1/user/toc/validateAuthCode` | **`authCode`** + **`scene`** | `scene` 被接受后仅剩「验证码不为空」，验证码字段名待定 |
| `.../vehicle-shares/share-status` | **`traceId`** | |
| `.../journalLog/trackpoint/list` | **`tripReportTime`**，格式 **`yyyyMMdd`** | 格式错 → `param check failed`；格式对 → `079001`（门禁） |
| `/sentinel-monitoring-service/.../alarm/event/query` | **`alarmEndTime`** 已确认；开始时间参数名待定 | `alarmBeginTime` 不被识别（仍报「告警开始时间不能为空」） |
| `/ms-app-bff/api/1.0/permissions` | **`tspPlatform`**，**数字枚举**（`0/1/2` 可过校验） | 字符串 → `param check failed` |
| `/ms-tsp-dkbs-geely/.../key-list` 等 | `signature` + `deviceid`（+`type`） | 数字钥匙族需要 App 侧签名 |

**踩过的坑**：query 值含空格会被 `urllib` 拒绝（`InvalidURL`），需先 `quote`。

---

## 3. 令牌现状与「换令牌」候选链

### 3.1 现有令牌（[实测] 解码 JWT）

```
iss    = https://snc-api-gw-inner.zeekrlife.com/auth-service/inner/v1/oauth/info
aud    = azp = user_center_client_phone      <- 用户中心「手机号登录」客户端
scope  = ""                                   <- 空
sub    = openId = 2068684429979209728
userId = 403215671     sid = <uuid>     RS256 / 1047 字符 / exp 7 天
来源   = POST /ms-user-auth/v1.0/auth/login（body 带 GW1 JWT）
```

### 3.2 候选链（[dex]）

```
场景码 scene ──(zeekrlife-app-user/.../authCodeByServiceCode)──> authCode
        └──> com.geely.snc.login：AuthLoginReqBean(authCode=) ──> AuthLoginRspBean(accessToken=)
                实现：IGLAuthLoginService / GLAuthLoginServiceImpl / GLTokenInterceptor
                配套：RefreshTokenReqBean/RspBean、HFScanLoginReqBean、ScanCodeLoginReqBean
                广播：com.geely.snc.action.login.elsewhere（即「登录被顶替」）
另一条：AccessCodeReq(clientId=) ──> /zeekrlife-mp-auth2/v1/auth/accessCode（动词未知）
车控 SDK（SDK 令牌持有者，[dex]）：com.zeekr.snc.vehicle
        core/net/http/{VclHttpApi,VclHttpUrl,VclHttpUrl$Builder,VclHttpReq,VclHttpParam,VclHttpHeader}
        core/net/mqtt/{VclMqttMsg,VclMqttRsp,VclMqttClient}   <- 还有 MQTT 通道
        iot/GLIotService、iot/utils/IIotTokenHelper、log/ITokenHelper、dlp/dmc/ZeekrDlcTokenHelper
```

**未解决**：`AuthLoginReqBean` 的 HTTP 端点路径未找到（`VclHttpUrl` 是 Java builder，URL 非明文常量）。

---

## 4. 车辆分享（CarShare）状态 — 存在矛盾，待 App 侧核对

[实测]（`16620192335`，车主已表示分享过）：

```
GET vehicle-shares/owner/share-list       -> 000000 ok, total=0
GET vehicle-shares/share/accept-list      -> 000000 ok, total=0
GET vehicle-shares/owner/share-histories  -> 000000 ok, total=0
GET vehicle-shares/share/accept-histories -> 000000 ok, total=0
```

⇒ 服务端视角该号**既非分享方也非被分享方**。两种解释：

1. **[推断] 分享已过期/失效**（App 文案含「授权已过期」「该分享已经失效」「超过最大分享次数」），
   但 TSP 侧绑定仍在 ⇒ 车控可用而分享列表为空；
2. **[推断] 车控来自另一套绑定**（亲情账号 `account/affection`、企业车辆 `enterprise-vehicles`、
   家庭成员），非 vehicle-shares。

**判据（明天第一个动作）**：车主 App →「我分享出去的」那条记录的**状态 / 有效期 / 权限项**截图。

---

## 5. 待验证的两个竞争假设

**假设 A（令牌身份论，我目前更倾向）**
`[SDK]` 白名单比对的是令牌的客户端身份（`azp`/`aud`）。
现有令牌是 `user_center_client_phone` 且 `scope=""`，天然不在白名单。
⇒ 需要走 §3.2 的 SDK 登录换一份 `azp` 为 SDK 客户端的令牌。
支持证据：同一服务内查询接口放行而控制接口被拒，与「账号权限」无关（权限是账号级的，不会按接口分）。

**假设 B（账号权限论）**
`[SDK]` 其实就是「该账号是否对本车具备车控权限」的另一种表述，
而当前账号的权限因**分享过期**已失效，故控制类接口全拒。
⇒ 车主重新分享（并在 App 内接受）后应能解开。

**如何区分（明天，一步到位）**：`tools/zeekr_gate_check.py` 的 22 个门禁项里，
**只要有任何一项从 `079001` 变成其他码**，就是假设 B；**全部仍是 `079001`** 则是假设 A。
该测试**全部只读**，不会动作车。

---

## 6. 明天（2026-09-19）测试计划

### 步骤 0 — 环境自检（1 分钟，无需任何前置动作）

```bash
PY=C:/Users/rexze/.workbuddy/binaries/python/envs/default/Scripts/python.exe
CREDS=C:/Users/rexze/AppData/Local/Temp/zeekr_bak/tokens.json
cd /d/zeekr_ha
$PY tools/zeekr_gate_check.py --creds "$CREDS"          # 只看判定表，不写文件
```

### 步骤 1 — 车主重新分享（需要用户/车主操作）

- 车主 App → 车辆分享 → 分享给 `16620192335`，**权限勾满（含远程控制）**；
- 记录并截图：状态 / 有效期 / 权限项；
- 用 `16620192335` 在 App 登录后**接受**该分享（分享流程是 `创建 → traceId → 轮询`，
  见 §2.4 `share-status` 用 `traceId`）。

### 步骤 2 — 门禁是否解除（关键判定，只读）

```bash
$PY tools/zeekr_gate_check.py --creds "$CREDS" \
    --compare docs/zeekr_gate_baseline.json
```

判读（脚本会自动打印）：

| 结果 | 含义 | 下一步 |
| --- | --- | --- |
| 有门禁项变为「放行/可用」 | 假设 B 成立，权限解开了 | 直接进步骤 3 |
| 22 项仍全部 `079001` | 假设 A 成立 | 转 §3.2 换令牌链 |
| 基线项（`基线:` 前缀）不可用 | 令牌/会话坏了 | 重新短信登录，再重跑 |

基线已就绪：`docs/zeekr_gate_baseline.json`（28 项：22 门禁 / 5 可用 / 1 放行）。

### 步骤 3 — 若门禁解除：验证车辆状态读取（只读）

```bash
$PY tools/zeekr_route_sweep.py --creds "$CREDS" \
    --routes C:/Users/rexze/AppData/Local/Temp/zeekr_ctrl_routes.txt \
    --out docs/zeekr_route_probe_results_after.md --gateways gw3
```
与今夜结果 `docs/zeekr_route_probe_results.md` 对比，一次性看清所有新解锁的接口。

### 步骤 4 — 若状态可读：闭环验证指令（**会动作车，需在场确认**）

- 先用最无害的指令（如闪灯/鸣笛，若接入），再验证 `queryProcessResult(sessionId)` 轮询闭环；
- 注意集成现状是「发完即认为成功」，缺闭环（[历史结论]）。

### 环境与依赖就绪状态（今晚已确认）

| 项 | 状态 |
| --- | --- |
| Python venv（pycryptodome 3.23.0、androguard 4.1.4） | 就绪 |
| 探测工具（复用集成的签名/加密代码） | `tools/zeekr_probe.py` 就绪 |
| 凭据文件 `tokens.json` | 就绪（4459 B） |
| dex 字符串池缓存（32 MB，全部检索毫秒级） | 就绪 `%TEMP%\zeekr_strings.txt` |
| 门禁基线快照 | 就绪 `docs/zeekr_gate_baseline.json` |
| 全量路由清单 | 就绪 `docs/zeekr_endpoints_full.md` |
| 控制平面路由实测表 | 就绪 `docs/zeekr_route_probe_results.md` |
| APK 原件 | 就绪（597 MB） |
| 短信验证码 | **需要用户实时配合**（有效期极短） |

> 说明：写记录时一次网络探测命令的授权弹窗超时（无人确认），其输出被 withheld；
> 该命令的产物 `docs/zeekr_gate_baseline.json` 经校验完整可用（28 项，内容自洽）。
> 后续网络类命令可能需要重新授权，**建议明天先跑步骤 0 确认授权链正常**。

---

## 7. 本轮新增工具（均可复用）

| 工具 | 作用 |
| --- | --- |
| `scratch/dex_strings.py` | 把加固 dex 的字符串池导出为文本（处理 uleb128 长度前缀），一次 40 秒，之后检索毫秒级 |
| `scratch/s.py` | 在该文本上做正则检索 + 邻居上下文（利用字符串池有序性） |
| `scratch/route_inventory.py` | 生成全量服务路由 / 主机 / ARouter 页面清单 |
| `tools/zeekr_route_sweep.py` | 全量路由 × 多网关扫描（**只发 GET**），产出对比用 markdown 表 |
| `tools/zeekr_gate_check.py` | 一键门禁检测 + 与基线对比，门禁解除时以退出码 1 报信 |

---

## 8. 来源清单

- **[实测]** 本机 `tools/zeekr_probe.py` / `zeekr_route_sweep.py` / `zeekr_gate_check.py`
  对 `snc-tsp-api.zeekrlife.com`、`api-gw-toc.zeekrlife.com`、`api.zeekrline.com` 的真实请求。
- **[dex]** APK `com.zeekrlife.mobile.apk` v5.0.5 `classes.dex` 字符串池
  （id 表已被 `libconch` 加固移除，仅字符串数据区明文；结构化解析不可行）。
- **[历史]** `.workbuddy/memory/MEMORY.md`、`.workbuddy/memory/2026-09-1[678].md`、
  `docs/zeekr_app_endpoints.md`。

## 9. 不确定点汇总（逐条可验证）

1. `16620192335` 是否真的曾获得车辆分享、是否已过期 —— 需 App 侧截图（**最高优先**）。
2. `[SDK]` 白名单到底比对什么（客户端身份 vs 账号权限）—— 步骤 2 一次判定。
3. `AuthLoginReqBean` 的 HTTP 端点路径 —— 未找到，需继续逆向（`VclHttpUrl` 是 builder，非明文）。
4. `authCodeByServiceCode` 的合法 `scene` 值域 —— 0–60 与关键词全被拒（`300035`），
   可能该接口对本客户端整体不可用。
5. `validateAuthCode` 的「验证码」字段名 —— 已知 `authCode`/`scene`，第三个字段待定。
6. 哨兵告警查询的「开始时间」参数名 —— 已知 `alarmEndTime`，开始时间待定。
7. 14 个服务（`ms-vehicle-core`、`ms-iot-control`、`ms-tsp-bks-geely` 等）的真实宿主 —— 未找到。
8. 数字钥匙族所需 `signature` / `deviceid` 的算法与来源 —— 疑为 SDK 内部签名。
9. `/ms-remote-control/api/v1.0/...`（带 `api`）与集成现用不带 `api` 的路径是否等价 ——
   两者实测同码，**未定论**，接入前需确认。

---

# 2026-09-18 上午：App 侧证据到手，两个关键事实被推翻/确立

## 用户提供的两张 App 截图（决定性证据）

### 截图 B：`收到的车辆分享`
```
车辆           小粉 / 1833            <- 尾号 1833 = L6T77HCE9PF081833，与本项目 VIN 一致
分享来自账号   酒酿澜澜圆子 / 13874333029   <- 车主账号
分享状态       已接受
分享时间       2026/09/16 01:35
接受时间       2026/09/16 01:35
底部按钮       结束用车
```

**⇒ 车辆分享真实存在且已接受**（2026-09-16 建立）。这与接口侧
`vehicle-shares/{share/accept-list, accept-histories}` 返回 `total=0` **矛盾**，
详见下节推论。

### 截图 A：`爱车提醒`（报警列表）
```
[小粉]执行失败，请重试。请确认车端软件和手机APP版本为最新，若问题仍存在，请联系售后服务
2026-09-17 02:10 / 02:08 / 02:08 / 01:04 / 01:03
```

**⇒ 指令确实被送达车端，车端尝试执行后失败。** 时间窗（09-17 01:03–02:10）
与项目记录中「GW2 `PUT /remote-control/vehicle/telematics/{VIN}` 测 5 组参数变体」
的时段吻合。与历史结论「GW2 回 `1000` 但车不动 ⇒ 病根在车端执行」完全一致。
提示语「请确认车端软件和手机APP版本为最新」暗示**协议版本不匹配**。

## GW1 JWT 解码（本机凭据文件，无需联网）

```
iss=prod   aud=app   exp=1821127660
sub = { accountInfoDTO: { accountId 2068684429979209728, mobile 16620192335,
                          nickname 极氪用户_M1ZT6LbH, city 广州市, 海珠区,
                          buSite 1, channel 3, tenantId 0, registerBusinessType 8352008 },
        accountLoginInfoDTO: {
          agoLoginDeviceName  "iPhone13",  agoLoginAt  1789585388891,
          lastLoginDeviceName "Android SDK built for arm64",
          lastLoginDeviceId   299c9bc6ebe34c8994def00068988006,
          logoutOtherDevices  true            <- 单设备策略，顶号由此而来
        } }
client_id = APPLE0000APP00IPHONE266M14110026      <- 32 字符，iOS 客户端标识
user_id   = 403215671
```

**⇒ `logoutOtherDevices: true` 被服务端确认**，解释了所有 079021「登录被顶替」现象。
**⇒ 我的 `client_id` 是 iOS 的**；账号登录历史里出现过 `iPhone13`，说明用户手机
很可能就是用 `16620192335` 登录的（需用户确认）。

## dex 结构修正（重要）

- **`ControlReqBean(controlType=` / `ControlReqBean15(controlType=` 属于数字钥匙蓝牙协议**
  （`com/geely/snc/digitalkey/base/dk/business/protocol/dk{15,20}/bean/`），
  **不是 HTTP 控制请求体**。此前把它当作 HTTP 请求 Bean 是误判。
- HTTP 控制一族实为：`RemoteControlReq` / **`RemoteControlSetting(serviceParameters=`** /
  `RemoteControlParams(qrInfo=` / `EnergyBaseRequest(serviceId=` /
  `EnergyBaseRequestSetting(serviceParameters=` / **`ControlResult(sessionId=`、
  `ControlResult(iotRemoteControlType=`** / `OperationScheduling(duration=`。
- dex 中**不存在** Android 形态的 client_id（形如 `XXXX0000APP...`）；iOS 那个也不在 dex 里
  ⇒ client_id 由服务端下发（`/zeekrlife-app-user/v1/user/pub/secretConfig` 等）。

## 推论链（当前最可能的完整解释）

1. 账号 `16620192335` 对车辆 `小粉` 具备**已接受的车辆分享**（含车控权限）；
2. App 用该账号可正常进入车辆页并展示「结束用车」，说明**账号权限是有的**；
3. 但本集成走 `/ms-user-auth/v1.0/auth/login` 拿到的 GW3 令牌
   （`azp=user_center_client_phone`、`scope=""`）被 21 个控制类接口以
   `079001 [SDK]此接口未被授权` 拒绝；
4. ⇒ **门禁判定的是「客户端身份」（token 的 azp/aud/scope），与账号车辆权限无关**。
   假设 A 基本坐实，假设 B 被截图 B 直接削弱。

## 仍待用户确认（一个二选一就能定案）

- **在 App 里点一次车控（闪灯/锁车）到底成功吗？**
  - 成功 ⇒ 同一账号、同一手机号，App 能而 API 不能 ⇒ **纯粹是客户端身份问题**，
    必须走抓包拿到 App 用的令牌（`docs/zeekr_capture_playbook.md`）。
  - 也失败（同样「执行失败」）⇒ 病根在**车端执行/协议版本**，
    与令牌无关，方向转为「找出车端接受的指令格式」，抓包同样是第一步。
- 截图是用哪个号码登录看到的？（`16620192335` 还是用户常用号）

---

# 2026-09-18 上午（续）：关键推论 —— 我们的 GW3 登录流程不是 App 的流程

## 推论与证据

把 dex 里 `ms-user-auth` 的**全部 13 条路由**列出来：

```
/ms-user-auth/api/v1.0/account/affection[/unbind]
/ms-user-auth/api/v1.0/auth/cloud/temp/code
/ms-user-auth/api/v1.0/auth/scanLogin
/ms-user-auth/api/v1.0/csp/{relation,resetPassword,user,verification/mobilePhone[/cspmobile]}
/ms-user-auth/api/v1.0/face/{delete,dhu-wakeup,pictureUpload,registered}
```

**里面没有 `/auth/login`。** 而本集成拿 GW3 令牌用的正是
`POST /ms-user-auth/v1.0/auth/login`（body 带 GW1 JWT、`identityType: 5`）。

⇒ **该端点是「能用」，但不是 App 用的那条路。** 它的令牌
（`azp=user_center_client_phone`、`scope=""`）天然不在 `[SDK]` 白名单里。

同族里名字最像「App 取令牌」的是：

```
/ms-midground-user/api/v1.0/user/auth/{get/token, refresh/token, hfScanLogin, cancel/login, logout}
```

本轮对它做了**多路径 × 多网关**矩阵实测（`/api/v1.0/`、`/v1.0/`、去掉 `ms-` 前缀；
GW1 / GW2 / GW3 / `gateway-pub` / `gateway-int-test`）——**全部 404 / 无路由**。
⇒ 宿主仍未定位（疑为 H5/中台侧主机，dex 主机表里暂无匹配）。

## 因此的结论

**抓包从「加速手段」升级为「唯一可行路径」**：只有看到 App 真实的那一次控制请求，
才能知道它（a）打哪个 host/path，（b）带哪份 `Authorization`，（c）带哪些 `X-*` 头，（d）请求体长什么样。
静态手段（字符串池考古 + 端点轰测）已基本挖尽。

## 等待期间已完成的准备

- `tools/zeekr_capture_start.py`：自动探测本机局域网 IP、启动 mitmdump、把手机侧步骤（含 IP）打印出来；
  支持 `--zeekr-only` 只代理极氪域名。
- `docs/zeekr_capture_playbook.md` 新增 **§0.5 方案 0**：手机自带抓包 App（Reqable 等）VPN 模式，
  **不需要电脑、不需要同一网络**，人在外面也能做；只需截图请求头 + 请求体 + 路径给我。
- 明确禁止项：**不要把账号登进模拟器**（`logoutOtherDevices: true`，会顶掉用户手机）。

---

# 2026-09-18 晚：抓包成功 —— 找到 App 真实调用链（重大突破）

用户手机抓包成功（`capture/zeekr-20260918-1925.flow`，54 条请求，1 MB），
操作是「开空调」。**整条链路彻底看清了。**

## 1. App 打的网关不是我们用的那个

```
gric-zhf-api.geely.com      <- 车控 / 车况 / 权限 / 车辆详情 / 能力集（主）
gric-api.geely.com          <- 车辆核心（收藏车辆等）
gric-aic-api.geely.com      <- /think/app/v3/car/function/push
```

**我们集成打的是 `snc-tsp-api.zeekrlife.com`（GW3）** —— 路径几乎一样，但网关不同，
所以那边一律回 `079001 [SDK]此接口未被授权`。

## 2. App 的车控请求（逐字节）

```
POST https://gric-zhf-api.geely.com/ms-remote-control/api/v1.0/remoteControl/control

x-tenant-id: ZEEKR
x-platform: Android
x-sales-platform: ZEEKR
x-device-brand: OPPO
x-device-model: PLJ110
x-device-os-version: Android 16 (API 36)
x-app-version: v1.0.0
x-app-id: GEELYCNCH001M0001              <- 注意不是 ZEEKRCNCH001M0001
accept: application/json; charset=UTF-8
accept-language: zh_CN
authorization: <JWT, azp=auth_client_zeekr_phone>
x-api-signature-version: 2.1
x-api-signature-nonce: 8f2e46d7-9f75-4882-baeb-ea7a2f98a34b
x-timestamp: 1789731095309
x-device-id: 291d2cec-c5c0-43b9-b7f8-8fba770f04ce
x-vehicle-identifier: l1oQt6DQLAWGk8VKjbFBdxXaNr6FhF1h6obO8pgzLw4=     (base64, 32B = AES 加密 VIN)
x-vehicle-brand: ZEEKR
x-vehicle-series: QlgxRQ==               (base64 "BX1E" = 车系代码)
x-tsp-platform: 4                        <- 我们只试过 0/1/2
x-signature: 05yFNewzZJvAl1n8eYtVwUdDGNTHrETRozJ8OWpQf2Y=
content-type: application/json; charset=UTF-8
user-agent: okhttp/4.12.0

请求体（158 B）:
{"command":"","serviceId":"ZAF",
 "setting":{"serviceParameters":[
   {"key":"AC","value":true},
   {"key":"AC.temp","value":"18.0"},
   {"key":"AC.duration","value":20}]}}

响应 200:
{"code":"0","data":{"sessionId":"PF081833000000013109515333902410"},
 "debug":{"bizName":"ms-mobile-adapter-service",...},"msg":"操作成功"}
```

要点：
- 请求体有 **`command: ""`** 这个空字段；
- `serviceParameters` 是 **`{key,value}` 列表**，`value` 类型随键而变（bool / string / number）；
- 响应给出 **`sessionId`**（形如 `PF0818330000000131...`），随后用
  `queryProcessResult` 轮询闭环 —— 与我们此前的推断一致。

## 3. App 的令牌与我们不同

```
aud = azp = auth_client_zeekr_phone          <- 我们的是 user_center_client_phone
iss = https://gric-mid-inner.geely.com/ms-auth-service/inner/v1.0/oauth/info
                                                <- 我们的是 snc-api-gw-inner.../auth-service/...
sub = openId = 2068684429979209728            <- 同一个账号（与我们相同）
userId = 403215671   brand = ZEEKR   env = PROD
deviceId = 291d2cec-c5c0-43b9-b7f8-8fba770f04ce
```

⇒ **同一账号，两份不同客户端身份的令牌。** 我们的 GW3 登录
（`/ms-user-auth/v1.0/auth/login`，dex 里根本没有这个路由）拿到的令牌天然进不了 GRIC/SNC 的白名单。

## 4. 我们离成功只差「两个东西」

**[实测] 我们现有的签名实现（`_sign_gw3` + `_SNC_SECRET`）在 GRIC 上是有效的！**

| 组合 | 结果 | 含义 |
| --- | --- | --- |
| `x-app-id: ZEEKRCNCH001M0001` + 我们的签名 | `00A02 header property 'X-VEHICLE-SERIES' is required` → 补头后变 `00A22 The app information does not exist.` | **签名通过**，只是该 app-id 未在 GRIC 注册 |
| `x-app-id: GEELYCNCH001M0001` + 我们的签名 | `00A06 Signature verification failed.` | 该 app-id 存在，但**密钥与我们的不同** |

⇒ 缺的两样：**① `GEELYCNCH001M0001` 的签名密钥；② `auth_client_zeekr_phone` 那份令牌的来源。**
（`x-vehicle-identifier` 我们也能生成：`_encrypt_vin` 输出同样是 44 字符 base64/32 字节。）

## 5. 密钥不在我们手里的 APK 里

- dex 里只有 **`ZEEKRCNCH001M0000` / `ZEEKRCNCH001M0001` / `ZEEKERCNCH001M0001`**，
  **没有 `GEELYCNCH001M0001`**；
- `_SNC_SECRET` 也不是从 app-id 简单派生（已穷举 md5/sha1/sha256 各种拼法，全不匹配）；
- `secretConfig` 只返回 RSA 公钥，不含签名密钥；
- 抓包里 `x-app-version: v1.0.0`，而我们逆向的 APK 是 **v5.0.5**。

⇒ **用户手机上那个 App 很可能不是我们手里的这一版**
（`x-app-version: v1.0.0` 也可能是 GRIC SDK 自身的版本号，待确认）。

## 下一步（需要用户）

1. **极氪 App 的版本号**（App → 我的 → 设置 → 关于）。
2. **最好能把那个 APK 导出给我**（OPPO 可用「应用管理 → 分享/提取安装包」，或任意 APK 提取器）。
   我会在新 APK 的字符串池里搜 `GEELYCNCH001M0001`，它的邻居极可能就有那把 32 位密钥；
   同时找 `auth_client_zeekr_phone` 对应的登录/换令牌端点。
3. 备选：**再抓一次包含「退出登录 → 重新登录」的抓包**，
   即可完整看到令牌获取链路（当前抓包里令牌是缓存的，没有出现获取过程）。

---

# 2026-09-18 晚（续）：唯一缺口锁定为「`GEELYCNCH001M0001` 的共享密钥」

## 实测矩阵（GRIC 网关，`gric-zhf-api.geely.com/ms-app-bff/api/1.0/permissions?tspPlatform=4`）

| 条件 | 返回 | 判读 |
| --- | --- | --- |
| 无 Authorization | `00A02 header 'AUTHORIZATION' is required` | 头校验在签名校验**之前** |
| 任意编造的 app-id + 我们的签名 | `00A22 The app information does not exist.` | **签名不作为判据**（网关不知道这个 app），只是 app 未注册 |
| `GEELYCNCH001M0001` + 我们的签名 | `00A06 Signature authentication failed.` | 该 app **已注册** ⇒ 网关用**它自己的密钥**校验，我们的不匹配 |
| 同上，签名版本改 1.0 | `00A02 Unsupported signature version` | 只支持 2.0 / 2.1 |

⇒ 结论铁定：**签名算法我们已经实现正确**（此前 ZEEKR app-id 在 GRIC 上通过签名校验就是证明），
**唯一缺的是 `GEELYCNCH001M0001` 那一把共享密钥**。

## 密钥不在客户端静态数据里（已穷尽）

- **整包逐字节扫描**（597 MB，全部 zip 条目）：`GEELYCNCH001M0001` 出现 **0 次**；
  `CNCH` 只有三个变体：`ZEEKRCNCH001M0000` / `ZEEKRCNCH001M0001` / `ZEEKERCNCH001M0001`。
- **97 个 .so 全扫**：只有 `libfq.so` / `libnative-lib.so` 含 `ZEEKR`（人脸 SDK `ZEEKR_FaceID*`），无 app-id 无密钥。
- `libHttpSecretKey.so` 只暴露
  `Java_com_haohan_module_http_encrypt_HttpSecretKey_{get,set}SecretKey` ⇒ **密钥是运行时由 Java 侧 set 进去的**。
- 用户提供的 APK（`C:/Users/rexze/Documents/OPPO 互联/极氪.apk`）与仓库外那份 `Downloads` APK **完全一致**
  （同为 597 MB、同 dex、同 so 清单、同样只有 ZEEKR 变体）⇒ 版本确实是 v5.0.5，不是版本差异问题。
- `_SNC_SECRET` 不是 app-id 派生（md5/sha1/sha256 各类拼法已穷举）。
- 抓包中的 `x-app-version: v1.0.0` 应是 **GRIC SDK 自己的版本号**，不是 App 版本。

## 第二次抓包（退出登录）未取到东西

- 用户反馈「退出登录网络报错」，抓包文件 `capture/zeekr-20260918-1942.flow` 中
  **完全没有 logout / login / token 相关请求**，只有心跳与车况轮询（全 200）。
  ⇒ 报错发生在 App 内部，请求未发出（疑似走 HTTP/3，代理无法拦截）。
- 但即便抓通登录流程，**共享密钥也永远不会出现在流量里**（它是本地常量/运行时下发，随请求只走签名结果）。
  ⇒ 抓登录对「拿密钥」帮助有限，只对「令牌获取链路」有价值。

## 两条可行路线（需用户决策）

**路线 A（低代价、不确定）：清除 App 数据后抓冷启动**
`设置 → 应用管理 → 极氪 → 清除数据`，然后抓包并重新登录。若密钥是**服务端下发**的，
这次会出现下发请求；若是本地常量则什么也看不到。
⚠️ 风险：会清掉 App 本地状态，**若手机上有蓝牙数字钥匙可能需要重新创建**；也会退出登录。

**路线 B（高代价、高确定性）：frida 动态提取**
在 Android 模拟器（可 root）里装 App + frida-server，hook
`HttpSecretKey.getSecretKey` 或签名函数直接 dump 密钥。
不需要登录即可拿到客户端常量；若密钥随登录下发，则需要登录（会顶掉手机，需事后重新登录）。
产出：**一把密钥 + 完整可复现的签名**。

**不可行**：重放抓包中的请求——`x-timestamp` 有有效窗口，只能当次有效，无法支撑 HA 长期使用。

## 已确知、可直接落地的部分（与密钥无关）

App 的完整调用链已经逐字节掌握（网关、路径、全部请求头、`x-vehicle-identifier` 生成方式我们已具备、
请求体结构、响应 `sessionId` 与 `queryProcessResult` 闭环）。**一旦拿到密钥，接入是纯工程工作。**

---

# 2026-09-18 晚（三）：重要更正 + 道路收窄

## 更正：`00A22` 不是「签名通过」，而是「app 未注册，不验签」

用「ZEEKR app-id（密钥已知）」做对照实验，逐一改变**参与签名的头集合**（6 种）× 签名版本（2.0/2.1）：

```
base / base+all-extra / base+tenant+tsp / base+vehicle / base+tenant+tsp+vehicle / all_minus_meta
× ver 2.0 / 2.1   →  12 种组合全部返回 00A22
```

**12 种互斥的规范串不可能同时被接受** ⇒ 网关在校验签名**之前**就返回了 `00A22`。
⇒ 之前「我们的签名在 GRIC 上有效」的判断**作废**。真实语义：

| 返回 | 含义 |
| --- | --- |
| `00A02` | 缺头 / 签名版本不支持（前置校验） |
| `00A22` | **app 未注册** → 直接返回，**不验签** |
| `00A06` | app 已注册 → **验签失败** |

## 密钥不在字符串池（离线暴力已做）

`scratch/key_hunt.py`：以抓包中 App 的 `x-signature` 为目标，用
`_sign_gw3` 的规范串构造 + HMAC-SHA256，对 dex 字符串池 **848,708 个候选 × 3 种大小写** 逐一验证
（含用第二条请求复核的逻辑）→ **未命中**。

⇒ 结合「`GEELYCNCH001M0001` 这个 app-id 本身在整包 0 命中」这一事实，
**该 App 的字符串常量是加密存储的（`libEncryptorP.so`）**，签名密钥大概率同样加密
⇒ **纯静态不可得**。

## 道路收窄（两条重要结论）

1. **模拟器 + frida 基本不可行**：APK 是 **arm64-v8a 单架构**（93 个原生库全 arm64，
   含视频/人脸 SDK），x86_64 模拟器无法原生运行；国产 App 另有模拟器检测。
2. **带代理登录会失败**：用户实测「挂代理网络错误，登录不上」。
   ⇒ 登录链路与车控链路不同，疑似**证书固定 / 代理检测 / HTTP/2 协商**之一。
   `--no-http2` 值得一试（HTTP/2 协商失败是代理场景常见故障点）。

## 当前状态与可选路线

- **已确定可用**：GRIC 网关上 App 的完整调用链（网关/路径/全部请求头/请求体/签名算法框架）。
- **缺口**：`GEELYCNCH001M0001` 的共享密钥（加密常量）。
- 路线：
  - **① 再试一次带代理登录**（`--no-http2`）→ 若通，可看到登录/令牌/可能的密钥下发；
  - **② 手机端抓包 App（Reqable 等，VPN 模式）** → 换一种抓包实现，规避 mitmproxy 被识别/协商失败；
  - **③ 若都不行**：控车路线在当前条件下**不可得**（除非有 root 设备或 ARM 环境可动态提取）。
    此时应把精力转回「已通的只读能力」交付。

---

# 2026-09-18 晚：开源生态突破 —— 静态提取 6 密钥 + 找到海外版完整认证链

## 一、决定性发现：这个问题社区已经解决过

检索公开资料后找到三个直接相关的项目（**说明我们的方向从"逆向猜"变成"照抄已验证的实现"**）：

| 项目 | 价值 |
| --- | --- |
| **`wysie/zeekr_key_extractor`** | 从极氪 APK **静态提取 6 个密钥**的成体工具；**支持 `--region CN`**；新版密钥位于 **`libenv.so` 明文表**（纯静态可提，无需 root/模拟器/frida） |
| **`sunshijiang/zeekr_homeassistant_sun`** | 一个**已支持中国大陆短信登录**的 HA 集成；用 `hmac_access_key`+`hmac_secret_key`，`X-API-SIGNATURE-VERSION: 2.1`，主机 `api-gw-toc.zeekrlife.com` |
| **`nikagl/zeekr_ev_api`** | 海外版 API 库（PyPI `zeekr-ev-api`）；含 **`zeekr_app_sig.py`（X-SIGNATURE 权威实现）** 与 **`zeekr_hmac.py`（X-HMAC 实现）** |

## 二、6 个密钥已成功提取（无 root、无模拟器）

在**我们手上的中国版 APK** 上运行（`--region CN`）：

```bash
python zeekr_extract_secrets.py "C:/Users/rexze/Documents/OPPO 互联/极氪.apk" --region CN
# => All 6 secrets extracted successfully!
```

结果落盘 `C:/Users/rexze/Documents/OPPO 互联/zeekr_secrets.json`：

```
hmac_access_key    = 7dbae691d53f4f3c9fab905368370d80
hmac_secret_key    = hnpigl1f13fcb6a3ac834895b9e403c08cd895ce
password_public_key= MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDENksAVqDoz5SMCZq0bsZwE+I3NjrANyTTwUVSf1+...
prod_secret        = 03d1cd020062469e90ed63416c5c0fda   （另有 ~120 个候选）
vin_key            = 2014052600006128
vin_iv             = aebd1811194e82d9
```

与集成现有常量对比（**都不同**）：

| 用途 | 集成现有 | 提取值 |
| --- | --- | --- |
| X-SIGNATURE 密钥 | `_SNC_SECRET = 890efe3207af95348b95f66b2ee7da04` | `prod_secret = 03d1cd020062469e90ed63416c5c0fda` |
| VIN 加密 | `_AES_KEY=a01a6db985a2f5d4` / `_AES_IV=ed446b8b8845013d` | `vin_key=2014052600006128` / `vin_iv=aebd1811194e82d9` |

依赖：`capstone 5.0.7` + `pyelftools`（已装入 default venv）。

## 三、找到海外版完整认证链（`zeekr_ev_api` 实证）

```
1) 邮箱密码登录        → 用户中心 token
2) GET  user/tspCode                     → tspCode
3) POST ms-user-auth/v1.0/auth/login     → bearer accessToken
        {identifier: tspCode, identityType: 10, loginDeviceId, ...}
4) 用 bearer token 调 ms-vehicle-status / ms-remote-control / ms-charge-manage ...
```

关键点：**中国区集成用的 `identityType: 5` 是「用户中心手机号」令牌，而能调 `ms-*` 的是 `identityType: 10` 的 bearer 令牌**（用 tspCode 换）。
且海外版的业务调用头是 `X-APP-ID: ZEEKRCNCH001M0001` + `X-PROJECT-ID: ZEEKR_SEA` + `X-API-SIGNATURE-VERSION: 2.0`；
**登录用另一套 `DEFAULT_HEADERS`**：`app-code: 32816dbd-...`、`client-id: 1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc`、`appsecret: zeekr_tis`、`appid: TSP`、`msgappid: 11002`。

## 四、本轮实测（全部只读，未做任何车控写操作）

| 测试 | 结果 | 结论 |
| --- | --- | --- |
| **`GET /zeekrlife-app-user/v1/user/tspCode`（GW1）** | **`000009 检测到您的账号在多个设备登录，请重新登录`** | **路由真实存在！**（此前认为"中国区无此路由"是**错误结论**，我们当时试的是别的前缀）。000009 说明会话被顶 |
| `snc-tsp-api` 上 `user/tspCode` 等 6 条候选 | `00A01 404` | 不在 GW3 |
| `/ms-user-auth/v1.0/user/tspCode`（GW3） | `079026 请求不在可访问地址范围` | 路由存在，区域受限 |
| `identityType=10` + identifier∈{空, JWT, openId, 手机号, GW3 token} | **全部 `015013 登录权限校验不正确`** | 10 需要**真实 tspCode**，不是随便填（此前"identityType 只有 5 可用"的结论需修正为"**5 可用是因为参数齐，10 缺 tspCode**"） |
| 对照 `identityType=5` | `000000 ok` + 拿到令牌 | 基线正常 |
| HMAC 头（`X-HMAC-*`）+ CN 密钥打 GRIC / GW1 | GRIC `404`；`api-gw-toc` **`401`** | **HMAC 体系不是我们这两个网关的签名方式** |
| 用 `vin_key/vin_iv` 与 `_AES_KEY/_AES_IV` **解密** App 的 `x-vehicle-identifier` | 两套都得乱码（CBC/ECB/互换均试） | `x-vehicle-identifier` **不是简单 AES(VIN)**（可能含盐/复合串，或第三套密钥） |
| `x-signature` 2.1 **全天量爆破** | `ALLOWED_HEADERS` / `+CN 扩展` / `x_only` / `CN_only` × 12 变体 × **786,079** 候选 ≈ 全部未命中 | GRIC 的签名密钥**不在 APK 明文字符串池**（`libEncryptorP.so` 加密封装），静态不可得 |
| DNS：中国区网关候选 | `cn-snc-tsp-api-gw.*` / `cn-snc-tsp-api.*` **均不解析**；`snc-tsp-api.zeekrlife.com` = 121.43.28.50 正常 | **中国区就是无前缀的 `snc-tsp-api.zeekrlife.com`** |

## 五、下一步（需要一次有效会话，故需用户配合）

新增一键脚本 `tools/zeekr_bearer_chain.py`：

```bash
# 1) 发验证码（用户收到短信）
python tools/zeekr_bearer_chain.py --send-sms --phone 16620192335
# 2) 带验证码跑完整链路
python tools/zeekr_bearer_chain.py --phone 16620192335 --code <6位码>
```

脚本会依次执行：GW1 手机登录 → 提取 JWT → `tspCode` → `identityType:10` 换 bearer → 用 bearer 探 5 个只读接口，
并打印每步原始返回。**判据：任一接口从 `079001` 变为 `000000`/参数级错误 ⇒ 链路成立。**

⚠️ **约束**：一个账号只能在线一个设备。跑脚本期间**请勿在手机上打开极氪 App**（会互相顶），否则链路会在中途断掉。

## 六、待验证事项（更新）

1. **`tspCode` 的获取是否只需 GW1 JWT**：需一次有效登录验证（当前 000009 是因会话被顶）。
2. `identityType: 10` 在中国区是否需要**额外的客户端头**（`app-code`/`client-id`/`appsecret`）——海外版带、我们从未带。
3. 中国区的 `X-PROJECT-ID` 取值（`ZEEKR` / `ZEEKR_CN` / `ZEEKR_SEA`）未知。
4. `x-vehicle-identifier` 的真实构造（非简单 AES(VIN)）。
5. GRIC 的 `x-signature` 密钥（静态不可得；若 GW3+bearer 链路成立则**不再需要**）。
6. 若 GW3+bearer 链路仍不通，备选是 `sunshijiang` 的 HMAC 路线（需先确认其端点是否真可用——该项目的 CN 端点路径是**猜的**，靠 3×3 穷举撞成功）。

---

# 2026-09-18 夜（用户配合实跑）：三处否证 + libenv.so 全解密

## 一、成功拿到的资产

- **GW1 手机验证码登录成功**（验证码是 **4 位**，不是 6 位）。
- **JWT 已缓存**到 `C:/Users/rexze/AppData/Local/Temp/zeekr_jwt.txt`（1842 字符，`Bearer …` 前缀自带），
  由 `tools/zeekr_bearer_chain.py` 写入并复用 ⇒ **后续探测不再需要用户提供验证码**。

## 二、三处否证（都很重要，避免走回头路）

### 1) `tspCode` 中国区路由**不存在**（修正此前的"重大发现"）

带**有效 JWT** 后实测 11 条候选路径，全部是 Spring 原生 404：

```
{"timestamp":"2026-09-18 20:56:52","status":404,"error":"Not Found","path":"/v1/user/tspCode"}
```

`path` 字段显示网关剥掉了 `/zeekrlife-app-user` 前缀 ⇒ 服务在、路由不在。
**结论**：此前看到的 `000009 多设备登录` 只是**网关层的会话失效拦截**（发生在路由解析之前），
**不能作为"路由存在"的证据**。上一轮据此得出的"tspCode 路由存在"是**误判，已作废**。

### 2) `identityType: 10` 中国区**不通**，且与客户端头无关

全矩阵（3 种客户端头集合 × identityType 1–12 × 3 种 identifier = 108 次）：

| 结果 | 说明 |
| --- | --- |
| `identityType=5` → **`000000` + 令牌** | 唯一可用（任何 identifier 都行） |
| `identityType=2` → `015000 参数错误` | 另一个分支 |
| **其余全部 `015013 登录权限校验不正确`** | 含 10 |

三种客户端头（无 / 最小集 / **海外版完整 `DEFAULT_HEADERS`**）结果**逐字节相同**。
⇒ **海外版的 `tspCode + identityType:10` 认证链在中国区不适用**，不是"缺客户端头"。

### 3) `x-signature` 的密钥**静态不可得**（两轮爆破均零命中）

| 轮次 | 候选来源 | 规模 | 结果 |
| --- | --- | --- | --- |
| 1 | dex 明文字符串池 | **786,079** × 48 变体 | 0 命中 |
| 2 | **`libenv.so` 解密字符串** | 215 × 48 变体 | 0 命中 |

变体覆盖：头集合 4 种（`ALLOWED` / `+CN扩展` / 全 `x-*` / 仅CN头）× query 3 种 × 尾部 2 种 × body 2 种。
⇒ 密钥既不在 dex 明文池、也不在 `libenv.so` 的解密区 ⇒ **加密封装**（`libEncryptorP.so` / iWall 白盒），
**纯静态不可得**。

## 三、`libenv.so` 全解密（本轮新增资产）

`libenv.so`（133 KB，ARM64）是 **OLLVM 加密**布局（`EnvTableResolver.looks_like_new_format=False`，
明文字符串只有 165 条全是 JNI 名字）。用 extractor 的 `NativeLibAnalyzer.decrypt_strings()`
（`extended = data + 0x10000` 后按 vaddr XOR）**解密出 91 条字符串**：

**（a）网关主机表——15 环境 × 4 stage**（注意：**全是 `zeekrlife*` / `zeekr.eu` / `zeekr.co.il`，
没有任何 `geely.com` / `gric`**）：

```
f2e-sit / f2e-uat / f2e
gateway-int-test / gateway-int-dev / gateway-int-uat / gateway-pub-uat / gateway-pub
gateway-pub-azure.zeekr.eu / gateway-pub-em / gateway-pub-em.zeekrlife-test
gateway-int-uae-dev / gateway-int-uae-test / gateway-pub-uae-uat
gateway-pub-aws-em-ae / gateway-pub-hw-em-sg(-uat) / gateway-pub-hw-em-mx(-uat)
gateway-pub-*/zom-pay-gateway/zom-pay-core-service/
overseas-dev / overseas-sit / website-eu-uat / www.zeekr.eu / website-em-* / www.zeekr.co.il
```

**（b）密钥表**：22 个 32-hex + 十几条 40 字符 + 2 条特殊字符长串，其中已确认：

```
7dbae691d53f4f3c9fab905368370d80        = hmac_access_key（CN 行）
hnpigl1f13fcb6a3ac834895b9e403c08cd895ce = hmac_secret_key（CN 行）
```

**推论**：`libenv.so` 是**海外环境表**，中国区/GRIC 的配置不在这里 ⇒ 印证 GRIC 属**吉利中台**独立体系。

## 四、当前结论（定案）

1. **App 能控车用的是 GRIC 体系**（`gric-zhf-api.geely.com` + `GEELYCNCH001M0001` + `x-signature` 2.1 +
   `auth_client_zeekr_phone` 令牌），**与我们 GW3 的 `ZEEKR` 体系完全平行**。
2. **GRIC 的签名密钥静态不可得**（两轮爆破 + 整包 + .so 全扫 + libenv 解密区）。
3. **中国区没有 `identityType:10` 通道**（实测），所以"换令牌"这条捷径关闭。
4. ⇒ 要打通控车，**只剩两条路**：
   - **(A) 动态提取**：真机 root + frida hook（`wysie/zeekr_key_extractor` 的 `vin_hook.js` 思路；
     APK 是 **arm64-v8a 单架构**，x86 模拟器跑不动，需要真机或 ARM 环境）。
   - **(B) 完整抓包**：抓一次 **App 冷启动/登录全过程**的包，直接看 GRIC 令牌从哪来
     （此前的障碍是"挂代理就登录不了"，需改用手机端网卡级抓包 App 或 VPN 模式）。

## 五、下一步可自主进行的部分（不需用户）

用缓存的 JWT 继续探测中国区接口面（`zeekrlife-*` 全族、`ms-user-auth` 中国区分支），
寻找能换取 GRIC/中台令牌的入口。命令：

```bash
python tools/zeekr_bearer_chain.py            # 复用缓存 JWT，直接跑 [2]→[4]
python tools/zeekr_probe.py --creds <tokens.json> gw1 GET <path>
```
