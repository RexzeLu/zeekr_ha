# 排查与内部实现（开发者向）

面向读代码/调协议的人。日常使用请看 [README](../README.md)。

## 网关

| 网关 | 地址 | 签名 | 用途 |
| --- | --- | --- | --- |
| GW1 | `api-gw-toc.zeekrlife.com` | SHA1 排序签名 | 短信验证码、手机号登录（JWT） |
| GW2 | `api.zeekrline.com` | HMAC-SHA1 | 换取 ecar accessToken、车辆列表/状态、指令回退 |
| GW3 | `snc-tsp-api.zeekrlife.com` | HMAC-SHA256 + AES 加密 VIN | 登录、车辆列表、最新状态、远程控制 |
| GRIC | `gric-api.geely.com` / `gric-zhf-api.geely.com` | HMAC-SHA256（18 头 + 查询串 + 方法 + 路径） | **独立第二条通道**：换令牌、车况、远程控制 |

GRIC 与 SNC 字段习惯不同：车况 `v2.0`（SNC `v1.0`）、充电上限按**十分位**（`950`=95%）、
坐标已是十进制度数、锁定字段 `0`=未锁 / 非零=已锁 —— 已在解析层统一规范化。

### GRIC 签名

密钥 `e70024ed24bda3cbd4a6295ed3fac5aa`（App `mmkv/ble_sdk` 的 `dkAppSecret`），
签名类 `com.geely.snc.network.http.biz.interceptor.GLSignInterceptor`。基串：

```
18 个白名单头（按名升序 "name:value\n"）
+ [查询串 "k=v&…" 按 key 升序 + "\n"]      ← 必须在 METHOD 之前
+ [base64(md5(body)) + "\n"]               ← 仅 POST/有 body
+ METHOD + "\n" + PATH(纯路径)
→ base64(HMAC-SHA256(key, base))
```

**查询串放在 path 之后会一律回 `00A06`**（老坑）。GET 不带 body 哈希那一行。
18 头白名单：accept-language, authorization, x-api-signature-nonce, x-api-signature-version,
x-app-id, x-app-version, x-device-brand, x-device-id, x-device-model, x-device-os-version,
x-platform, x-sales-platform, x-tenant-id, x-timestamp, x-tsp-platform, x-vehicle-brand,
x-vehicle-identifier, x-vehicle-series（`accept` / `user-agent` 会发送但不签名）。

### 令牌（GRIC）

`iss=https://gric-mid-inner.geely.com/ms-auth-service/inner/v1.0/oauth/info`，
`aud=azp=auth_client_zeekr_phone`，RS256；access 7 天 / refresh 30 天。
`POST gric-api.geely.com/ms-midground-user/api/v1.0/user/auth/refresh/token`
body `{"refreshToken":"…"}` → `code:"0"` + 新 access **和新 refresh**（服务端轮换，`sid` 不变）。
⇒ ≤7 天刷一次 = 无限续期；集成侧 `_REFRESH_MARGIN_SECONDS=24h`，轮询即心跳。

⚠️ 会话单一持有者：每次轮换作废同会话其它令牌 ⇒ 谁最后刷谁拥有，另一方收 `00A17`。
**严禁再打 `logout` / `cancel/login`**。

## 远程控制

`POST /ms-remote-control/v1.0/remoteControl/control`，`serviceParameters` **嵌在 `setting` 里**：

```json
{"command": "start", "serviceId": "ZAF",
 "setting": {"serviceParameters": [{"key": "AC", "value": "true"}]}}
```

`serviceId`：空调 `ZAF`、锁 `RDL`、解锁 `RDU`、车窗天窗遮阳帘 `RWS`、鸣笛闪灯 `RHL`、
充电 `RCS`、寻车 `PCM`。被拒时回退 GW2 `PUT /remote-control/vehicle/telematics/{VIN}`。
两条通道的尝试都记进诊断 `gateways.command_attempts`。

GRIC 重试间隔更宽（10/30/60/120/170 秒）—— 中台唤醒并回报实测约 120 秒。

## 诊断文件里有什么

- `payload_summary` —— 每个关键值的**字段溯源**（`path` 为 `null` 即该别名没匹配上，补 `_ALIAS`）
- `vehicle_list_raw` —— 车辆列表原始条目（车辆名/车牌取错时比对字段名）
- `config_entries` —— 本 HA 全部极氪配置项（id、标题、`last_update_success`、手机号后四位、VIN）
- `entities` / `devices` —— 实体/设备注册表快照，含 `restored` 标记
- `gateways` —— 各通道返回码、`command_attempts`、`gw3_token_source`、
  `gw3_vin_attempts`、`platform_chain`、`status_source`、`vehicle_list_source`、`endpoint_probe`
- `report_age_seconds` —— 当前这份状态已经陈了多久

## 字段校准结论（真实报文核对，`BX1E` + `DC1E`）

| 字段 | 结论 |
| --- | --- |
| 动力电池 SOC | `electricVehicleStatus.chargeLevel`（**不是** `maintenanceStatus.mainBatteryStatus.chargeLevel`，那是 12V 电瓶） |
| 12V 电瓶 | `maintenanceStatus.mainBatteryStatus.chargeLevel` / `.voltage` |
| 续航 | `electricVehicleStatus.distanceToEmptyOnBatteryOnly`（实测 321 km，与 App 一致） |
| 胎压 | `maintenanceStatus.tyreStatus{Driver,Passenger,DriverRear,PassengerRear}`，kPa |
| 坐标量纲 | 定点整数，实测「度 × 3,600,000」；解析器自动探测 3.6e6 / 1e7 / 1e6 / 已是度数 |
| 定位可信 | `basicVehicleStatus.position.posCanBeTrusted`（熄火停放常为 false，只作属性） |
| 锁车 | `*LockStatus*` 系列：`0`=未锁，非 `0`=已锁 |
| 充电口盖 | `chargeLidAcStatus` / `chargeLidDcAcStatus`：`1`=打开，`0`/`2`=关闭 |
| 是否在充电 | **主车况自带**：`chargeSts` / `chargerState` / `statusOfChargerConnection` / `dcChargeSts`；`chargeUAct`（电压）、`chargeIAct`（电流） |
| 预计充满 | `timeToFullyCharged`，空闲哨兵值 `2047` → 未知 |
| 遮阳帘 / 天窗 | `curtainPos` / `sunroofPos` / `sunCurtainRearPos` = `101` ⇒ 本车未配备（实体显示不可用） |
| 车型名称 | 列表里的 `modelName` 是目录配置名、**不可靠**（四座四驱极氪 X 实测返回 `四座后驱版-001`）；显示名改按 `seriesCodeVs`：`BX1E`→极氪 X、`DC1E`→极氪 001 |

待实测：`_CHARGING_ACTIVE` / `_CHARGING_IDLE` 码集合（只观测到 `chargeSts=0`）、
哨兵模式 `RSM` 开关取值、`relHumSts`（出现过 `103`，超出湿度范围按未知处理）。

设备名按 `昵称 → 车牌 → 车型` 取第一个非空值，全空才退回 VIN（`"plateNo": ""` 视为没有）。

## `079001 此接口未被授权`（短信通道）

两代登录接口发的令牌权限不同：`identityType: 5` + GW1 JWT（旧）只能访问车辆列表等；
`identityType: 10` + `tspCode`（新平台）才能进车辆状态与远程控制。0.3.21 起集成在
**第一次遇到 `079001` 时**自动补一次新平台登录（`/user/tspCode?tspClientId=…` → 以
`identityType: 10` 再登录），每进程只做一次。0.3.24 起还会试几种身份取值
（GW1 JWT / GW2 令牌 / clientId / userId），判定标准是「车辆接口是否放行」。

已证伪、别再加回来：`X-API-SIGNATURE-VERSION: 2.1`、`X-PROJECT-ID: ZEEKR_CN`、
以及两者同时（真机都回 `079001`，说明判定不由请求头驱动）；
主机名 `gateway-pub-hw-em-cn` / `-em` / `-cn`（中国区根本无法解析）。

`X-VIN` 编码候选的应答含义：`079001` = 令牌代际不对或账号无权；
`079025 Decrypt X-VIN failed` = 发的不是密文；`00A02 validation failed` = 值太短
（网关要求 ≥17 字符，正好是 VIN 长度）⇒ 必须放 **VIN 的密文**，放 `userVehId` 那条路已被否掉。

诊断里的 `endpoint_probe` 会直接问网关两件事：权限边界在哪（三条请求逐个记应答）、
`X-VIN` 该放什么（依次试 `aes(vin)`、`aes(userVehId)`、`userVehId`、`aes(temId)`、
`aes-ecb(vin)`、`aes-zeroiv(vin)`、明文 VIN；被接受的候选会被采用，
`vehicle_token_source` 写成 `probe:...`）。明文 VIN 与对照项 `control:zero-ciphertext`
只用于划边界，标了 `adopt=False`，绝不会被采用。

## `079025 Signature authentication failed`（GW3）

三个已修正的成因：① `X-APP-ID` 用错（GW3 所有端点含登录都必须 `ZEEKRCNCH001M0001`）；
② 签名应是 HMAC-SHA256 的 **Base64**（44 字符），曾输出 hex；③ 请求体序列化必须逐字节一致
（`_json_body` 紧凑 JSON + `data=`）。请求头已对齐 App 抓包（`X-APP-OS-VERSION`、
`User-Agent`、`Content-Type` 空格、nonce 带横线 UUID、登录不带 `Authorization` 但带 `X-VIN`、
query 的 `*`→`%2A`）。仍失败时看诊断 `gateways.gw3_last_rejected`。

## GRIC 报错码

| 码 | 含义 |
| --- | --- |
| `00A06` | 验签失败（查询串位置 / 头列表） |
| `00A02` | 缺 `x-vehicle-identifier`（或 `X-VIN` 太短） |
| `00A06 Decrypt X-VEHICLE-IDENTIFIER failed` | 标识值不是该车的密文 |
| `00A17` | 已在别处登录（会话被顶） |
| `1000P001` / `1000P004` | 参数缺 / 方法不允许 |
| `1018P061` | refreshToken 过期或吊销 |
| `1051P004` / `1051N001` | 参数不正确 / 内部错误（`queryProcessResult` 恒定此值，非公开路径） |
| `000002` | 通过但缺参数 |
| `code:"0"` | 通过 |

## 代码结构

- `parser.py` 容错解析与字段规范化（两通道共用，对外输出统一结构）
- `api_sms.py` / `api_gric.py` 两条通道，暴露**同一组方法**（`async_get_vehicle_list` /
  `get_vehicle_status` / `async_do_remote_control` / …）
- `coordinator.py` 轮询（`polling.py` 自适应退避）、下发指令、乐观更新
- `entity.py` + `VehicleEntityManager`（车辆出现后自动补建实体）
- `__init__.py` 按 `auth_method` 工厂选择客户端 ⇒ 协调器与各平台不需要知道走哪条通道

## 工具（仓库内，不随集成发布）

`tools/zeekr_gric_verify.py` 只读探针（打印车辆列表/车况）·
`tools/zeekr_gric_control.py` 真车车控（裸跑只列命令表，有安全门）·
`tools/zeekr_gric_token.py` 令牌 `show/refresh/ensure` + `form`（导出表单两值）·
`tools/zeekr_device_pull.py` root 手机只读拉取（不触发重登）·
`tools/hexgrep.sh` 内存 hex 搜索 · `tools/generate_brand_images.py` 生成 brand 图标。
