# 极氪 App（com.zeekrlife.mobile v5.0.5）内的服务端路由

来源：官方 APK 的 dex/so/json/xml 字符串表（只读提取，未执行、未修改）。
提取方式：`tools/inspect_apk.py` 之外另用一次性脚本按 `/ms-…` 正则扫描。
这些是**事实**，优先级高于任何推断 —— 改端点前先对照这里。

## 车辆状态
```
/ms-vehicle-status/api/v1.0/vehicle/status/carFridge
/ms-vehicle-status/api/v1.0/vehicle/status/powerMode
/ms-vehicle-status/api/v1.0/vehicle/status/qrvs
/ms-vehicle-status/api/v1.0/vehicle/status/vtm
/ms-vehicle-status/api/v2.0/vehicle/status/latest
/ms-vehicle-status/api/v2.0/vehicle/status/widget
```

## 远程控制
```
/ms-remote-control/api/v1.0/remoteControl/aiClimate
/ms-remote-control/api/v1.0/remoteControl/control
/ms-remote-control/api/v1.0/remoteControl/getOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/queryAiClimate
/ms-remote-control/api/v1.0/remoteControl/queryProcessResult
/ms-remote-control/api/v1.0/remoteControl/setOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/setSmartTemp
/ms-remote-control/api/v1.0/remoteControl/temperature/del/pattern
/ms-remote-control/api/v1.0/remoteControl/temperature/get/pattern
/ms-remote-control/api/v1.0/remoteControl/temperature/save/pattern
```

## 充电
```
/ms-charge-manage/api/v1.0/charge/control
/ms-charge-manage/api/v1.0/charge/getBookingVtm
/ms-charge-manage/api/v1.0/charge/getChargingPlanNew
/ms-charge-manage/api/v1.0/charge/getLatestDischargeSoc
/ms-charge-manage/api/v1.0/charge/getLatestSoc
/ms-charge-manage/api/v1.0/charge/getLatestTravelPlanNew
/ms-charge-manage/api/v1.0/charge/setBookingVtm
/ms-charge-manage/api/v1.0/charge/setChargingPlan
/ms-charge-manage/api/v1.0/charge/setTravelPlan
/ms-charge-manage/api/v2.0/charge/getBookingCharge
/ms-charge-manage/api/v2.0/charge/getTravelPlan
/ms-charge-manage/api/v2.0/charge/setBookingCharge
/ms-charge-manage/api/v2.0/charge/setTravelPlan
```

## 认证 / 用户
```
/ms-user-auth/api/v1.0/account/affection
/ms-user-auth/api/v1.0/account/affection/unbind
/ms-user-auth/api/v1.0/auth/cloud/temp/code
/ms-user-auth/api/v1.0/auth/scanLogin
/ms-user-auth/api/v1.0/csp/relation
/ms-user-auth/api/v1.0/csp/resetPassword
/ms-user-auth/api/v1.0/csp/user
/ms-user-auth/api/v1.0/csp/verification/mobilePhone
/ms-user-auth/api/v1.0/csp/verification/mobilePhone/cspmobile
/ms-user-auth/api/v1.0/face/delete
/ms-user-auth/api/v1.0/face/dhu-wakeup
/ms-user-auth/api/v1.0/face/pictureUpload
/ms-user-auth/api/v1.0/face/registered
```

## 其余（完整清单）
```
/ms-ai-cloud/api/v1.0/material/query
/ms-app-bff/api/1.0/permissions
/ms-app-bff/api/v1.0/certificate-center/getVehicleCertificate
/ms-app-bff/api/v1.0/climate/getScheduleList
/ms-app-bff/api/v1.0/mntmode/authCode/ownerAuthorization
/ms-app-bff/api/v1.0/mntmode/authCode/statusAndVehicleInfo
/ms-app-bff/api/v1.0/remoteControl/getSmartTemp
/ms-app-bff/api/v1.0/remoteControl/queryFreezerData
/ms-app-bff/api/v1.0/remoteControl/queryFridgeData
/ms-app-bff/api/v1.0/remoteControl/queryVehicleFragrance
/ms-app-message-center/api/v1.0/device/upload
/ms-app-online-center/api/v2.0/app/hb
/ms-charge-manage/api/v1.0/charge/control
/ms-charge-manage/api/v1.0/charge/getBookingVtm
/ms-charge-manage/api/v1.0/charge/getChargingPlanNew
/ms-charge-manage/api/v1.0/charge/getLatestDischargeSoc
/ms-charge-manage/api/v1.0/charge/getLatestSoc
/ms-charge-manage/api/v1.0/charge/getLatestTravelPlanNew
/ms-charge-manage/api/v1.0/charge/setBookingVtm
/ms-charge-manage/api/v1.0/charge/setChargingPlan
/ms-charge-manage/api/v1.0/charge/setTravelPlan
/ms-charge-manage/api/v2.0/charge/getBookingCharge
/ms-charge-manage/api/v2.0/charge/getTravelPlan
/ms-charge-manage/api/v2.0/charge/setBookingCharge
/ms-charge-manage/api/v2.0/charge/setTravelPlan
/ms-iot-control/api/v1.0/iotControl/downLink
/ms-iot-control/api/v1.0/iotControl/queryProcessResult
/ms-iot-device/api/v1.0/iot/device
/ms-iot-device/api/v1.0/iot/device/unbind
/ms-iot-device/api/v1.0/iot/product
/ms-iot-device/api/v1.0/iot/product/modelProductList
/ms-iot-status/api/v1.0/iotProperty/batchGetDeviceProperty
/ms-lbs-service/api/v2.0/sendToCar
/ms-log/v2.0/log/upload/getossuploadtoken
/ms-midground-user/api/v1.0/user/auth/cancel/login
/ms-midground-user/api/v1.0/user/auth/get/token
/ms-midground-user/api/v1.0/user/auth/hfScanLogin
/ms-midground-user/api/v1.0/user/auth/logout
/ms-midground-user/api/v1.0/user/auth/refresh/token
/ms-remote-control/api/v1.0/remoteControl/aiClimate
/ms-remote-control/api/v1.0/remoteControl/control
/ms-remote-control/api/v1.0/remoteControl/getOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/queryAiClimate
/ms-remote-control/api/v1.0/remoteControl/queryProcessResult
/ms-remote-control/api/v1.0/remoteControl/setOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/setSmartTemp
/ms-remote-control/api/v1.0/remoteControl/temperature/del/pattern
/ms-remote-control/api/v1.0/remoteControl/temperature/get/pattern
/ms-remote-control/api/v1.0/remoteControl/temperature/save/pattern
/ms-tsp-bks-geely/api/v1.5/digital-key-center/active-blu-key
/ms-tsp-bks-geely/api/v1.5/digital-key-center/auth-blu-key
/ms-tsp-bks-geely/api/v1.5/digital-key-center/create-blu-key
/ms-tsp-bks-geely/api/v1.5/digital-key-center/create-share-key
/ms-tsp-bks-geely/api/v1.5/digital-key-center/key-info
/ms-tsp-bks-geely/api/v1.5/digital-key-center/key-list
/ms-tsp-bks-geely/api/v1.5/digital-key-center/loop-active-status
/ms-tsp-bks-geely/api/v1.5/digital-key-center/reset-blu-key
/ms-tsp-bks-geely/api/v1.5/digital-key-center/update-blu-key
/ms-tsp-dkbs-geely/api/v1.0/app/calibration-info/lynkco-custom-calibration-info
/ms-tsp-dkbs-geely/api/v1.0/app/certificatecenter/create-app-certificate
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/activate-owner-fob-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/auth-blu-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/bind-ccc-id
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/ccc-set-switch-of-approach-unlock
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/ccc-set-switch-of-walk-away-lock
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-owner-fob-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-owner-nfc-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-share-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/destroy-ccc-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-bind-user-list
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-calibration-gears
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-remaining-slot-quantity
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-info
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-linked-share-account
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-list
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-status
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/loop-ccc-report-status
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/loop-key-status
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/pairing-code
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/phonecoef
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/remove-one-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/repush-key-to-vehicle
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/reset-calibration-gears
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-calibration-gear
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-switch-of-approach-unlock
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-switch-of-walk-away-lock
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/share-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/sync-key-list
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unbind-ccc-id
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unlock-owner-nfc-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unpair-ccc-key
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/upload-mobile-brand
/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/write-owner-nfc-key
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/check-device
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/create-owner-icce-key
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/create-share-icce-key
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/loop-icce-key-status
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/push-key
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/remove
/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/upload-calibration-data
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/delete
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-card-status
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-partner-token
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-purchase-authority
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/key-bind
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/set-default-cardface
/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/traffic-card-list
/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/get-ccc-key-list
/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/key-list
/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/sync-key-list
/ms-tsp-user-setting/api/v1.0/userVeh/setting/query
/ms-tsp-user-setting/api/v1.0/userVeh/setting/save
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/cancel
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/check-share
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/details
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/finish
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-cancel
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-finish
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/delete
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-histories
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-list
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/services
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share-keys
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share-status
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-histories
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-list
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/delete
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/reject
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/social-sharing-info
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/upload-base64
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/update-auth
/ms-user-auth/api/v1.0/account/affection
/ms-user-auth/api/v1.0/account/affection/unbind
/ms-user-auth/api/v1.0/auth/cloud/temp/code
/ms-user-auth/api/v1.0/auth/scanLogin
/ms-user-auth/api/v1.0/csp/relation
/ms-user-auth/api/v1.0/csp/resetPassword
/ms-user-auth/api/v1.0/csp/user
/ms-user-auth/api/v1.0/csp/verification/mobilePhone
/ms-user-auth/api/v1.0/csp/verification/mobilePhone/cspmobile
/ms-user-auth/api/v1.0/face/delete
/ms-user-auth/api/v1.0/face/dhu-wakeup
/ms-user-auth/api/v1.0/face/pictureUpload
/ms-user-auth/api/v1.0/face/registered
/ms-user-manager/api/v1.0/user/get/user/info
/ms-vehicle-account/api/v1.0/vehicle-detail
/ms-vehicle-account/api/v2.0/model/series/getAllModelYearStyle
/ms-vehicle-capability-set/api/app/v1/vehicle/capability/available
/ms-vehicle-core/api/v1.0/vehicle/enterprise-vehicles
/ms-vehicle-core/api/v1.0/vehicle/favorite-vehicles
/ms-vehicle-core/api/v1.0/vehicle/set-default-vehicle
/ms-vehicle-core/api/v1.0/vehicle/set-nick-name
/ms-vehicle-core/api/v1.0/vehicle/set-plate-number
/ms-vehicle-defence/api/v1.0/fence/create
/ms-vehicle-defence/api/v1.0/fence/delete
/ms-vehicle-defence/api/v1.0/fence/enable
/ms-vehicle-defence/api/v1.0/fence/page
/ms-vehicle-defence/api/v1.0/fence/update
/ms-vehicle-extend/api/v1.0/car-audit-info/delete-audit-records
/ms-vehicle-guard/api/v1.0/sentinel/queryPhotoList
/ms-vehicle-status/api/v1.0/vehicle/status/carFridge
/ms-vehicle-status/api/v1.0/vehicle/status/powerMode
/ms-vehicle-status/api/v1.0/vehicle/status/qrvs
/ms-vehicle-status/api/v1.0/vehicle/status/vtm
/ms-vehicle-status/api/v2.0/vehicle/status/latest
/ms-vehicle-status/api/v2.0/vehicle/status/widget
/ms-vehicle-trail/api/v1.0/journalLog/delete
/ms-vehicle-trail/api/v1.0/journalLog/mark
/ms-vehicle-trail/api/v1.0/journalLog/onOff
/ms-vehicle-trail/api/v1.0/journalLog/trackpoint/list
/ms-vehicle-trail/api/v1.0/journalLog/trip/listForPage
```

---

# 2026-09-18 补充：dex 加固结论 + 用户/认证服务路由 + 请求 Bean 字段线索

## dex 加固（决定后续所有逆向手段的选择）

`classes.dex`（195 MB）header 被伪造（`endian_tag`/`string_ids_off` 等全是垃圾值，
仅 `file_size` 字段疑似真实 = 175662436，与整包 195141696 之差 ~19.5 MB 疑似壳数据）。
androguard 只能解析出 **45 个壳类**；真实 dex 的 **id 表（string_ids/type_ids/
field_ids/class_defs）不在明文中**（已用「锚点 u32 反查」+「相对基址 Δ 扫描（含 4096
对齐与全量扫描）」两种方法证实）。字符串**数据区明文可读** ⇒ 一切结论只能来自
字符串池（本工具 `tools/inspect_apk.py` 与 `scratch/dex_grep.py`）。
**结构化解析（字段表/注解/字节码）走不通，别再试。**

## 用户/认证服务路由（GW1 `api-gw-toc` 上实测存活）

服务 `zeekrlife-app-user` 在 GW1 上**真实存在**（此前 tspCode 候选 404 只是路径不对）。
实测：`GET /zeekrlife-app-user/v1/user/pub/secretConfig` → `000000`，
返回 RSA **publicKey**（App 的 secret 动态下发，不在 dex 里硬编码）。

关键端点（其余 61 条见会话记录，多为隐私/资料类）：

```
/zeekrlife-app-user/v1/user/pub/sms/authCode           短信验证码
/zeekrlife-app-user/v1/user/pub/login/mobile           手机号登录
/zeekrlife-app-user/v1/user/pub/login/mobile/oneClick  一键登录
/zeekrlife-app-user/v1/user/pub/login/platform
/zeekrlife-app-user/v1/user/pub/secretConfig           RSA 公钥下发（实测 000000）
/zeekrlife-app-user/v1/user/toc/authCodeByServiceCode  按「场景代码」换 authCode（实测 POST {} → 000005 场景代码,不为空）
/zeekrlife-app-user/v1/user/toc/validateAuthCode       （实测 POST {} → 000005 验证码不为空,场景代码,不为空）
/zeekrlife-mp-auth2/v1/auth/accessCode                 （GET 400 / POST 405 ⇒ 动词未知，路由存在）
```

⇒ **存在「场景代码(scene) → authCode → validate」链**，参数名待挖（不是
`serviceCode`）。这是下一个最可能换出 TSP 能力令牌的入口。

## 控制协议的闭环形状（来自 toString 常量）

- `ControlReqBean(controlType=` / `ControlReqBean15(controlType=` —— 控制请求 Bean；
  另有构造签名 `(String×9, List, OperationScheduling, TimerEntity, String)`。
- **`RemoteControlRsp(sessionId=`** ⇒ 控制下发返回 **sessionId**；
  `ControlResult(sessionId=` / `ControlResultBean(code=` + 路由
  `queryProcessResult` ⇒ App 的流程是 **下发 → 拿 sessionId → 轮询执行结果**，
  不是发了就算。我们集成目前只发不等，若 GW2 通道有对应的结果查询接口，
  闭环验证应优先做这个。
- `OperationScheduling(duration=`（构造参数
  `Integer, Long, Boolean, Integer, Integer, Long, Long`）；
  `TimerEntity(timers=`、`TimerInfo(timerId=`。
- 空调：`AiClimateReqBean(dataSource=`（GW3 `aiClimate` 用）、
  `ClimateStatusVo(interiorTemp=`、`SmartTempSettingBean(heat=`。

## serviceId 与参数键（dex 字符串确认）

- **serviceId 全部在 dex 中**：`ZAF`/`RDL`/`RDU`/`RWS`/`RHL`/`RCS`/`RSM`/`PCM`/`RCE`，
  与集成现用一致。
- ZAF 参数键：`AC`（存在）、`AC.temp`、`AC.duration` —— 别的没有。
- **`rce.*` 家族**：`rce.conditioner` `rce.heat` `rce.ventilation` `rce.level`
  `rce.temp`，以及 **`rce.heat.{11,19,21,25,29,31,39}`**、
  **`rce.ventilation.{11,19,21,25,29,31,39}`** —— 数字后缀像是温度/档位枚举，
  用法待定（可能是 `rce.heat` 的取值集合，也可能是组合键）。

---

# 2026-09-18 深夜：GW3 微服务地图 + 「SDK 门禁」真相 + 车辆分享业务域

## 一句话结论

**`079001` 的真相是「SDK 级接口」门禁 —— 卡的是客户端/令牌身份，不是参数。**
同一份 GW3 令牌下，同一服务的「控制类」接口被拒、「查询类」接口放行。
⇒ **GW2 侧继续猜 `serviceParameters` 参数是死路，可正式停止。**

## 实测矩阵（令牌：`azp=aud=user_center_client_phone`、`scope=""`）

| 接口 | 结果 | 判定 |
| --- | --- | --- |
| `POST /ms-remote-control/v1.0/remoteControl/control` | `079001 [SDK]此接口未被授权，无法访问!` | SDK 门禁 |
| `GET /ms-vehicle-status/api/v2.0/vehicle/status/latest` | 同上 | SDK 门禁 |
| `ms-vehicle-status/.../qrvs`、`/vtm`、`/widget` | 同上 | SDK 门禁 |
| `GET /ms-tsp-user-vehicle/.../vehicle-shares/services`、`/check-share` | 同上 | SDK 门禁 |
| `GET /ms-remote-control/v1.0/remoteControl/queryProcessResult` | `000002` sessionId 缺失 | **可用（闭环结果查询！）** |
| `GET ms-tsp-user-vehicle/.../vehicle-shares/{owner/share-list, owner/share-histories, share/accept-list, share/accept-histories}` | `000000 ok`（total=0） | **可用** |
| `POST .../vehicle-shares/{owner/share, update-auth, cancel, share/accept}` | `000002` 分享类型/分享主键不可为空 | 网关放行，参数级校验 |
| `GET /ms-user-auth/api/v1.0/auth/cloud/temp/code` | `000000 ok` | **可用** |
| `POST /ms-user-auth/v1.0/auth/login` | `000000 ok` → 令牌 1047 字符 | 我们现用登录 |

要点：同一服务内「控制被拒 / 查询放行」⇒ 门禁按**接口粒度**（很可能看令牌 azp/scope 或客户端身份），
与 `X-VIN`、`serviceParameters` 无关。

## GW3 令牌声明（实测解码）

```
iss   = https://snc-api-gw-inner.zeekrlife.com/auth-service/inner/v1/oauth/info
aud   = azp = user_center_client_phone     <- 用户中心「手机号登录」客户端
scope = ""                                  <- 空
sub   = openId = 2068684429979209728
userId= 403215671   sid = <uuid>   RS256 / 1047 字符   exp 7 天
```

## 微服务地图（dex 全量枚举 55 个前缀）

```
zeekrlife-bbs-theme(158) zeekrlife-mp-order(92) zeekrlife-mp-integral(64)
zeekrlife-app-user(60)   ms-tsp-dkbs-geely(54)  zeekrlife-config-order(26)
ms-tsp-user-vehicle(21)  ms-charge-manage(15)   zeekrlife-mp-mps(13)  ms-user-auth(13)
scenario-personalization(12) ms-remote-control(11) zeekrlife-mp-cmall(10)
map-d2d-auto-service(10) ms-app-bff(9)  ms-tsp-bks-geely(9)  ms-midground-user(6)
ms-vehicle-status(6)     sentinel-monitoring-service(6) zeekrlife-mp-account(6)
zeekrlife-mp-mkt(6)      zeekrlife-dod-search(5) ms-vehicle-defence(5) ms-vehicle-trail(5)
ms-vehicle-core(5)       zeekrlife-mp-sic(5)    ms-iot-device(4) zeekrlife-mp-sconfig(4)
zeekrlife-mp-auth2(3)    zeekrlife-pricing-order(3) zeekr-ud-ota(3) zeekrlife-mp-achieve(3)
ms-tsp-user-setting(2)   ms-user-manager(2)     snc-remote-config(2) file-service(2)
ms-iot-control(2)        scenario-mate-management-service(2) zeekrlife-mp-osp(2)
journey-statistics-service(1) ms-app-online-center(1) map-service(1) ms-lbs-service(1)
ms-vehicle-guard(1)      ms-ai-cloud(1) ms-app-message-center(1) ms-vehicle-account(1)
ms-vehicle-extend(1)     appconfig(1) ms-iot-status(1) ms-log(1) zeekrlife-mp-store(1)
```

### 控制相关服务的完整路由（dex 原文）

```
# ms-remote-control（10）
/ms-remote-control/api/v1.0/remoteControl/aiClimate        <- 注意带 /api/
/ms-remote-control/api/v1.0/remoteControl/control
/ms-remote-control/api/v1.0/remoteControl/getOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/queryAiClimate
/ms-remote-control/api/v1.0/remoteControl/queryProcessResult   <- 闭环结果查询（实测可用）
/ms-remote-control/api/v1.0/remoteControl/setOxygenSupply
/ms-remote-control/api/v1.0/remoteControl/setSmartTemp
/ms-remote-control/api/v1.0/remoteControl/temperature/{del,get,save}/pattern

# ms-vehicle-status（6）
/ms-vehicle-status/api/v1.0/vehicle/status/{carFridge,powerMode,qrvs,vtm}
/ms-vehicle-status/api/v2.0/vehicle/status/{latest,widget}

# ms-iot-control（2）  <- GW1/GW2/GW3 均 404，宿主未知
/ms-iot-control/api/v1.0/iotControl/downLink
/ms-iot-control/api/v1.0/iotControl/queryProcessResult

# ms-iot-device（4）   /ms-vehicle-core（5，GW1/GW3 均 404）
/ms-iot-device/api/v1.0/iot/{device,device/unbind,product,product/modelProductList}
/ms-vehicle-core/api/v1.0/vehicle/{favorite-vehicles,enterprise-vehicles,set-default-vehicle,set-nick-name,set-plate-number}

# ms-user-auth（13）
/ms-user-auth/api/v1.0/auth/{scanLogin,cloud/temp/code}      <- temp/code 实测 000000
/ms-user-auth/api/v1.0/{account/affection[/unbind],csp/{relation,resetPassword,user,verification/mobilePhone[/cspmobile]}}
/ms-user-auth/api/v1.0/face/{delete,dhu-wakeup,pictureUpload,registered}

# ms-vehicle-defence（电子围栏） / ms-vehicle-guard
/ms-vehicle-defence/api/v1.0/fence/{create,delete,enable,page,update}
/ms-vehicle-guard/api/v1.0/sentinel/queryPhotoList
```

## 车辆分享（CarShare）业务域 —— 一条完整的「合法授权」通道

`ms-tsp-user-vehicle` 上的 REST 全族（dex 原文，21 条）：

```
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share          创建分享
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-list     我分享出去的
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-histories
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/delete
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept         接受分享
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/reject
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/delete
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-list    我收到的分享
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-histories
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/upload-base64
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/social-sharing-info
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share-status
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/details?shareId=
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/services             可分享服务清单（SDK 门禁）
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/check-share          校验被分享账号（SDK 门禁）
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/update-auth          设置分享权限
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/cancel
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/finish
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-cancel
/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-finish
```

App 侧 UI 文案（dex）：侧边栏-车辆分享、创建车分享、接受车分享、拒绝车分享、结束车分享、
设置车分享权限、添加分享账号、校验被分享账号、无法分享给自己、收到的车辆分享、车分享详情、
分享码已复制、超过最大分享次数、分享数字钥匙已存在。

SDK（`com.geely.snc.sdk.carshare`，Geely CarShare SDK）：
`IGLCarShareService` / `GLGeelyCarShareService` 方法：createCarShare、acceptCarShare、rejectCarShare、
cancelCarShare、finishCarShare、updateCarShare、detailsCarShare、onwerListCarShare、
acceptListCarShare、loopCarShareStatus、forceCancelCarShare、forceFinishCarShare、
ownerDeleteCarShare、acceptDeleteCarShare、uploadBase64CarShare、getUrlCarShare、
**queryVehicleServiceList**。
请求 Bean：`GlCarShare{Create,Accept,Reject,Cancel,Finish,Update,Delete,Details,List,Loop,Url,Upload,VerifySharingUser,ForceCancel,ForceFinish}ReqBean`；
响应：`GlCarShare{ServiceList,Condition,Details}RespBean`、`ShareDetailFunctionInfo`、`ServiceListBean`、
`ShareVehVoHF(shareId=`、`VehicleShareBean.kt`。

**实测（本账号 16620192335）**：四个 list 端点全部 total=0 —— 这个号**既不是分享方也不是被分享方**，
所以「非车主却有完整车控」并非来自车辆分享，而是 TSP 侧的直接绑定。

## 两条「换令牌」候选链（当前最高优先级）

1. **场景码 → authCode → SNC 令牌**
   `POST /zeekrlife-app-user/v1/user/toc/authCodeByServiceCode`（实测缺「场景代码」参数，参数名待定）
   → `com.geely.snc.login` 的 `AuthLoginReqBean(authCode=)` → `AuthLoginRspBean(accessToken=)`
   （`IGLAuthLoginService` / `GLAuthLoginServiceImpl` / `GLTokenInterceptor`）。
   佐证：`PhoneModifyAuthCodeReq(scene=` ⇒「场景」就是 authCode 的入参概念；
   `com.geely.snc.action.login.elsewhere` 即我们遇到的「登录被顶替」广播。
2. **`AccessCodeReq(clientId=)` → `/zeekrlife-mp-auth2/v1/auth/accessCode`**（路由存在，动词待定）。

## 车控 SDK（原生层，SDK 令牌持有者）

`com.zeekr.snc.vehicle`：`core/net/http/VclHttpApi|VclHttpReq|VclHttpRsp|VclHttpUrl|VclHttpParam`、
`core/net/mqtt/VclMqttMsg|VclMqttRsp`（**MQTT 通道**）、`core/net/wifi/VclWifiSdk`、
`iot/GLIotService`、`iot/utils/IIotTokenHelper`、`log/ITokenHelper`、`dlp/dmc/ZeekrDlcTokenHelper`、
`utils/ZeekrENVKt`（`getVclCtrlApi$module_vehicle_release`）。
⇒ SDK 令牌很可能经由 **IoT 令牌**体系下发。

## 已收敛的请求头线索（dex 头名池）

`X-TSP-PLATFORM`、`X-REGION-ID`、`X-A-Key`、`X-S-Key`、`X-Key-Token`、`X-APP-KEY`、`X-APIKEY`、
`X-API-SIGNATURE-{NONCE,VERSION}`、`X-HMAC-{ACCESS-KEY,ALGORITHM,DIGEST,SIGNATURE}`、
`X-ENCRYPTION-{KEY,KEY-ID,VERSION}`、`X-Request-CipheredOverlay{Key,IV,Version}`。
