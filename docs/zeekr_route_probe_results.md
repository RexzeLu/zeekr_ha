# 控制平面路由实测结果

由 `tools/zeekr_route_sweep.py` 生成（**只发 GET，无写操作**）。
共 203 条路由 × 2 个目标，耗时 54s。

目标：gw1, gw3　VIN: `L6T77HCE9PF081833`

判读：`000000` 可用；`079001` SDK 门禁；`000010` 动词不符（可能是写接口）；
`00A01/404` 该网关无此服务；`000002` 过鉴权、缺参数。

## file-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/file-service/api/v5/file/path/apply` | 404 | 34A02 Supported HTTP methods:POST. |

## map-d2d-auto-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/map-d2d-auto-service/api/v1/app/avp/carLocation` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/avp/recover` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/avp/rtc/getRtcInfo` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/avp/start` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/preciseMap/city/getAll` | 404 | 000000 success |
| `/map-d2d-auto-service/api/v1/app/preciseMap/conf/get` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/preciseMap/downloadPath/get` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/preciseMap/map2station/query` | 404 | 67A02 Supported HTTP methods:POST. |
| `/map-d2d-auto-service/api/v1/app/preciseMap/parking/list` | 404 | 67A01 Unknown error. |
| `/map-d2d-auto-service/api/v1/app/station/connectors/query` | 404 | 67A02 Supported HTTP methods:POST. |

## map-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/map-service/api/v2.0/location-share/send2car` | 404 | 00A01 404 Not Found |

## ms-ai-cloud

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-ai-cloud/api/v1.0/material/query` | 404 | 00A01 404 Not Found |

## ms-app-bff

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-app-bff/api/v1.0/certificate-center/getVehicleCertificate` | 404 | 000010 method not allowed |
| `/ms-app-bff/api/v1.0/climate/getScheduleList` | 404 | 00A01 404 Not Found |
| `/ms-app-bff/api/v1.0/mntmode/authCode/ownerAuthorization` | 404 | 000010 method not allowed |
| `/ms-app-bff/api/v1.0/mntmode/authCode/statusAndVehicleInfo` | 404 | 000010 method not allowed |
| `/ms-app-bff/api/v1.0/remoteControl/getSmartTemp` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-app-bff/api/v1.0/remoteControl/queryFreezerData` | 404 | 00A01 404 Not Found |
| `/ms-app-bff/api/v1.0/remoteControl/queryFridgeData` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-app-bff/api/v1.0/remoteControl/queryVehicleFragrance` | 404 | 079001 [SDK]此接口未被授权，无法访问! |

## ms-app-message-center

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-app-message-center/api/v1.0/device/upload` | 404 | 00A01 404 Not Found |

## ms-app-online-center

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-app-online-center/api/v2.0/app/hb` | 404 | 00A01 404 Not Found |

## ms-charge-manage

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-charge-manage/api/v1.0/charge/control` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v1.0/charge/getBookingVtm` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-charge-manage/api/v1.0/charge/getLatestDischargeSoc` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-charge-manage/api/v1.0/charge/getLatestSoc` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-charge-manage/api/v1.0/charge/getLatestTravelPlanNew` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-charge-manage/api/v1.0/charge/setBookingVtm` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v1.0/charge/setChargingPlan` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v1.0/charge/setTravelPlan` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v2.0/charge/getBookingCharge` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-charge-manage/api/v2.0/charge/getTravelPlan` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v2.0/charge/setBookingCharge` | 404 | 000010 method not allowed |
| `/ms-charge-manage/api/v2.0/charge/setTravelPlan` | 404 | 000010 method not allowed |

## ms-iot-control

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-iot-control/api/v1.0/iotControl/downLink` | 404 | 00A01 404 Not Found |
| `/ms-iot-control/api/v1.0/iotControl/queryProcessResult` | 404 | 00A01 404 Not Found |

## ms-iot-device

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-iot-device/api/v1.0/iot/device` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-iot-device/api/v1.0/iot/device/unbind` | 404 | 000010 method not allowed |
| `/ms-iot-device/api/v1.0/iot/product` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-iot-device/api/v1.0/iot/product/modelProductList` | 404 | 079001 [SDK]此接口未被授权，无法访问! |

## ms-iot-status

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-iot-status/api/v1.0/iotProperty/batchGetDeviceProperty` | 404 | 00A01 404 Not Found |

## ms-lbs-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-lbs-service/api/v2.0/sendToCar` | 404 | 00A01 404 Not Found |

## ms-log

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-log/v2.0/log/upload/getossuploadtoken` | 404 | 000002 The request parameter deviceId is missing or empty |

## ms-midground-user

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-midground-user/api/v1.0/user/auth/cancel/login` | 404 | 00A01 404 Not Found |
| `/ms-midground-user/api/v1.0/user/auth/get/token` | 404 | 00A01 404 Not Found |
| `/ms-midground-user/api/v1.0/user/auth/hfScanLogin` | 404 | 00A01 404 Not Found |
| `/ms-midground-user/api/v1.0/user/auth/logout` | 404 | 00A01 404 Not Found |
| `/ms-midground-user/api/v1.0/user/auth/refresh/token` | 404 | 00A01 404 Not Found |

## ms-remote-control

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-remote-control/api/v1.0/remoteControl/aiClimate` | 404 | 000010 method not allowed |
| `/ms-remote-control/api/v1.0/remoteControl/control` | 404 | 000010 method not allowed |
| `/ms-remote-control/api/v1.0/remoteControl/getOxygenSupply` | 404 | 00A01 404 Not Found |
| `/ms-remote-control/api/v1.0/remoteControl/queryAiClimate` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-remote-control/api/v1.0/remoteControl/queryProcessResult` | 404 | 000002 The request parameter sessionId is missing or empty |
| `/ms-remote-control/api/v1.0/remoteControl/setOxygenSupply` | 404 | 000010 method not allowed |
| `/ms-remote-control/api/v1.0/remoteControl/setSmartTemp` | 404 | 000010 method not allowed |
| `/ms-remote-control/api/v1.0/remoteControl/temperature/del/pattern` | 404 | 00A01 404 Not Found |
| `/ms-remote-control/api/v1.0/remoteControl/temperature/get/pattern` | 404 | 00A01 404 Not Found |
| `/ms-remote-control/api/v1.0/remoteControl/temperature/save/pattern` | 404 | 00A01 404 Not Found |

## ms-tsp-bks-geely

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/active-blu-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/auth-blu-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/create-blu-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/create-share-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/key-info` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/key-list` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/loop-active-status` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/reset-blu-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-bks-geely/api/v1.5/digital-key-center/update-blu-key` | 404 | 00A01 404 Not Found |

## ms-tsp-dkbs-geely

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-tsp-dkbs-geely/api/v1.0/app/calibration-info/lynkco-custom-calibration-info` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/certificatecenter/create-app-certificate` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/activate-owner-fob-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/auth-blu-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/bind-ccc-id` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/ccc-set-switch-of-approach-unlock` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/ccc-set-switch-of-walk-away-lock` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-owner-fob-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-owner-nfc-key` | 404 | 00A29 操作太频繁，请稍后重试 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/create-share-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/destroy-ccc-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-bind-user-list` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-calibration-gears` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/get-remaining-slot-quantity` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-info` | 404 | 000002 钥匙ID不能为空,手机品牌不能为空,deviceid不能为空,手机型号不能为空,signature不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-linked-share-account` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-list` | 404 | 000002 signature不能为空,deviceid不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/key-status` | 404 | 000002 钥匙ID不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/loop-ccc-report-status` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/loop-key-status` | 404 | 000002 钥匙ID不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/pairing-code` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/phonecoef` | 404 | 000002 手机型号不能为空,手机品牌不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/remove-one-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/repush-key-to-vehicle` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/reset-calibration-gears` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-calibration-gear` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-switch-of-approach-unlock` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/set-switch-of-walk-away-lock` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/share-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/sync-key-list` | 404 | 000002 signature不能为空,deviceid不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unbind-ccc-id` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unlock-owner-nfc-key` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/unpair-ccc-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/upload-mobile-brand` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center/write-owner-nfc-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/check-device` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/create-owner-icce-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/create-share-icce-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/loop-icce-key-status` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/push-key` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/remove` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/icce-key/upload-calibration-data` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/delete` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-card-status` | 404 | 000002 deviceid不能为空,signature不能为空,type不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-partner-token` | 404 | 000002 signature不能为空,deviceid不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/get-purchase-authority` | 404 | 000002 deviceid不能为空,signature不能为空 |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/key-bind` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/set-default-cardface` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v1.0/app/traffic-card/traffic-card-list` | 404 | 00A01 404 Not Found |
| `/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/get-ccc-key-list` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/key-list` | 404 | 000010 method not allowed |
| `/ms-tsp-dkbs-geely/api/v2.0/app/digital-key-center/sync-key-list` | 404 | 000010 method not allowed |

## ms-tsp-user-setting

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-tsp-user-setting/api/v1.0/userVeh/setting/query` | 404 | 000010 method not allowed |
| `/ms-tsp-user-setting/api/v1.0/userVeh/setting/save` | 404 | 000010 method not allowed |

## ms-tsp-user-vehicle

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/cancel` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/check-share` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/details` | 404 | 000002 The request parameter shareId is missing or empty |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/finish` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-cancel` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/force-finish` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/delete` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-histories` | 404 | 000000 ok |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-list` | 404 | 000000 ok |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/services` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share-keys` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share-status` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-histories` | 404 | 000000 ok |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-list` | 404 | 000000 ok |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/delete` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/reject` | 404 | 000010 method not allowed |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/social-sharing-info` | 404 | 00A01 404 Not Found |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/upload-base64` | 404 | 00A01 404 Not Found |
| `/ms-tsp-user-vehicle/api/v1.0/vehicle-shares/update-auth` | 404 | 000010 method not allowed |

## ms-user-auth

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-user-auth/api/v1.0/account/affection` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/account/affection/unbind` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/auth/cloud/temp/code` | 404 | 000000 ok |
| `/ms-user-auth/api/v1.0/auth/scanLogin` | 404 | 000010 method not allowed |
| `/ms-user-auth/api/v1.0/csp/relation` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/csp/resetPassword` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/csp/user` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/csp/verification/mobilePhone` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/csp/verification/mobilePhone/cspmobile` | 404 | 00A01 404 Not Found |
| `/ms-user-auth/api/v1.0/face/delete` | 404 | 000010 method not allowed |
| `/ms-user-auth/api/v1.0/face/dhu-wakeup` | 404 | 000010 method not allowed |
| `/ms-user-auth/api/v1.0/face/pictureUpload` | 404 | 000010 method not allowed |
| `/ms-user-auth/api/v1.0/face/registered` | 404 | 079001 [SDK]此接口未被授权，无法访问! |

## ms-user-manager

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-user-manager/api/v1.0/user/get/user/info` | 404 | 00A01 404 Not Found |

## ms-vehicle-account

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-account/api/v1.0/vehicle-detail` | 404 | 079001 [SDK]此接口未被授权，无法访问! |

## ms-vehicle-core

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-core/api/v1.0/vehicle/enterprise-vehicles` | 404 | 00A01 404 Not Found |
| `/ms-vehicle-core/api/v1.0/vehicle/favorite-vehicles` | 404 | 00A01 404 Not Found |
| `/ms-vehicle-core/api/v1.0/vehicle/set-default-vehicle` | 404 | 00A01 404 Not Found |
| `/ms-vehicle-core/api/v1.0/vehicle/set-nick-name` | 404 | 00A01 404 Not Found |
| `/ms-vehicle-core/api/v1.0/vehicle/set-plate-number` | 404 | 00A01 404 Not Found |

## ms-vehicle-defence

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-defence/api/v1.0/fence/create` | 404 | 000010 method not allowed |
| `/ms-vehicle-defence/api/v1.0/fence/delete` | 404 | 000002 Fence ID cannot be empty! |
| `/ms-vehicle-defence/api/v1.0/fence/enable` | 404 | 000002 围栏ID不能为空!,状态不能为空! |
| `/ms-vehicle-defence/api/v1.0/fence/page` | 404 | 000010 method not allowed |
| `/ms-vehicle-defence/api/v1.0/fence/update` | 404 | 000010 method not allowed |

## ms-vehicle-extend

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-extend/api/v1.0/car-audit-info/delete-audit-records` | 404 | 00A01 404 Not Found |

## ms-vehicle-guard

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-guard/api/v1.0/sentinel/queryPhotoList` | 404 | 00A01 404 Not Found |

## ms-vehicle-status

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-status/api/v1.0/vehicle/status/carFridge` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-vehicle-status/api/v1.0/vehicle/status/powerMode` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-vehicle-status/api/v1.0/vehicle/status/qrvs` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-vehicle-status/api/v1.0/vehicle/status/vtm` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-vehicle-status/api/v2.0/vehicle/status/latest` | 404 | 079001 [SDK]此接口未被授权，无法访问! |
| `/ms-vehicle-status/api/v2.0/vehicle/status/widget` | 404 | 079001 [SDK]此接口未被授权，无法访问! |

## ms-vehicle-trail

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/ms-vehicle-trail/api/v1.0/journalLog/delete` | 404 | 000002 The request parameter tripReportTime is missing or empty |
| `/ms-vehicle-trail/api/v1.0/journalLog/mark` | 404 | 00A01 404 Not Found |
| `/ms-vehicle-trail/api/v1.0/journalLog/onOff` | 404 | 000010 method not allowed |
| `/ms-vehicle-trail/api/v1.0/journalLog/trackpoint/list` | 404 | 000002 The request parameter tripReportTime is missing or empty |
| `/ms-vehicle-trail/api/v1.0/journalLog/trip/listForPage` | 404 | 000010 method not allowed |

## scenario-mate-management-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/scenario-mate-management-service/api/v1.0/mate/query/app/all/function` | 404 | 24A02 Supported HTTP methods:POST. |
| `/scenario-mate-management-service/api/v1.0/mate/query/app/all/icon` | 404 | 000000 success |

## scenario-personalization

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/scenario-personalization/api/v1.0/app/user/scenario/get-detail` | 404 | 34A02 Missing required request parameters:scenarioCode. |
| `/scenario-personalization/api/v1.0/app/user/scenario/get-template` | 404 | 34A02 Missing required request parameters:scenarioCode. |
| `/scenario-personalization/api/v1.0/app/user/scenario/query` | 404 | 34S16 Headers x-ota-version不能为空 |
| `/scenario-personalization/api/v1.0/app/user/scenario/sort` | 404 | 34A02 Supported HTTP methods:POST. |
| `/scenario-personalization/api/v1.0/app/user/scenario/template/list` | 404 | 34S16 Headers x-ota-version不能为空 |
| `/scenario-personalization/api/v1.0/share/scenario-cancel` | 404 | 34A02 Missing required request parameters:shareCode. |
| `/scenario-personalization/api/v1.0/user/scenario/auto-switch` | 404 | 34A02 Missing required request parameters:scenarioCode. |
| `/scenario-personalization/api/v1.0/user/scenario/delete` | 404 | 34A02 Supported HTTP methods:DELETE. |
| `/scenario-personalization/api/v1.0/words/app/check` | 404 | 34A02 Supported HTTP methods:POST. |
| `/scenario-personalization/api/v2.0/app/user/scenario/save-batch` | 404 | 34A02 Supported HTTP methods:POST. |
| `/scenario-personalization/api/v2.0/share/app-scenario-addition` | 404 | 34A02 Missing required request parameters:shareCode. |
| `/scenario-personalization/api/v2.0/share/scenario/app-share` | 404 | 34A02 Supported HTTP methods:POST. |

## sentinel-monitoring-service

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/sentinel-monitoring-service/api/v2.0/alarm/event/launchUploadVideo` | 404 | 56A02 Supported HTTP methods:POST. |
| `/sentinel-monitoring-service/api/v2.0/alarm/event/query` | 404 | 56A02 告警开始时间不能为空,告警结束时间不能为空 |
| `/sentinel-monitoring-service/api/v2.0/alarm/live/app/getToken` | 404 | 56A02 Supported HTTP methods:POST. |
| `/sentinel-monitoring-service/api/v2.0/alarm/live/app/launchLive` | 404 | 0 success |
| `/sentinel-monitoring-service/api/v2.0/pic/enhancePic` | 404 | 56A02 Supported HTTP methods:POST. |
| `/sentinel-monitoring-service/api/v2.0/pic/list` | 404 | 0 success |

## snc-remote-config

| 路由 | gw1 | gw3 |
| --- | --- | --- |
| `/snc-remote-config/api/v1.0/remote/config/getUnlockStatus` | 404 | 00A01 404 Not Found |
| `/snc-remote-config/api/v1.0/remote/config/setUnlockStatus` | 404 | 00A01 404 Not Found |
