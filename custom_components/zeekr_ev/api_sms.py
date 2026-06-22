"""Zeekr SMS API client - flows.json based for +86 mainland China login."""
from __future__ import annotations
import hashlib
import hmac
import json
import time
import uuid
from typing import Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
_CA_SECRET = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz09z6e9WOcNq+nUMX8Vq1Xe2EmJxuR3XbtureDCS90dfkok"
_LINE_SECRET = "e83a60805fa54de9bdfcb0f2d6bca757"
_SNC_SECRET = "890efe3207af95348b95f66b2ee7da04"
_AES_KEY = "a01a6db985a2f5d4"
_AES_IV = "ed446b8b8845013d"
def _ts():
    return str(int(time.time() * 1000))
def _nonce():
    import random as _r
    return _r.randrange(0, 10**8)
class VehicleWrapper:
    def __init__(self, vin, data=None):
        self.vin = vin
        self.data = data or {}
class ZeekrSmsApiClient:
    def __init__(self, session):
        self._session = session
        self._device_id = uuid.uuid4().hex
        self._jwt_token = None
        self._access_token = None
        self._refresh_token = None
        self._user_id = None
        self._client_id = None
        self._new_access_token = None
        self._new_refresh_token = None
        self._vehicles = []
        self._vehicle_data = {}
    def set_device_id(self, did):
        self._device_id = did
    def store_tokens(self, data):
        self._jwt_token = data.get("jwt_token") or self._jwt_token
        self._access_token = data.get("access_token") or self._access_token
        self._refresh_token = data.get("refresh_token") or self._refresh_token
        self._user_id = data.get("user_id") or self._user_id
        self._client_id = data.get("client_id") or self._client_id
        self._new_access_token = data.get("new_access_token") or self._new_access_token
        self._new_refresh_token = data.get("new_refresh_token") or self._new_refresh_token
    def get_token_storage(self):
        return {"device_id": self._device_id, "jwt_token": self._jwt_token,
                "access_token": self._access_token, "refresh_token": self._refresh_token,
                "user_id": self._user_id, "client_id": self._client_id,
                "new_access_token": self._new_access_token, "new_refresh_token": self._new_refresh_token}
    def _sign_gw1(self, ts, nonce):
        return hashlib.sha1("".join(sorted([ts, str(nonce), _CA_SECRET])).encode()).hexdigest()
    def _gw1_headers(self):
        ts = _ts()
        nonce = _nonce()
        return {"User-Agent": f"ZeekrLife/4.0.2 (iPhone; iOS 17.4.1; Scale/3.00){self._device_id}",
                "request-original": "zeekr-app", "Accept-Language": "zh-Hans-CN;q=1, en-CN;q=0.9",
                "Content-Type": "application/json", "Accept": "*/*", "x_ca_secret": _CA_SECRET,
                "Version": "2", "WorkspaceId": "prod", "x_ca_key": "APP-SIGN-SECRET-KEY",
                "app_type": "IOS", "app_version": "4.0.2", "phone_model": "iPhone13",
                "phone_version": "17.4.1", "x_gray_code": "gray74", "x_ca_timestamp": ts,
                "x_ca_nonce": str(nonce), "x_ca_sign": self._sign_gw1(ts, nonce),
                "app_code": "toc_ios_zeekrapp", "device_id": self._device_id,
                "Authorization": self._jwt_token or ""}
    async def _gw1(self, method, path, params=None, payload=None):
        url = f"https://api-gw-toc.zeekrlife.com{path}"
        if params:
            url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
        async with self._session.request(method, url, headers=self._gw1_headers(), json=payload) as r:
            return await r.json()
    async def send_sms(self, phone, region="+86"):
        return await self._gw1("GET", "/zeekrlife-app-user/v1/user/pub/sms/authCode",
                               params={"mobile": phone, "x_ca_time": _ts(), "regionCode": region})
    async def sms_login(self, phone, sms_code, region="+86"):
        result = await self._gw1("POST", "/zeekrlife-app-user/v1/user/pub/login/mobile", payload={
            "mobile": phone, "deviceId": self._device_id, "smsCode": sms_code,
            "channel": 2, "x_ca_time": _ts(), "deviceName": "iPhone13",
            "skipSmsCode": "0", "regionCode": region, "ip": "192.168.1.1"})
        if result.get("code") == "000000":
            self._jwt_token = result.get("data", {}).get("jwtToken") or self._jwt_token
        return result
    async def get_access_code(self):
        return await self._gw1("GET", "/zeekrlife-mp-auth2/v1/auth/accessCodeList", params={"envType": 3})
    def _sign_gw2(self, method, path, params, payload, ts, nonce):
        body_b64 = __import__("base64").b64encode(
            hashlib.md5(json.dumps(payload, separators=(",", ":")).encode() if payload else b"").digest()
        ).decode()
        qs_str = "&".join(f"{k}={v}" for k, v in sorted((params or {}).items()))
        s = "\n".join(["application/json;responseformat=3", f"x-api-signature-nonce:{nonce}",
                       "x-api-signature-version:1.0", "", qs_str, body_b64, ts, method.upper(), path])
        return __import__("base64").b64encode(hmac.new(_LINE_SECRET.encode(), s.encode(), hashlib.sha1).digest()).decode()
    def _gw2_headers(self, method, path, params, payload):
        ts = _ts()
        nonce = uuid.uuid4().hex.upper()
        h = {"content-type": "application/json", "x-api-signature-version": "1.0",
             "x-app-id": "ZEEKRAPP", "user-agent": "ZeekrLife/4.0.2 (iPhone; iOS 17.4.1; Scale/3.00)",
             "x-device-model": "iPhone", "x-device-manufacture": "Apple",
             "x-agent-type": "iOS", "x-device-type": "mobile", "platform": "NON-CMA",
             "x-env-type": "production", "accept-language": "zh-Hans-CN;q=1, en-CN;q=0.9",
             "x-agent-version": "17.4.1", "accept": "application/json;responseformat=3",
             "x-device-brand": "Apple", "x-operator-code": "ZEEKR",
             "x-device-identifier": self._device_id, "authorization": self._access_token or "",
             "x-client-id": self._client_id or ""}
        sig = self._sign_gw2(method, path, params, payload, ts, nonce)
        h.update({"x-timestamp": ts, "x-api-signature-nonce": nonce, "x-signature": sig})
        return h
    async def _gw2(self, method, path, params=None, payload=None):
        url = f"https://api.zeekrline.com{path}"
        if params:
            url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
        async with self._session.request(method, url, headers=self._gw2_headers(method, path, params, payload), json=payload) as r:
            return await r.json()
    async def ecar_login(self, auth_code):
        result = await self._gw2("POST", "/auth/account/session/secure", params={"identity_type": "zeekr"}, payload={"authCode": auth_code})
        d = result.get("data", {})
        if d.get("accessToken"):
            self._access_token = d["accessToken"]
            self._user_id = d.get("userId") or self._user_id
            self._client_id = d.get("clientId") or self._client_id
            self._refresh_token = d.get("refreshToken") or self._refresh_token
        return result
    async def refresh_gw2(self):
        if not self._refresh_token:
            return {"error": "no refresh token"}
        result = await self._gw2("PUT", "/auth/account/session/secure", payload={"refreshToken": self._refresh_token})
        d = result.get("data", {})
        if d.get("accessToken"):
            self._access_token = d["accessToken"]
            self._user_id = d.get("userId") or self._user_id
            self._client_id = d.get("clientId") or self._client_id
            self._refresh_token = d.get("refreshToken") or self._refresh_token
        return result
    async def get_vehicle_list_gw2(self):
        result = await self._gw2("GET", "/device-platform/user/vehicle/secure", params={"id": self._user_id or "", "needSharedCar": 1})
        return result.get("data", {}).get("list", [])
    async def get_vehicle_status_gw2(self, vin):
        result = await self._gw2("GET", f"/remote-control/vehicle/status/{vin}", params={"latest": "Local", "target": "basic%2Cmore", "userId": self._user_id or ""})
        return result.get("data", {}).get("vehicleStatus", {})
    @staticmethod
    def _encrypt_vin(vin):
        ct = AES.new(_AES_KEY.encode(), AES.MODE_CBC, _AES_IV.encode()).encrypt(pad(vin.encode(), AES.block_size))
        return __import__("base64").b64encode(ct).decode()
    def _sign_gw3(self, method, path, headers, params, payload):
        SIGNED = {"x-app-id", "content-type", "x-api-signature-nonce", "x-timestamp",
                  "x-api-signature-version", "x-project-id", "authorization", "accept-language", "x-vin", "x-device-id", "x-platform"}
        hp = "".join(f"{k.lower()}:{headers[k]}\n" for k in sorted(k for k, v in headers.items() if k.lower() in SIGNED and v))
        qp = ("&".join(f"{k}={v}" for k, v in sorted((params or {}).items())) + "\n") if params else ""
        ct_val = headers.get("Content-Type", headers.get("content-type", "")).lower() if payload else ""
        b64 = (__import__("base64").b64encode(hashlib.md5(json.dumps(payload, separators=(",", ":")).encode()).digest()).decode() + "\n") if payload and "application/json" in ct_val else ""
        canon = hp + qp + b64 + method.upper() + "\n" + path
        return hmac.new(_SNC_SECRET.encode(), canon.encode(), hashlib.sha256).hexdigest()
    def _gw3_headers(self, method, path, params, payload, extra=None):
        ts = _ts()
        nonce = uuid.uuid4().hex.upper()
        h = {"X-APP-ID": "ZEEKRCNCH001M0000", "X-TIMESTAMP": ts,
             "X-API-SIGNATURE-VERSION": "2.0", "X-SIGNATURE": "",
             "Accept-Language": "zh-CN", "Accept-Encoding": "gzip, deflate, br",
             "Content-Type": "application/json;charset=UTF-8", "X-PROJECT-ID": "ZEEKR",
             "X-P": "iOS", "X-DEVICE-ID": self._device_id, "X-APP-OS-VERSION": "4.9.9",
             "X-PLATFORM": "APP", "X-API-SIGNATURE-NONCE": nonce,
             "User-Agent": "ZeekrLife/2025061706 CFNetwork/3826.500.131 Darwin/24.5.0"}
        if extra:
            h.update(extra)
        sig = self._sign_gw3(method, path, h, params, payload)
        h["X-SIGNATURE"] = sig
        return h
    async def _gw3(self, method, path, params=None, payload=None, extra=None):
        url = f"https://snc-tsp-api.zeekrlife.com{path}"
        if params:
            url += "?" + "&".join(f"{k}={v}" for k, v in params.items())
        async with self._session.request(method, url, headers=self._gw3_headers(method, path, params, payload, extra), json=payload) as r:
            return await r.json()
    async def snc_login(self):
        result = await self._gw3("POST", "/ms-user-auth/v1.0/auth/login",
                                  payload={"loginDeviceType": 1, "identityType": 5, "loginSystem": "ios",
                                           "loginDeviceId": self._device_id, "token": self._jwt_token or "",
                                           "loginPhoneBrand": "Apple"},
                                  extra={"Authorization": self._jwt_token or ""})
        if result.get("code") == "000000":
            d = result.get("data", {})
            self._new_access_token = d.get("accessToken") or self._new_access_token
            self._new_refresh_token = d.get("refreshToken") or self._new_refresh_token
        return result
    async def snc_refresh(self):
        if not self._new_access_token or not self._new_refresh_token:
            return {"error": "no new tokens"}
        result = await self._gw3("POST", "/ms-user-auth/v1.0/auth/refreshToken",
                                  payload={"loginDeviceType": 1, "loginDeviceId": self._device_id,
                                           "loginPhoneBrand": "Apple", "loginSystem": "ios",
                                           "refreshToken": self._new_refresh_token,
                                           "accessToken": self._new_access_token},
                                  extra={"Authorization": self._jwt_token or ""})
        if result.get("code") == "000000":
            d = result.get("data", {})
            self._new_access_token = d.get("accessToken") or self._new_access_token
            self._new_refresh_token = d.get("refreshToken") or self._new_refresh_token
        return result
    async def get_vehicle_list_gw3(self):
        result = await self._gw3("GET", "/ms-app-bff/api/v3.0/veh/vehicle-list",
                                  params={"needSharedCar": "true"},
                                  extra={"Authorization": self._jwt_token or ""})
        return result.get("data", [])
    async def get_vehicle_status_gw3(self, vin):
        evin = self._encrypt_vin(vin)
        result = await self._gw3("GET", "/ms-vehicle-status/api/v1.0/vehicle/status/latest",
                                  params={"latest": "false", "target": "new"},
                                  extra={"X-VIN": evin, "X-APP-ID": "ZEEKRCNCH001M0001",
                                         "Authorization": self._new_access_token or ""})
        return result.get("data", {})
    async def full_login(self, phone, sms_code, region="+86"):
        result = {}
        r1 = await self.sms_login(phone, sms_code, region)
        result["sms_login"] = r1
        if r1.get("code") != "000000":
            return result
        r2 = await self.get_access_code()
        result["access_code"] = r2
        yikat = r2.get("data", {}).get("YIKAT_NEW")
        if not yikat:
            return result
        r3 = await self.ecar_login(yikat)
        result["ecar_login"] = r3
        if not self._access_token:
            return result
        vlist = await self.get_vehicle_list_gw2()
        result["vehicles_gw2"] = vlist
        vins = [v.get("vin", v.get("VIN", "")) for v in vlist if v.get("vin") or v.get("VIN")]
        self._vehicles = [VehicleWrapper(v) for v in vins]
        r4 = await self.snc_login()
        result["snc_login"] = r4
        vlist3 = await self.get_vehicle_list_gw3()
        result["vehicles_gw3"] = vlist3
        return result

    @property
    def logged_in(self):
        return self._jwt_token is not None

    @property
    def username(self):
        return self._device_id[:8] if self._device_id else None

    @property
    def region_code(self):
        return "+86"

    def get_vehicle_list(self):
        return self._vehicles
    def get_vehicle_by_vin(self, vin):
        for v in self._vehicles:
            if v.vin == vin:
                return v
        return None
    async def fetch_status_all(self):
        data = {}
        for v in self._vehicles:
            if not v.vin:
                continue
            try:
                sd = await self.get_vehicle_status_gw3(v.vin)
                if sd:
                    data[v.vin] = sd
                    continue
            except Exception:
                pass
            try:
                sd = await self.get_vehicle_status_gw2(v.vin)
                if sd:
                    data[v.vin] = {"vehicleStatus": sd}
            except Exception:
                pass
        self._vehicle_data = data
        return data
    def get_status_data(self):
        return self._vehicle_data
