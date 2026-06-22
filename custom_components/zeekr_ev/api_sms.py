"""Zeekr SMS API client - flows.json based for +86 mainland China login."""
from __future__ import annotations
import hashlib
import hmac
import json
import time
import uuid
from typing import Any
import asyncio
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
_CA_SECRET = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCz09z6e9WOcNq+nUMX8Vq1Xe2EmJxuR3XbtureDCS90dfkok"
_LINE_SECRET = "e83a60805fa54de9bdfcb0f2d6bca757"
_SNC_SECRET = "890efe3207af95348b95f66b2ee7da04"
_AES_KEY = "a01a6db985a2f5d4"
_AES_IV = "ed446b8b8845013d"
_LOGGER = logging.getLogger(__name__)
def _ts():
    return str(int(time.time() * 1000))
def _nonce():
    import random as _r
    return _r.randrange(0, 10**8)
class VehicleWrapper:
    """Wrapper exposing methods expected by entity platforms.
    Delegates API calls to ZeekrSmsApiClient via HA event loop.
    """

    def __init__(self, vin, data=None, client=None, loop=None, coordinator=None):
        self.vin = vin
        self.data = data or {}
        self._client = client
        self._loop = loop
        self._coordinator = coordinator

    def _run_async(self, coro):
        """Run a coroutine in the HA event loop from a sync context."""
        if self._loop and self._loop.is_running():
            import concurrent.futures
            try:
                return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=30)
            except concurrent.futures.TimeoutError:
                _LOGGER.warning("VehicleWrapper: API call timed out for %s", self.vin)
                return {"error": "timeout"}
        try:
            return asyncio.get_event_loop().run_until_complete(coro)
        except RuntimeError:
            return asyncio.new_event_loop().run_until_complete(coro)

    def do_remote_control(self, command, service_id, setting):
        """Send a remote control command (sync wrapper)."""
        if not self._client:
            return {"error": "no client"}
        return self._run_async(self._client.async_do_remote_control(self.vin, command, service_id, setting))

    def get_status(self):
        if self._coordinator:
            return self._coordinator.data.get(self.vin, {})
        return {}

    def get_charging_status(self):
        if not self._client:
            return {}
        return self._run_async(self._client.async_get_charging_status(self.vin))

    def get_charging_limit(self):
        if not self._client:
            return {}
        return self._run_async(self._client.async_get_charging_limit(self.vin))

    def get_charge_plan(self):
        if self._coordinator:
            return self._coordinator.data.get(self.vin, {}).get("chargePlan", {})
        return {}

    def get_travel_plan(self):
        if self._coordinator:
            return self._coordinator.data.get(self.vin, {}).get("travelPlan", {})
        return {}

    def get_journey_log(self, page_size=50):
        if not self._client:
            return []
        return self._run_async(self._client.async_get_journey_log(self.vin, page_size))

    def set_charge_plan(self, start_time, end_time, command, bc_cycle=False, bc_temp=False):
        if not self._client:
            return
        self._run_async(self._client.async_set_charge_plan(self.vin, start_time, end_time, command, bc_cycle, bc_temp))

    def set_travel_plan(self, command, start_time, scheduled_time, ac_preconditioning=True, steering_wheel_heating=False):
        if not self._client:
            return
        self._run_async(self._client.async_set_travel_plan(self.vin, command, start_time, scheduled_time, ac_preconditioning, steering_wheel_heating))
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


    # ------------------------------------------------------------------
    # Remote control via GW3 (SNCTSP gateway)
    # ------------------------------------------------------------------

    async def async_do_remote_control(self, vin, command, service_id, setting):
        """Send a remote control command via SNCTSP (GW3) gateway."""
        evin = self._encrypt_vin(vin)
        payload = {
            "command": command,
            "serviceId": service_id,
            "serviceParameters": setting.get("serviceParameters", []),
        }
        try:
            result = await self._gw3(
                "POST",
                "/ms-vehicle-control/api/v1.0/vehicle/control",
                payload=payload,
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            if result.get("code") != "000000":
                _LOGGER.warning(
                    "Remote control %s/%s returned %s: %s",
                    service_id, command, result.get("code"), result.get("msg"),
                )
            return result
        except Exception as exc:
            _LOGGER.error("Remote control %s/%s failed: %s", service_id, command, exc)
            return {"error": str(exc)}

    async def async_get_charging_status(self, vin):
        """Fetch charging status via GW3."""
        evin = self._encrypt_vin(vin)
        try:
            result = await self._gw3(
                "GET",
                "/ms-vehicle-status/api/v1.0/vehicle/charging/status",
                params={"latest": "true"},
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            return result.get("data", {})
        except Exception as exc:
            _LOGGER.debug("Failed to fetch charging status for %s: %s", vin, exc)
            return {}

    async def async_get_charging_limit(self, vin):
        """Fetch charging limit via GW3."""
        evin = self._encrypt_vin(vin)
        try:
            result = await self._gw3(
                "GET",
                "/ms-vehicle-status/api/v1.0/vehicle/charging/limit",
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            return result.get("data", {})
        except Exception as exc:
            _LOGGER.debug("Failed to fetch charging limit for %s: %s", vin, exc)
            return {}

    async def async_get_journey_log(self, vin, page_size=50):
        """Fetch journey log via GW3 BFF."""
        evin = self._encrypt_vin(vin)
        try:
            result = await self._gw3(
                "POST",
                "/ms-app-bff/api/v3.0/veh/journey/log",
                payload={"vin": vin, "pageSize": page_size, "loginDeviceType": 1},
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            return result.get("data", {})
        except Exception as exc:
            _LOGGER.debug("Failed to fetch journey log for %s: %s", vin, exc)
            return {}

    async def async_set_charge_plan(self, vin, start_time, end_time, command, bc_cycle=False, bc_temp=False):
        """Set charging plan schedule via GW3."""
        evin = self._encrypt_vin(vin)
        payload = {
            "command": command,
            "startTime": start_time,
            "endTime": end_time,
            "bcCycleActive": bc_cycle,
            "bcTempActive": bc_temp,
        }
        try:
            result = await self._gw3(
                "POST",
                "/ms-app-bff/api/v3.0/veh/charge/plan",
                payload=payload,
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            return result
        except Exception as exc:
            _LOGGER.error("Failed to set charge plan for %s: %s", vin, exc)
            return {"error": str(exc)}

    async def async_set_travel_plan(self, vin, command, start_time, scheduled_time, ac_preconditioning=True, steering_wheel_heating=False):
        """Set travel/departure plan via GW3."""
        evin = self._encrypt_vin(vin)
        payload = {
            "command": command,
            "startTime": start_time,
            "scheduledTime": scheduled_time,
            "ac": "true" if ac_preconditioning else "false",
            "bw": "1" if steering_wheel_heating else "0",
        }
        try:
            result = await self._gw3(
                "POST",
                "/ms-app-bff/api/v3.0/veh/travel/plan",
                payload=payload,
                extra={
                    "X-VIN": evin,
                    "X-APP-ID": "ZEEKRCNCH001M0001",
                    "Authorization": self._new_access_token or "",
                },
            )
            return result
        except Exception as exc:
            _LOGGER.error("Failed to set travel plan for %s: %s", vin, exc)
            return {"error": str(exc)}
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


    @property
    def vin_key(self):
        return _AES_KEY

    @property
    def vin_iv(self):
        return _AES_IV

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



# ------------------------------------------------------------------
# Data normalization: map raw GW3/GW2 fields to expected entity format
# ------------------------------------------------------------------


def _map_ev_status(raw, target):
    """Map electric-vehicle status fields from GW3 -> expected names."""
    mapping = {
        "soc": "chargeLevel",
        "remainKm": "distanceToEmptyOnBatteryOnly",
        "mileage": "distanceToEmptyOnBatteryOnly",
        "mileageAt20Soc": "distanceToEmptyOnBattery20Soc",
        "mileageAt80Soc": "distanceToEmptyOnBattery100Soc",
        "mileageAt100Soc": "distanceToEmptyOnBattery100Soc",
        "remainingChargeTime": "timeToFullyCharged",
        "chargeStatus": "chargerState",
        "chargePlugStatus": "statusOfChargerConnection",
        "averPowerConsumption": "averPowerConsumption",
        "tripMeter2": "tripMeter2",
        "avgSpeed": "avgSpeed",
        "batteryLevel": "chargeLevel",
        "range": "distanceToEmptyOnBatteryOnly",
        "chargerState": "chargerState",
        "statusOfChargerConnection": "statusOfChargerConnection",
    }
    for raw_key, target_key in mapping.items():
        if raw_key in raw and raw[raw_key] is not None:
            target[target_key] = raw[raw_key]


_TYRE_POS_MAP = {
    "FL": "Driver",
    "FR": "Passenger",
    "RL": "DriverRear",
    "RR": "PassengerRear",
}


def _map_tyre_fields(raw, target, prefix, suffix, target_prefix):
    """Map tyre pressure/temp fields with various naming conventions."""
    for pos_suffix, target_pos in _TYRE_POS_MAP.items():
        for sep in ["", "_", "-"]:
            key = f"{prefix}{sep}{pos_suffix}{suffix}"
            if key in raw and raw[key] is not None:
                target[f"{target_prefix}{target_pos}"] = raw[key]
                break
    for pos in ["Driver", "Passenger", "DriverRear", "PassengerRear"]:
        for sep in ["", "_", "-"]:
            key = f"{prefix}{sep}{pos}{suffix}"
            if key in raw and raw[key] is not None:
                target[f"{target_prefix}{pos}"] = raw[key]
                return
    plain_key = prefix + suffix
    if plain_key in raw and raw[plain_key] is not None:
        val = raw[plain_key]
        for pos in ["Driver", "Passenger", "DriverRear", "PassengerRear"]:
            target[f"{target_prefix}{pos}"] = val


def _map_door_fields(raw, target, prefix, target_prefix):
    """Map door-related status fields."""
    for pos_suffix, target_pos in _TYRE_POS_MAP.items():
        for sep in ["", "_"]:
            key = f"{prefix}{sep}{pos_suffix}"
            if key in raw and raw[key] is not None:
                target[f"{target_prefix}{target_pos}"] = raw[key]
                break
    for pos in ["Driver", "Passenger", "DriverRear", "PassengerRear"]:
        for sep in ["", "_"]:
            key = f"{prefix}{sep}{pos}"
            if key in raw and raw[key] is not None:
                target[f"{target_prefix}{pos}"] = raw[key]
                return


def normalize_vehicle_data(raw_data):
    """Normalize raw GW3/GW2 vehicle status data to the format expected by entity platforms.

    The entity platforms (sensor, binary_sensor, lock, etc.) expect data structured
    like what the zeekr_ev_api (email login) library returns.  This function adapts
    the SNCTSP / LINE gateway raw fields to that structure.
    """
    if not raw_data:
        return raw_data or {}

    if any(k in raw_data for k in ("additionalVehicleStatus", "basicVehicleStatus")):
        return raw_data

    n = {}
    avs = {}
    n["additionalVehicleStatus"] = avs

    evs = {}
    avs["electricVehicleStatus"] = evs
    _map_ev_status(raw_data, evs)

    ms = {}
    avs["maintenanceStatus"] = ms
    for raw_key in ("totalOdometer", "odometer", "totalMileage"):
        if raw_key in raw_data and raw_data[raw_key] is not None:
            ms["odometer"] = raw_data[raw_key]
            break
    _map_tyre_fields(raw_data, ms, "tyrePressure", "", "tyreStatus")
    _map_tyre_fields(raw_data, ms, "tyreTemp", "", "tyreTemp")
    _map_tyre_fields(raw_data, ms, "tyrePreWarning", "", "tyrePreWarning")
    _map_tyre_fields(raw_data, ms, "tyreTempWarning", "", "tyreTempWarning")
    _map_tyre_fields(raw_data, ms, "tyreStatus", "", "tyreStatus")
    _map_tyre_fields(raw_data, ms, "tyreTemp", "", "tyreTemp")

    cs = {}
    avs["climateStatus"] = cs
    for raw_key in ("temperatureInside", "interiorTemp", "cabinTemp", "insideTemp"):
        if raw_key in raw_data and raw_data[raw_key] is not None:
            cs["interiorTemp"] = raw_data[raw_key]
            break
    if "acStatus" in raw_data:
        cs["preClimateActive"] = str(raw_data["acStatus"])
    elif "acOn" in raw_data:
        cs["preClimateActive"] = "1" if raw_data["acOn"] else "0"
    elif "preClimateActive" in raw_data:
        cs["preClimateActive"] = raw_data["preClimateActive"]
    for raw_key in ("steerWhlHeatingSts",):
        if raw_key in raw_data:
            cs[raw_key] = raw_data[raw_key]
    for raw_key in ("curtainOpenStatus", "curtainPos"):
        if raw_key in raw_data:
            cs[raw_key] = raw_data[raw_key]
    _map_door_fields(raw_data, cs, "winStatus", "winStatus")
    _map_door_fields(raw_data, cs, "winPos", "winPos")

    dss = {}
    avs["drivingSafetyStatus"] = dss
    for raw_key in ("lockStatus", "centralLockingStatus", "doorLockStatus"):
        if raw_key in raw_data and raw_data[raw_key] is not None:
            dss["centralLockingStatus"] = str(raw_data[raw_key])
            break
    _map_door_fields(raw_data, dss, "doorLockStatus", "doorLockStatus")
    _map_door_fields(raw_data, dss, "doorOpenStatus", "doorOpenStatus")
    for raw_key, target_key in (
        ("trunkStatus", "trunkOpenStatus"),
        ("trunkOpenStatus", "trunkOpenStatus"),
        ("hoodStatus", "engineHoodOpenStatus"),
        ("engineHoodOpenStatus", "engineHoodOpenStatus"),
        ("parkBrakeStatus", "electricParkBrakeStatus"),
        ("electricParkBrakeStatus", "electricParkBrakeStatus"),
        ("chargeLidStatus", "chargeLidDcAcStatus"),
        ("chargeLidDcAcStatus", "chargeLidDcAcStatus"),
    ):
        if raw_key in raw_data and raw_data[raw_key] is not None:
            dss[target_key] = str(raw_data[raw_key])

    rs = {}
    avs["runningStatus"] = rs
    for raw_key in ("tripMeter2", "avgSpeed", "averPowerConsumption"):
        if raw_key in raw_data:
            rs[raw_key] = raw_data[raw_key]

    rcs = {}
    avs["remoteControlState"] = rcs
    for raw_key in ("vstdModeState",):
        if raw_key in raw_data:
            rcs[raw_key] = raw_data[raw_key]

    bvs = {}
    n["basicVehicleStatus"] = bvs
    for raw_key, target_key in (
        ("vehicleState", "usageMode"),
        ("usageMode", "usageMode"),
        ("drivingState", "engineStatus"),
        ("engineStatus", "engineStatus"),
    ):
        if raw_key in raw_data and raw_data[raw_key] is not None:
            bvs[target_key] = str(raw_data[raw_key])

    chs = {}
    n["chargingStatus"] = chs
    for raw_key in ("chargeVoltage", "chargeCurrent", "chargePower", "chargeSpeed"):
        if raw_key in raw_data:
            chs[raw_key] = raw_data[raw_key]
    if "bmsChargeVoltage" in raw_data:
        chs["chargeVoltage"] = raw_data["bmsChargeVoltage"]
    if "bmsChargeCurrent" in raw_data:
        chs["chargeCurrent"] = raw_data["bmsChargeCurrent"]

    return n
