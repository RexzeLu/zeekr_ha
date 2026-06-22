"""SMS-based coordinator for Zeekr EV (flows.json API)."""
from __future__ import annotations
import logging
from datetime import timedelta, datetime
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN
from .api_sms import ZeekrSmsApiClient, VehicleWrapper
_LOGGER = logging.getLogger(__name__)
class ZeekrSmsCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, client, entry):
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=timedelta(minutes=5))
        self.client = client
        self.entry = entry
        self.vehicles = []
        self._vehicle_data = {}
        self.latest_poll_time = None
    def get_vehicle_by_vin(self, vin):
        return self.client.get_vehicle_by_vin(vin)
    async def _async_update_data(self):
        try:
            if not self.vehicles:
                try:
                    vlist = await self.client.get_vehicle_list_gw2()
                    vins = [v.get("vin", v.get("VIN", "")) for v in vlist if v.get("vin") or v.get("VIN")]
                    from .api_sms import VehicleWrapper
                    self.vehicles = [VehicleWrapper(v) for v in vins]
                except Exception as exc:
                    _LOGGER.warning("Failed to get vehicle list: %s", exc)
                    return {}
            try:
                await self.client.refresh_gw2()
            except Exception:
                pass
            try:
                await self.client.snc_refresh()
            except Exception:
                pass
            raw_data = await self.client.fetch_status_all()
            self._vehicle_data = raw_data
            transformed = {}
            for vin, vdata in raw_data.items():
                transformed[vin] = self._transform_vehicle_data(vdata)
            self.latest_poll_time = datetime.now().isoformat()
            return transformed
        except Exception as err:
            raise UpdateFailed(f"Zeekr SMS update failed: {err}") from err

    @staticmethod
    def _transform_vehicle_data(vdata):
        # Transform raw API data to match zeekr_ev_api sensor expectations
        import copy
        result = {
            "additionalVehicleStatus": {"electricVehicleStatus": {}, "maintenanceStatus": {}, "climateStatus": {}, "runningStatus": {}},
            "chargingStatus": {},
            "vehicleStatus": {},
        }
        if not vdata:
            return result
        vs = vdata.get("vehicleStatus", vdata)
        if not isinstance(vs, dict):
            return result
        result["vehicleStatus"] = vs
        evs = result["additionalVehicleStatus"]["electricVehicleStatus"]
        ms = result["additionalVehicleStatus"]["maintenanceStatus"]
        cs = result["additionalVehicleStatus"]["climateStatus"]
        rs = result["additionalVehicleStatus"]["runningStatus"]
        ch = result["chargingStatus"]
        for k, v in vs.items():
            kl = k.lower()
            if kl in ("batterylevel", "chargelevel", "soc"):
                evs["chargeLevel"] = v
            elif kl in ("odometer", "mileage"):
                ms["odometer"] = v
            elif kl in ("remainingrange", "estimatedrange", "range"):
                evs["distanceToEmptyOnBatteryOnly"] = v
            elif kl in ("insidetemp", "interiortemperature", "cabin_temp"):
                cs["interiorTemp"] = v
            elif kl in ("outsidetemp", "exteriortemperature"):
                result["vehicleStatus"]["outsideTemp"] = v
            elif kl in ("tripmeter2", "trip2"):
                rs["tripMeter2"] = v
            elif kl in ("avgspeed", "average_speed"):
                rs["avgSpeed"] = v
            elif kl in ("averpowerconsumption", "avg_consumption"):
                evs["averPowerConsumption"] = v
            elif kl in ("chargevoltage", "charging_voltage"):
                ch["chargeVoltage"] = v
            elif kl in ("chargecurrent", "charging_current"):
                ch["chargeCurrent"] = v
            elif kl in ("chargepower", "charging_power"):
                ch["chargePower"] = v
            elif kl in ("chargespeed", "charging_speed"):
                ch["chargeSpeed"] = v
            elif "tyre" in kl or "tire" in kl:
                ms[k] = v
            elif kl in ("distancetoemptyonbattery20soc", "range_20"):
                evs["distanceToEmptyOnBattery20Soc"] = v
            elif kl in ("distancetoemptyonbattery100soc", "range_100"):
                evs["distanceToEmptyOnBattery100Soc"] = v
        return result
