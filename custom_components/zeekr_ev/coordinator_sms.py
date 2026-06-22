"""SMS-based coordinator for Zeekr EV (flows.json API)."""
from __future__ import annotations
import logging
from datetime import timedelta, datetime
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN
from .api_sms import ZeekrSmsApiClient, VehicleWrapper, normalize_vehicle_data
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
        """Return a VehicleWrapper with references to client, loop and coordinator."""
        vw = self.client.get_vehicle_by_vin(vin)
        if vw:
            vw._client = self.client
            vw._loop = self.hass.loop
            vw._coordinator = self
        return vw
    async def _async_update_data(self):
        try:
            if not self.vehicles:
                try:
                    vlist = await self.client.get_vehicle_list_gw2()
                    vins = [v.get("vin", v.get("VIN", "")) for v in vlist if v.get("vin") or v.get("VIN")]
                    from .api_sms import VehicleWrapper
                    self.vehicles = [VehicleWrapper(v, client=self.client, loop=self.hass.loop, coordinator=self) for v in vins]
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
            data = await self.client.fetch_status_all()
            # Normalize raw GW3/GW2 data to the structure expected by entity platforms
            normalized = {}
            for vin, raw in data.items():
                normalized[vin] = normalize_vehicle_data(raw)
            self._vehicle_data = normalized
            self.latest_poll_time = datetime.now().isoformat()
            return normalized
        except Exception as err:
            raise UpdateFailed(f"Zeekr SMS update failed: {err}") from err
