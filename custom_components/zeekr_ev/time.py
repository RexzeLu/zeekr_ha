"""Time platform — charging schedule window."""

from __future__ import annotations

import logging
import re
from datetime import time as dt_time
from typing import Any

from homeassistant.components.time import TimeEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_LOGGER = logging.getLogger(__name__)

_HHMM = re.compile(r"^(\d{1,2}):(\d{2})")


def _parse_hhmm(value: Any) -> dt_time | None:
    if value is None:
        return None
    match = _HHMM.match(str(value).strip())
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        return dt_time(hour=hour, minute=minute)
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "on", "yes")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the time platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [
            ZeekrChargeScheduleTime(coordinator, vin, "charge_start_time",
                                    "充电开始时间", "start_time"),
            ZeekrChargeScheduleTime(coordinator, vin, "charge_end_time",
                                    "充电结束时间", "end_time"),
        ],
    ).start()


class ZeekrChargeScheduleTime(ZeekrEntity, TimeEntity, RestoreEntity):
    """Start / end of the charging schedule."""

    _attr_icon = "mdi:clock-outline"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str, key: str,
                 name: str, field: str) -> None:
        super().__init__(coordinator, vin, key)
        self._attr_name = name
        self._field = field
        self._fallback: dt_time | None = None

    @property
    def native_value(self) -> dt_time | None:
        parsed = _parse_hhmm(self.get("charge_plan", self._field))
        return parsed if parsed is not None else self._fallback

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last is not None and last.state not in (None, "unknown", "unavailable"):
            self._fallback = _parse_hhmm(last.state)

    async def async_set_value(self, value: dt_time) -> None:
        start = self.get("charge_plan", "start_time") or "00:00"
        end = self.get("charge_plan", "end_time") or "06:00"
        command = str(self.get("charge_plan", "command") or "start")
        bc_cycle = _truthy(self.get("charge_plan", "bc_cycle"))
        bc_temp = _truthy(self.get("charge_plan", "bc_temp"))

        new_value = value.strftime("%H:%M")
        if self._field == "start_time":
            start = new_value
        else:
            end = new_value

        await self.coordinator.async_set_charge_plan(
            self.vin, start, end, command, bc_cycle, bc_temp
        )
        self._fallback = value
        self.coordinator.set_optimistic(
            self.vin, "charge_plan", self._field, value=new_value
        )
