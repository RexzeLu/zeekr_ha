"""Datetime platform — departure (travel plan) time."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.datetime import DateTimeEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_LOGGER = logging.getLogger(__name__)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "on", "yes")


def _to_utc(value: Any) -> datetime | None:
    """Convert a gateway timestamp (epoch ms, epoch s or ISO) to UTC datetime."""
    if value is None:
        return None
    if isinstance(value, str) and not value.strip().lstrip("-").isdigit():
        parsed = dt_util.parse_datetime(value)
        return dt_util.as_utc(parsed) if parsed is not None else None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number > 1e11:  # milliseconds
        number = number / 1000.0
    if number <= 0:
        return None
    return dt_util.utc_from_timestamp(number)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the datetime platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrDepartureTime(coordinator, vin)],
    ).start()


class ZeekrDepartureTime(ZeekrEntity, DateTimeEntity, RestoreEntity):
    """Scheduled departure time used by the travel plan."""

    _attr_name = "预约出发时间"
    _attr_icon = "mdi:clock-start"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "departure_time")
        self._fallback: datetime | None = None

    @property
    def native_value(self) -> datetime | None:
        value = _to_utc(self.get("travel_plan", "scheduled_time"))
        return value if value is not None else self._fallback

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        if last is not None and last.state not in (None, "unknown", "unavailable"):
            self._fallback = dt_util.parse_datetime(last.state)

    async def async_set_value(self, value: datetime) -> None:
        aware = dt_util.as_utc(value) if value.tzinfo else dt_util.as_utc(
            value.replace(tzinfo=dt_util.DEFAULT_TIME_ZONE)
        )
        epoch_ms = str(int(aware.timestamp() * 1000))

        command = str(self.get("travel_plan", "command") or "start")
        ac = self.get("travel_plan", "ac")
        ac_preconditioning = _truthy(ac) if ac is not None else True
        steering_wheel_heating = _truthy(
            self.get("travel_plan", "steering_wheel_heat")
        )

        await self.coordinator.async_set_travel_plan(
            self.vin, command, "", epoch_ms, ac_preconditioning,
            steering_wheel_heating,
        )
        self._fallback = aware
        self.coordinator.set_optimistic(
            self.vin, "travel_plan", "scheduled_time", value=epoch_ms
        )
