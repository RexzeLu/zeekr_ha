"""Number platform — charging limit."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberEntity, NumberMode, RestoreNumber
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the number platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrChargingLimitNumber(coordinator, vin)],
    ).start()


class ZeekrChargingLimitNumber(ZeekrEntity, NumberEntity, RestoreNumber):
    """Target state of charge."""

    _attr_name = "充电上限"
    _attr_icon = "mdi:battery-charging-high"
    _attr_native_min_value = 50
    _attr_native_max_value = 100
    _attr_native_step = 5
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_mode = NumberMode.SLIDER

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "charging_limit")
        self._fallback: float | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_number_data()
        if last is not None and last.native_value is not None:
            self._fallback = float(last.native_value)

    @property
    def native_value(self) -> float | None:
        value = self.get("battery", "limit")
        if value is None:
            return self._fallback
        try:
            number = float(value)
        except (TypeError, ValueError):
            return self._fallback
        # Some payloads report the limit as percent*10 (800 -> 80).
        if number > 100:
            number = number / 10.0
        return round(number)

    async def async_set_native_value(self, value: float) -> None:
        await self.send_command(
            "start",
            "RCS",
            {
                "serviceParameters": [
                    {"key": "soc", "value": str(int(round(value * 10)))},
                    {"key": "rcs.setting", "value": "1"},
                    {"key": "altCurrent", "value": "1"},
                ]
            },
        )
        self._fallback = value
        self.coordinator.set_optimistic(
            self.vin, "battery", "limit", value=value
        )
