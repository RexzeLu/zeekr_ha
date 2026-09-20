"""Number platform — charging limit and climate run time."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberMode, RestoreNumber
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, MAX_DURATION, MIN_DURATION
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
        lambda vin: [
            ZeekrChargingLimitNumber(coordinator, vin),
            ZeekrAcDurationNumber(coordinator, vin),
        ],
    ).start()


class ZeekrChargingLimitNumber(ZeekrEntity, RestoreNumber):
    """Target state of charge.

    ``RestoreNumber`` already extends ``NumberEntity``; listing both would make
    the MRO inconsistent.
    """

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


class ZeekrAcDurationNumber(ZeekrEntity, RestoreNumber):
    """How long the *next* climate start runs, in minutes.

    The App asks for a duration every time you start the cabin AC, and it stops
    on its own when it elapses.  Here that used to live only in the integration
    options: invisible on the device page and impossible to vary per call, so
    the car always got the same number.

    This is a **setting, not a command** — changing it talks to nobody.  It only
    decides what ``AC.duration`` the next ``climate.set_hvac_mode`` carries,
    which is why it must not call ``send_command``.
    """

    _attr_name = "空调运行时长"
    _attr_icon = "mdi:timer-outline"
    _attr_native_min_value = MIN_DURATION
    _attr_native_max_value = MAX_DURATION
    _attr_native_step = 1
    _attr_native_unit_of_measurement = UnitOfTime.MINUTES
    _attr_mode = NumberMode.BOX

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "ac_duration")

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        # Restore what the user last picked; otherwise the option default stands.
        last = await self.async_get_last_number_data()
        if last is not None and last.native_value is not None:
            self.coordinator.set_ac_duration(int(last.native_value))

    @property
    def native_value(self) -> float | None:
        return float(self.coordinator.ac_duration)

    async def async_set_native_value(self, value: float) -> None:
        self.coordinator.set_ac_duration(int(round(value)))
        self.async_write_ha_state()
