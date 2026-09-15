"""Climate platform — cabin pre-conditioning."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_LOGGER = logging.getLogger(__name__)

DEFAULT_TARGET_TEMP = 22.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the climate platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrClimate(coordinator, vin)],
    ).start()


class ZeekrClimate(ZeekrEntity, ClimateEntity, RestoreEntity):
    """Cabin air conditioning / pre-conditioning."""

    _attr_name = "空调"
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_hvac_modes = [HVACMode.OFF, HVACMode.HEAT_COOL]
    _attr_min_temp = 16.0
    _attr_max_temp = 30.0
    _attr_target_temperature_step = 0.5
    _attr_icon = "mdi:air-conditioner"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "climate")
        self._attr_target_temperature = DEFAULT_TARGET_TEMP

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None:
            temp = last_state.attributes.get("temperature")
            try:
                if temp is not None:
                    self._attr_target_temperature = float(temp)
            except (TypeError, ValueError):
                pass

    # -- state ------------------------------------------------------------

    @property
    def current_temperature(self) -> float | None:
        value = self.get("climate", "inside_temp")
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def target_temperature(self) -> float | None:
        return self._attr_target_temperature

    @property
    def hvac_mode(self) -> HVACMode | None:
        active = self.get("climate", "ac_on")
        if active is None:
            return None
        return HVACMode.HEAT_COOL if active else HVACMode.OFF

    # -- commands ---------------------------------------------------------

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode == HVACMode.HEAT_COOL:
            duration = self.coordinator.ac_duration
            await self.send_command(
                "start",
                "ZAF",
                {
                    "serviceParameters": [
                        {"key": "AC", "value": "true"},
                        {"key": "AC.temp", "value": str(self._attr_target_temperature)},
                        {"key": "AC.duration", "value": str(duration)},
                    ]
                },
            )
            self.coordinator.set_optimistic(self.vin, "climate", "ac_on", value=True)
        elif hvac_mode == HVACMode.OFF:
            await self.send_command(
                "start", "ZAF", {"serviceParameters": [{"key": "AC", "value": "false"}]}
            )
            self.coordinator.set_optimistic(self.vin, "climate", "ac_on", value=False)
        else:
            _LOGGER.warning("不支持的空调模式: %s", hvac_mode)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temperature = kwargs.get("temperature")
        if temperature is None:
            return
        self._attr_target_temperature = float(temperature)
        self.async_write_ha_state()
        # If the AC is already running, push the new setpoint immediately.
        if self.hvac_mode == HVACMode.HEAT_COOL:
            await self.async_set_hvac_mode(HVACMode.HEAT_COOL)
