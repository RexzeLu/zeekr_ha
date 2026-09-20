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

from .const import DEFAULT_TARGET_TEMP, DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_LOGGER = logging.getLogger(__name__)

# The range the climate entity offers.  It is *not* the range the car accepts:
# the App happily sets 31 °C, and a hard 30 °C ceiling silently clamped the
# car's own setpoint (and blocked it in the UI).  The entity therefore widens
# itself to cover whatever the car reports -- see ``min_temp`` / ``max_temp``.
BASE_MIN_TEMP = 16.0
BASE_MAX_TEMP = 30.0


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
    _attr_min_temp = BASE_MIN_TEMP
    _attr_max_temp = BASE_MAX_TEMP
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

    def _reported_target(self) -> float | None:
        """The setpoint the car itself reports, ``None`` when it has none.

        The cloud does hold it (``currentTemperature``), but answers ``"0.0"``
        whenever the AC is off — which the parser maps to ``None`` rather than
        to a 0 °C setpoint.
        """
        reported = self.get("climate", "target_temp")
        try:
            return float(reported) if reported is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def target_temperature(self) -> float | None:
        """Prefer the setpoint the car reports, fall back to the last one used.

        Reading straight from local state instead made the entity show its own
        stale default while the app showed the real setpoint.
        """
        reported = self._reported_target()
        if reported is not None:
            return reported
        return self._attr_target_temperature

    @property
    def min_temp(self) -> float:
        """Widen the floor if the car reports a setpoint below it."""
        reported = self._reported_target()
        if reported is not None and reported < BASE_MIN_TEMP:
            return reported
        return BASE_MIN_TEMP

    @property
    def max_temp(self) -> float:
        """Widen the ceiling if the car reports a setpoint above it (31 °C)."""
        reported = self._reported_target()
        if reported is not None and reported > BASE_MAX_TEMP:
            return reported
        return BASE_MAX_TEMP

    @property
    def hvac_mode(self) -> HVACMode | None:
        active = self.get("climate", "ac_on")
        if active is None:
            return None
        return HVACMode.HEAT_COOL if active else HVACMode.OFF

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Surface the run time the next start will carry.

        The car stops the AC by itself after ``AC.duration``, so this is the
        number that decides when — and it is otherwise only visible on the
        separate number entity.
        """
        attributes: dict[str, Any] = {
            "duration_minutes": self.coordinator.ac_duration,
            # Which of the two sources the setpoint came from.  When the car
            # stops reporting one, the entity falls back to its own memory and
            # this says so, instead of the value just silently freezing.
            "car_target_temp": self._reported_target(),
        }
        if self._reported_target() is None:
            attributes["target_temp_source"] = "local"
        else:
            attributes["target_temp_source"] = "car"
        return attributes

    # -- commands ---------------------------------------------------------

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode == HVACMode.HEAT_COOL:
            await self.coordinator.async_set_climate(
                self.vin,
                enabled=True,
                # Whatever is on display, not the entity's own default: the
                # car holds its own setpoint, and sending the default instead
                # overwrote whatever had been set from the app.
                temperature=self.target_temperature,
                # Whatever the number entity holds; the option default if never
                # touched.  The car ends pre-conditioning by itself when it runs out.
                duration=self.coordinator.ac_duration,
            )
        elif hvac_mode == HVACMode.OFF:
            await self.coordinator.async_set_climate(self.vin, enabled=False)
        else:
            _LOGGER.warning("不支持的空调模式: %s", hvac_mode)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temperature = kwargs.get("temperature")
        if temperature is None:
            return
        self._attr_target_temperature = float(temperature)
        # Show the new setpoint at once, and let the store take it back if the
        # car never confirms it.
        self.coordinator.set_optimistic(
            self.vin, "climate", "target_temp", value=float(temperature)
        )
        self.async_write_ha_state()
        # If the AC is already running, push the new setpoint immediately.
        if self.hvac_mode == HVACMode.HEAT_COOL:
            await self.async_set_hvac_mode(HVACMode.HEAT_COOL)
