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
from homeassistant.util import dt as dt_util

from .const import DEFAULT_TARGET_TEMP, DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity
from .parser import AC_HIGH_TEMP, AC_LOW_TEMP

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
        # Set only by :meth:`async_set_temperature`, i.e. by a value the user
        # picked here.  A restored state does not count: see
        # :meth:`target_temperature` for why that distinction matters.
        self._user_setpoint = False

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
        """The setpoint the car uploads, ``None`` when it has none.

        This is **the car's own setpoint, not the one remote commands use**:
        a payload taken seconds after the phone had run the AC at LOW, at 23
        and at HIGH in turn — with a fresh ``temperatureUpdateTime`` — still
        reported ``currentTemperature: "28.0"``, while ``interiorTemp`` had
        moved.  A remote setpoint is therefore written to the car but never
        read back, so this value is only a starting point, never an override.

        It also answers ``"0.0"`` whenever the AC is off, which the parser
        maps to ``None`` rather than to a 0 °C setpoint.
        """
        reported = self.get("climate", "target_temp")
        try:
            return float(reported) if reported is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def target_temperature(self) -> float | None:
        """What the AC will be started at.

        A value the user picked here wins, because the car never echoes remote
        setpoints back: preferring the uploaded one made a setpoint chosen in
        Home Assistant snap back to the car's own 28 °C on the next poll, which
        looked exactly like "the temperature never syncs".  Until the user
        picks one, follow the car.
        """
        if self._user_setpoint and self._attr_target_temperature is not None:
            return self._attr_target_temperature
        reported = self._reported_target()
        if reported is not None:
            return reported
        return self._attr_target_temperature

    def _reported_at(self) -> str | None:
        """When the car uploaded the climate block, as a local ISO timestamp."""
        stamp = self.get("climate", "temp_reported_at")
        try:
            millis = int(stamp)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        if millis <= 0:
            return None
        return dt_util.as_local(
            dt_util.utc_from_timestamp(millis / 1000)
        ).isoformat(timespec="seconds")

    @property
    def min_temp(self) -> float:
        """Widen the floor to the App's ``LO`` end, and to whatever the car says.

        The App's picker starts at 16 but has a non-numeric ``LO`` below it, so
        a hard 16 floor made that end unreachable from Home Assistant.
        """
        reported = self._reported_target()
        floor = min(BASE_MIN_TEMP, AC_LOW_TEMP)
        if reported is not None and reported < floor:
            return reported
        return floor

    @property
    def max_temp(self) -> float:
        """Widen the ceiling to the App's ``HI`` end (31 °C has been seen)."""
        reported = self._reported_target()
        ceiling = max(BASE_MAX_TEMP, AC_HIGH_TEMP)
        if reported is not None and reported > ceiling:
            return reported
        return ceiling

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
            # What the car actually sent.  The App's ends of the scale are not
            # numbers ("LO" / "HI"), so this is where a guessed setpoint can be
            # told apart from a real one.
            "car_target_temp_raw": self.get("climate", "target_temp_raw"),
            # When the car last uploaded the climate block.  This is what tells
            # "the car has not uploaded the new setpoint yet" apart from "the
            # integration read the wrong field" — they look identical otherwise.
            "car_temp_reported_at": self._reported_at(),
        }
        if self._user_setpoint:
            attributes["target_temp_source"] = "local"
        elif self._reported_target() is None:
            attributes["target_temp_source"] = "default"
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
        # The car never echoes a remote setpoint back, so this is the only
        # place the choice is recorded — and it now survives every poll.
        self._user_setpoint = True
        # Show the new setpoint at once, and let the store take it back if the
        # car never confirms it.
        self.coordinator.set_optimistic(
            self.vin, "climate", "target_temp", value=float(temperature)
        )
        self.async_write_ha_state()
        # If the AC is already running, push the new setpoint immediately.
        if self.hvac_mode == HVACMode.HEAT_COOL:
            await self.async_set_hvac_mode(HVACMode.HEAT_COOL)
