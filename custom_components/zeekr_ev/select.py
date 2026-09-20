"""Select platform — seat heating and ventilation levels."""

from __future__ import annotations

from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

OPTION_OFF = "关闭"
OPTION_1 = "1档"
OPTION_2 = "2档"
OPTION_3 = "3档"
OPTIONS = [OPTION_OFF, OPTION_1, OPTION_2, OPTION_3]

OPTION_TO_LEVEL = {OPTION_OFF: 0, OPTION_1: 1, OPTION_2: 2, OPTION_3: 3}
LEVEL_TO_OPTION = {level: option for option, level in OPTION_TO_LEVEL.items()}

# (entity key, name, ZAF service code, mode, position)
#
# The names share a 座椅 *prefix* on purpose.  Home Assistant lists a device's
# entities alphabetically by name and offers no way to set their order, so the
# name is the only lever there is.  Without the shared prefix these six were
# scattered between unrelated controls (充电…, 除霜…, 车窗…) because their
# first characters sort all over the place.
SEAT_SPECS = (
    ("seat_heat_driver", "座椅 · 主驾加热", "SH.11", "heat", "fl"),
    ("seat_heat_passenger", "座椅 · 副驾加热", "SH.19", "heat", "fr"),
    ("seat_heat_rear_left", "座椅 · 左后加热", "SH.21", "heat", "rl"),
    ("seat_heat_rear_right", "座椅 · 右后加热", "SH.29", "heat", "rr"),
    ("seat_vent_driver", "座椅 · 主驾通风", "SV.11", "vent", "fl"),
    ("seat_vent_passenger", "座椅 · 副驾通风", "SV.19", "vent", "fr"),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the select platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [
            ZeekrSeatSelect(coordinator, vin, *spec) for spec in SEAT_SPECS
        ],
    ).start()


class ZeekrSeatSelect(ZeekrEntity, SelectEntity):
    """Seat heat / vent level."""

    _attr_options = OPTIONS

    def __init__(self, coordinator: ZeekrCoordinator, vin: str, key: str,
                 name: str, service_code: str, mode: str, position: str) -> None:
        super().__init__(coordinator, vin, key)
        self._attr_name = name
        self._service_code = service_code
        self._mode = mode
        self._position = position
        self._attr_icon = (
            "mdi:car-seat-heater" if mode == "heat" else "mdi:car-seat-cooler"
        )

    # -- read -------------------------------------------------------------

    def _level(self) -> int:
        if self._mode == "heat":
            value = self.get("seats", "heat", self._position)
            try:
                return int(value) if value is not None else 0
            except (TypeError, ValueError):
                return 0
        vent = self.get("seats", "vent", self._position) or {}
        if not isinstance(vent, dict):
            return 0
        sts = vent.get("sts")
        if sts == 2:  # an explicit "off" wins over whatever level is left over
            return 0
        # Plenty of payloads carry the level and no status at all — this car
        # reports ``drvVentDetail`` but never ``drvVentSts``.  Keying off the
        # status alone therefore pinned ventilation to 关闭 forever even while
        # it was running, so fall back to the level whenever the status is
        # absent (or anything other than "off").
        try:
            return int(vent.get("level") or 0)
        except (TypeError, ValueError):
            return 0

    @property
    def current_option(self) -> str:
        return LEVEL_TO_OPTION.get(min(max(self._level(), 0), 3), OPTION_OFF)

    # -- write ------------------------------------------------------------

    async def async_select_option(self, option: str) -> None:
        level = OPTION_TO_LEVEL.get(option, 0)
        params: list[dict[str, str]] = []
        if level > 0:
            params.append({"key": self._service_code, "value": "true"})
            params.append({"key": f"{self._service_code}.level", "value": str(level)})
            params.append(
                {
                    "key": f"{self._service_code}.duration",
                    "value": str(self.coordinator.seat_duration),
                }
            )
        else:
            params.append({"key": self._service_code, "value": "false"})

        await self.send_command("start", "ZAF", {"serviceParameters": params})

        if self._mode == "heat":
            self.coordinator.set_optimistic(
                self.vin, "seats", "heat", self._position, value=level
            )
        else:
            self.coordinator.set_optimistic(
                self.vin,
                "seats",
                "vent",
                self._position,
                value={"sts": 0 if level == 0 else 1, "level": level},
            )
