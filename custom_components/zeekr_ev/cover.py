"""Cover platform — sunshade and (grouped) windows."""

from __future__ import annotations

from typing import Any

from homeassistant.components.cover import (
    CoverDeviceClass,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_POSITIONS = ("fl", "fr", "rl", "rr")


def _target(value: str) -> dict[str, Any]:
    return {"serviceParameters": [{"key": "target", "value": value}]}


def _covers(coordinator: ZeekrCoordinator, vin: str) -> list[CoverEntity]:
    """The cover entities this car actually has.

    A car without a sunshade answers the "not equipped" sentinel instead of a
    position, so the control is skipped outright rather than being shown as an
    unavailable blind.  It is only skipped once a poll has actually said so —
    otherwise a failed first refresh would silently remove it.
    """
    climate = ((coordinator.data or {}).get(vin) or {}).get("climate") or {}
    entities: list[CoverEntity] = []
    if climate.get("sunshade_supported") is not False:
        entities.append(ZeekrSunshade(coordinator, vin))
    entities.append(ZeekrWindows(coordinator, vin))
    return entities


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the cover platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: _covers(coordinator, vin),
    ).start()


class ZeekrSunshade(ZeekrEntity, CoverEntity):
    """Panoramic roof sunshade."""

    _attr_name = "遮阳帘"
    _attr_device_class = CoverDeviceClass.BLIND
    _attr_supported_features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "sunshade")

    @property
    def available(self) -> bool:
        # Cars without a sunshade report the "not equipped" sentinel instead of
        # a position.  Go unavailable rather than claim a part that does not
        # exist is open.
        if self.get("climate", "sunshade_supported") is False:
            return False
        return super().available

    @property
    def is_closed(self) -> bool | None:
        value = self.get("climate", "curtain_open")
        return None if value is None else (not value)

    @property
    def current_cover_position(self) -> int | None:
        value = self.get("climate", "curtain_pos")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    async def async_open_cover(self, **kwargs: Any) -> None:
        await self.send_command("start", "RWS", _target("sunshade"))
        self.coordinator.set_optimistic(
            self.vin, "climate", "curtain_open", value=True
        )

    async def async_close_cover(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RWS", _target("sunshade"))
        self.coordinator.set_optimistic(
            self.vin, "climate", "curtain_open", value=False
        )


class ZeekrWindows(ZeekrEntity, CoverEntity):
    """All windows as a single cover."""

    _attr_name = "所有车窗"
    _attr_device_class = CoverDeviceClass.WINDOW
    _attr_supported_features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "all_windows")

    def _open_states(self) -> list[bool]:
        return [
            value
            for value in (self.get("windows", pos) for pos in _POSITIONS)
            if value is not None
        ]

    @property
    def is_closed(self) -> bool | None:
        states = self._open_states()
        if not states:
            return None
        return not any(states)

    @property
    def current_cover_position(self) -> int | None:
        positions = []
        for pos in _POSITIONS:
            value = self.get("window_pos", pos)
            try:
                if value is not None:
                    positions.append(int(value))
            except (TypeError, ValueError):
                continue
        if not positions:
            return None
        return int(sum(positions) / len(positions))

    async def async_open_cover(self, **kwargs: Any) -> None:
        await self.send_command("start", "RWS", _target("window"))
        for pos in _POSITIONS:
            self.coordinator.set_optimistic(self.vin, "windows", pos, value=True)

    async def async_close_cover(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RWS", _target("window"))
        for pos in _POSITIONS:
            self.coordinator.set_optimistic(self.vin, "windows", pos, value=False)
