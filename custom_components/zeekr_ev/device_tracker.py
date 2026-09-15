"""Device tracker platform — vehicle GPS position."""

from __future__ import annotations

from typing import Any

from homeassistant.components.device_tracker import SourceType, TrackerEntity
from homeassistant.config_entries import ConfigEntry
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
    """Set up the device tracker platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrDeviceTracker(coordinator, vin)],
    ).start()


class ZeekrDeviceTracker(ZeekrEntity, TrackerEntity):
    """GPS tracker for a vehicle."""

    _attr_name = "位置"
    _attr_icon = "mdi:car-connected"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "location")

    @property
    def source_type(self) -> SourceType:
        return SourceType.GPS

    @property
    def latitude(self) -> float | None:
        value = self.get("position", "latitude")
        return float(value) if value is not None else None

    @property
    def longitude(self) -> float | None:
        value = self.get("position", "longitude")
        return float(value) if value is not None else None

    @property
    def location_accuracy(self) -> int:
        # The backend does not expose an accuracy; assume a sane default so the
        # zone is drawn compactly instead of as a city-wide blob.
        return 20

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "valid": self.get("position", "valid"),
            "heading": self.get("position", "heading"),
            "speed": self.get("position", "speed"),
            "altitude": self.get("position", "altitude"),
            "position_time": self.get("position", "timestamp"),
        }

    @property
    def available(self) -> bool:
        # Position can legitimately be missing; keep the entity available so the
        # user sees "unknown" rather than "unavailable".
        return super().available
