"""Lock platform — central door lock and charge-port lid."""

from __future__ import annotations

from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity


def _params(key: str, value: str) -> dict[str, Any]:
    return {"serviceParameters": [{"key": key, "value": value}]}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the lock platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [
            ZeekrCentralLock(coordinator, vin),
            ZeekrChargeLidLock(coordinator, vin),
        ],
    ).start()


class ZeekrCentralLock(ZeekrEntity, LockEntity):
    """Central locking — locks / unlocks all doors."""

    _attr_name = "车门锁"
    _attr_icon = "mdi:car-door-lock"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "central_lock")

    @property
    def is_locked(self) -> bool | None:
        value = self.get("locks", "central")
        return None if value is None else bool(value)

    async def async_lock(self, **kwargs: Any) -> None:
        await self.send_command("start", "RDL", _params("door", "all"))
        self.coordinator.set_optimistic(self.vin, "locks", "central", value=True)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RDU", _params("door", "all"))
        self.coordinator.set_optimistic(self.vin, "locks", "central", value=False)


class ZeekrChargeLidLock(ZeekrEntity, LockEntity):
    """Charge-port lid — ``locked`` means the lid is closed."""

    _attr_name = "充电口盖"
    _attr_icon = "mdi:ev-plug-type2"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "charge_lid_lock")

    @property
    def is_locked(self) -> bool | None:
        value = self.get("locks", "charge_lid")
        return None if value is None else bool(value)

    async def async_lock(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RDC", _params("target", "front-charge-lid"))
        self.coordinator.set_optimistic(self.vin, "locks", "charge_lid", value=True)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self.send_command("start", "RDO", _params("target", "front-charge-lid"))
        self.coordinator.set_optimistic(self.vin, "locks", "charge_lid", value=False)
