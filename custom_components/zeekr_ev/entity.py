"""Shared entity helpers for the Zeekr EV integration.

The important piece here is :class:`VehicleEntityManager`.  Entities are
created from the *vehicle list* rather than from the first poll's data, and
the manager keeps listening for vehicles that appear later.  That fixes the
original defect where an empty first poll meant ``async_setup_entry`` created
zero entities and they never appeared.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .parser import vehicle_display_name

_LOGGER = logging.getLogger(__name__)

# Guard against an unbounded entity explosion if an API returns junk VINs.
_MAX_VEHICLES = 20


def vehicle_device_info(coordinator: ZeekrCoordinator, vin: str) -> DeviceInfo:
    """Build the HA device entry for a vehicle."""
    vehicle = coordinator.get_vehicle(vin)
    meta: dict[str, Any] = getattr(vehicle, "meta", None) or {}
    return DeviceInfo(
        identifiers={(DOMAIN, vin)},
        name=vehicle_display_name(meta),
        manufacturer=meta.get("brand") or "Zeekr",
        model=meta.get("model") or meta.get("series") or "Zeekr EV",
        serial_number=vin,
    )


class ZeekrEntity(CoordinatorEntity[ZeekrCoordinator]):
    """Base class for every vehicle-scoped Zeekr entity."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: ZeekrCoordinator, vin: str, key: str) -> None:
        super().__init__(coordinator)
        self.vin = vin
        self._attr_unique_id = f"{vin}_{key}"

    # -- data access ------------------------------------------------------

    @property
    def data(self) -> dict[str, Any]:
        """The canonical state dict for this vehicle (may be empty)."""
        return (self.coordinator.data or {}).get(self.vin) or {}

    def get(self, *path: str, default: Any = None) -> Any:
        """Read a dotted path from the canonical state."""
        node: Any = self.data
        for step in path:
            if not isinstance(node, dict):
                return default
            node = node.get(step)
        return default if node is None else node

    @property
    def vehicle(self):
        return self.coordinator.get_vehicle(self.vin)

    @property
    def device_info(self) -> DeviceInfo:
        return vehicle_device_info(self.coordinator, self.vin)

    # -- command helpers --------------------------------------------------

    async def send_command(self, command: str, service_id: str,
                           setting: dict[str, Any]) -> Any:
        """Send a remote-control command and refresh shortly afterwards."""
        return await self.coordinator.async_send_and_refresh(
            self.vin, command, service_id, setting
        )


class VehicleEntityManager:
    """Create entities for each vehicle as soon as it is discovered."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        coordinator: ZeekrCoordinator,
        async_add_entities: AddEntitiesCallback,
        factory: Callable[[str], list[Entity]],
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.coordinator = coordinator
        self._async_add_entities = async_add_entities
        self._factory = factory
        self._known: set[str] = set()

    @callback
    def _sync(self) -> None:
        new_vins = [
            vin
            for vin in self.coordinator.vehicle_vins()
            if vin and vin not in self._known
        ]
        if not new_vins:
            return

        entities: list[Entity] = []
        for vin in new_vins:
            if len(self._known) >= _MAX_VEHICLES:
                _LOGGER.warning(
                    "已达车辆上限 %d，忽略 %s", _MAX_VEHICLES, vin
                )
                break
            self._known.add(vin)
            entities.extend(self._factory(vin))

        if entities:
            _LOGGER.debug("为 %s 创建了 %d 个实体", new_vins, len(entities))
            self._async_add_entities(entities)

    @callback
    def start(self) -> None:
        """Prime entities from cached vehicles and subscribe for new ones."""
        self.entry.async_on_unload(self.coordinator.async_add_listener(self._sync))
        self._sync()
