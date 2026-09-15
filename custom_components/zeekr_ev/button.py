"""Button platform — one-shot remote actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity


@dataclass(frozen=True)
class ButtonSpec:
    key: str
    name: str
    icon: str
    command: str
    service_id: str
    setting: dict[str, Any]


BUTTON_SPECS: tuple[ButtonSpec, ...] = (
    ButtonSpec(
        "flash_blinkers", "闪灯", "mdi:car-light-alert",
        "start", "RHL",
        {"serviceParameters": [{"key": "rhl", "value": "light-flash"}]},
    ),
    ButtonSpec(
        "honk_flash", "鸣笛并闪灯", "mdi:bullhorn",
        "start", "RHL",
        {"serviceParameters": [{"key": "rhl", "value": "horn-light-flash"}]},
    ),
    ButtonSpec(
        "parking_comfort_off", "关闭驻车舒适", "mdi:car-seat-cooler",
        "stop", "PCM",
        {"serviceParameters": [{"key": "parking_comfortable", "value": "false"}]},
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the button platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]

    def factory(vin: str) -> list[ButtonEntity]:
        entities: list[ButtonEntity] = [
            ZeekrCommandButton(coordinator, vin, spec) for spec in BUTTON_SPECS
        ]
        entities.append(ZeekrRefreshButton(coordinator, vin))
        return entities

    VehicleEntityManager(hass, entry, coordinator, async_add_entities, factory).start()


class ZeekrCommandButton(ZeekrEntity, ButtonEntity):
    """A button that fires a fixed remote-control command."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str,
                 spec: ButtonSpec) -> None:
        super().__init__(coordinator, vin, spec.key)
        self._attr_name = spec.name
        self._attr_icon = spec.icon
        self._spec = spec

    async def async_press(self) -> None:
        await self.send_command(
            self._spec.command, self._spec.service_id, self._spec.setting
        )


class ZeekrRefreshButton(ZeekrEntity, ButtonEntity):
    """Force an immediate poll (and vehicle rediscovery)."""

    _attr_name = "立即刷新"
    _attr_icon = "mdi:refresh"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "refresh")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"last_poll": self.coordinator.latest_poll_time}

    async def async_press(self) -> None:
        await self.coordinator.async_force_discovery()
