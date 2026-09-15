"""Binary sensor platform — charging, openings and tyre warnings."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_POSITIONS = ("fl", "fr", "rl", "rr")
_POS_LABEL = {"fl": "左前", "fr": "右前", "rl": "左后", "rr": "右后"}


@dataclass(frozen=True)
class BinarySpec:
    key: str
    name: str
    path: tuple[str, ...]
    device_class: BinarySensorDeviceClass | None = None
    invert: bool = False


def _build_specs() -> list[BinarySpec]:
    specs: list[BinarySpec] = [
        BinarySpec("charging", "充电中", ("battery", "charging"),
                   BinarySensorDeviceClass.BATTERY_CHARGING),
        BinarySpec("plugged_in", "已连接充电枪", ("battery", "plugged"),
                   BinarySensorDeviceClass.PLUG),
        BinarySpec("door_open_fl", "左前门", ("doors", "fl"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("door_open_fr", "右前门", ("doors", "fr"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("door_open_rl", "左后门", ("doors", "rl"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("door_open_rr", "右后门", ("doors", "rr"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("trunk_open", "后备箱", ("doors", "trunk"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("hood_open", "前机盖", ("doors", "hood"),
                   BinarySensorDeviceClass.DOOR),
        BinarySpec("window_open_fl", "左前车窗", ("windows", "fl"),
                   BinarySensorDeviceClass.WINDOW),
        BinarySpec("window_open_fr", "右前车窗", ("windows", "fr"),
                   BinarySensorDeviceClass.WINDOW),
        BinarySpec("window_open_rl", "左后车窗", ("windows", "rl"),
                   BinarySensorDeviceClass.WINDOW),
        BinarySpec("window_open_rr", "右后车窗", ("windows", "rr"),
                   BinarySensorDeviceClass.WINDOW),
    ]
    for pos in _POSITIONS:
        specs.append(
            BinarySpec(
                f"tyre_warning_{pos}", f"胎压报警 {_POS_LABEL[pos]}",
                ("tyres", "pressure_warning", pos),
                BinarySensorDeviceClass.PROBLEM,
            )
        )
    return specs


BINARY_SPECS = _build_specs()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary sensor platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrBinarySensor(coordinator, vin, spec)
                     for spec in BINARY_SPECS],
    ).start()


class ZeekrBinarySensor(ZeekrEntity, BinarySensorEntity):
    """A boolean read from the canonical state."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str,
                 spec: BinarySpec) -> None:
        super().__init__(coordinator, vin, spec.key)
        self._spec = spec
        self._attr_name = spec.name
        self._attr_device_class = spec.device_class

    @property
    def is_on(self) -> bool | None:
        value = self.get(*self._spec.path)
        if value is None:
            return None
        return (not value) if self._spec.invert else bool(value)
