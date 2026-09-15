"""Switch platform — charging, climate helpers and scheduled plans."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_LOGGER = logging.getLogger(__name__)


def _sp(*pairs: tuple[str, str]) -> dict[str, Any]:
    return {"serviceParameters": [{"key": k, "value": v} for k, v in pairs]}


def _truthy(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "on", "yes")


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the switch platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [
            ZeekrChargingSwitch(coordinator, vin),
            ZeekrDefrostSwitch(coordinator, vin),
            ZeekrSteeringWheelHeatSwitch(coordinator, vin),
            ZeekrSentrySwitch(coordinator, vin),
            ZeekrChargePlanSwitch(coordinator, vin),
            ZeekrTravelPlanSwitch(coordinator, vin),
            ZeekrDepartureACSwitch(coordinator, vin),
        ],
    ).start()


class ZeekrSwitchBase(ZeekrEntity, SwitchEntity):
    """Common plumbing for the command-backed switches."""

    _attr_icon = "mdi:toggle-switch"

    def __init__(self, coordinator: ZeekrCoordinator, vin: str, key: str,
                 name: str, icon: str | None = None) -> None:
        super().__init__(coordinator, vin, key)
        self._attr_name = name
        if icon:
            self._attr_icon = icon


class ZeekrChargingSwitch(ZeekrSwitchBase):
    """Start / stop charging."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "charging", "充电", "mdi:battery-charging")

    @property
    def is_on(self) -> bool | None:
        return self.get("battery", "charging")

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.send_command("start", "RCS", _sp(("rcs.restart", "1")))
        self.coordinator.set_optimistic(self.vin, "battery", "charging", value=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RCS", _sp(("rcs.terminate", "1")))
        self.coordinator.set_optimistic(self.vin, "battery", "charging", value=False)


class ZeekrDefrostSwitch(ZeekrSwitchBase):
    """Front defroster."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "defrost", "前风挡除霜", "mdi:car-defrost-front")

    @property
    def is_on(self) -> bool | None:
        return self.get("climate", "defrost")

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.send_command(
            "start", "ZAF", _sp(("DF", "true"), ("DF.level", "2"))
        )
        self.coordinator.set_optimistic(self.vin, "climate", "defrost", value=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.send_command("start", "ZAF", _sp(("DF", "false")))
        self.coordinator.set_optimistic(self.vin, "climate", "defrost", value=False)


class ZeekrSteeringWheelHeatSwitch(ZeekrSwitchBase):
    """Steering wheel heating."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "steering_wheel_heat",
                         "方向盘加热", "mdi:steering")

    @property
    def is_on(self) -> bool | None:
        return self.get("climate", "steering_wheel_heat")

    async def async_turn_on(self, **kwargs: Any) -> None:
        duration = self.coordinator.steering_wheel_duration
        await self.send_command(
            "start", "ZAF",
            _sp(("SW", "true"), ("SW.duration", str(duration)), ("SW.level", "3")),
        )
        self.coordinator.set_optimistic(
            self.vin, "climate", "steering_wheel_heat", value=True
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.send_command("start", "ZAF", _sp(("SW", "false")))
        self.coordinator.set_optimistic(
            self.vin, "climate", "steering_wheel_heat", value=False
        )


class ZeekrSentrySwitch(ZeekrSwitchBase):
    """Sentry / guard mode.

    The backend ``RSM`` payload values are not fully documented; ``6`` is the
    value the Zeekr app sends to arm the system.
    """

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "sentry", "哨兵模式", "mdi:cctv")

    @property
    def is_on(self) -> bool | None:
        return self.get("safety", "sentry")

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.send_command("start", "RSM", _sp(("rsm", "6")))
        self.coordinator.set_optimistic(self.vin, "safety", "sentry", value=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.send_command("stop", "RSM", _sp(("rsm", "0")))
        self.coordinator.set_optimistic(self.vin, "safety", "sentry", value=False)


class ZeekrChargePlanSwitch(ZeekrSwitchBase):
    """Enable / disable the charging schedule."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "charge_plan", "充电计划", "mdi:calendar-clock")

    @property
    def is_on(self) -> bool | None:
        command = self.get("charge_plan", "command")
        if command is None:
            return None
        return str(command) == "start"

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set("start")

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set("stop")

    async def _set(self, command: str) -> None:
        start = self.get("charge_plan", "start_time") or "00:00"
        end = self.get("charge_plan", "end_time") or "06:00"
        bc_cycle = _truthy(self.get("charge_plan", "bc_cycle")) or False
        bc_temp = _truthy(self.get("charge_plan", "bc_temp")) or False
        await self.coordinator.async_set_charge_plan(
            self.vin, start, end, command, bc_cycle, bc_temp
        )
        self.coordinator.set_optimistic(
            self.vin, "charge_plan", "command", value=command
        )


class ZeekrTravelPlanSwitch(ZeekrSwitchBase):
    """Enable / disable the departure (travel) plan."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "travel_plan", "出行计划", "mdi:car-clock")

    @property
    def is_on(self) -> bool | None:
        command = self.get("travel_plan", "command")
        if command is None:
            return None
        return str(command) == "start"

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set("start")

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set("stop")

    async def _set(self, command: str) -> None:
        scheduled = self.get("travel_plan", "scheduled_time") or ""
        ac = _truthy(self.get("travel_plan", "ac"))
        swh = _truthy(self.get("travel_plan", "steering_wheel_heat")) or False
        await self.coordinator.async_set_travel_plan(
            self.vin, command, "", scheduled, True if ac is None else ac, swh
        )
        self.coordinator.set_optimistic(
            self.vin, "travel_plan", "command", value=command
        )


class ZeekrDepartureACSwitch(ZeekrSwitchBase):
    """Pre-condition the cabin before departure."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str) -> None:
        super().__init__(coordinator, vin, "departure_ac", "出行空调", "mdi:air-conditioner")

    @property
    def is_on(self) -> bool | None:
        return _truthy(self.get("travel_plan", "ac"))

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)

    async def _set(self, ac_on: bool) -> None:
        command = self.get("travel_plan", "command") or "start"
        scheduled = self.get("travel_plan", "scheduled_time") or ""
        swh = _truthy(self.get("travel_plan", "steering_wheel_heat")) or False
        await self.coordinator.async_set_travel_plan(
            self.vin, str(command), "", scheduled, ac_on, swh
        )
        self.coordinator.set_optimistic(
            self.vin, "travel_plan", "ac", value="true" if ac_on else "false"
        )
