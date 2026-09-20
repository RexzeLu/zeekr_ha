"""Sensor platform — read-only vehicle telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EntityCategory,
    PERCENTAGE,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfLength,
    UnitOfPower,
    UnitOfPressure,
    UnitOfSpeed,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_TYRE_POSITIONS = ("fl", "fr", "rl", "rr")
_TYRE_LABEL = {"fl": "左前", "fr": "右前", "rl": "左后", "rr": "右后"}

# No standard HA unit for consumption; keep the string the car reports.
_CONSUMPTION_UNIT = "kWh/100km"


@dataclass(frozen=True)
class SensorSpec:
    """Declarative description of one sensor."""

    key: str
    name: str
    path: tuple[str, ...]
    device_class: SensorDeviceClass | None = None
    state_class: SensorStateClass | None = None
    unit: str | None = None
    icon: str | None = None
    divisor: float = 1.0
    category: EntityCategory | None = None


def _build_specs() -> list[SensorSpec]:
    specs: list[SensorSpec] = [
        # -- drive / energy ---------------------------------------------
        SensorSpec(
            "battery_level", "电量", ("battery", "soc"),
            SensorDeviceClass.BATTERY, SensorStateClass.MEASUREMENT,
            PERCENTAGE, "mdi:battery",
        ),
        SensorSpec(
            "range", "续航", ("battery", "range"),
            SensorDeviceClass.DISTANCE, SensorStateClass.MEASUREMENT,
            UnitOfLength.KILOMETERS, "mdi:map-marker-distance",
        ),
        SensorSpec(
            "odometer", "总里程", ("odometer",),
            SensorDeviceClass.DISTANCE, SensorStateClass.TOTAL_INCREASING,
            UnitOfLength.KILOMETERS, "mdi:counter",
        ),
        SensorSpec(
            "speed", "车速", ("safety", "speed"),
            SensorDeviceClass.SPEED, SensorStateClass.MEASUREMENT,
            UnitOfSpeed.KILOMETERS_PER_HOUR, "mdi:speedometer",
        ),
        SensorSpec(
            "power_consumption", "平均能耗", ("battery", "power_consumption"),
            None, None, _CONSUMPTION_UNIT, "mdi:lightning-bolt-outline",
        ),
        # -- climate ----------------------------------------------------
        SensorSpec(
            "inside_temperature", "车内温度", ("climate", "inside_temp"),
            SensorDeviceClass.TEMPERATURE, SensorStateClass.MEASUREMENT,
            UnitOfTemperature.CELSIUS, "mdi:thermometer",
        ),
        SensorSpec(
            "outside_temperature", "车外温度", ("climate", "outside_temp"),
            SensorDeviceClass.TEMPERATURE, SensorStateClass.MEASUREMENT,
            UnitOfTemperature.CELSIUS, "mdi:thermometer-lines",
        ),
        SensorSpec(
            "climate_target_temperature", "空调设定温度", ("climate", "target_temp"),
            SensorDeviceClass.TEMPERATURE, SensorStateClass.MEASUREMENT,
            UnitOfTemperature.CELSIUS, "mdi:thermostat",
        ),
        # -- charging ---------------------------------------------------
        SensorSpec(
            "charge_power", "充电功率", ("battery", "power"),
            SensorDeviceClass.POWER, SensorStateClass.MEASUREMENT,
            UnitOfPower.KILO_WATT, "mdi:flash",
        ),
        SensorSpec(
            "charge_voltage", "充电电压", ("battery", "voltage"),
            SensorDeviceClass.VOLTAGE, SensorStateClass.MEASUREMENT,
            UnitOfElectricPotential.VOLT, "mdi:sine-wave",
        ),
        SensorSpec(
            "charge_current", "充电电流", ("battery", "current"),
            SensorDeviceClass.CURRENT, SensorStateClass.MEASUREMENT,
            UnitOfElectricCurrent.AMPERE, "mdi:current-ac",
        ),
        SensorSpec(
            "remaining_charge_time", "预计充满时间", ("battery", "remaining_minutes"),
            SensorDeviceClass.DURATION, SensorStateClass.MEASUREMENT,
            UnitOfTime.MINUTES, "mdi:timer-sand",
        ),
        SensorSpec(
            "charge_limit", "充电上限", ("battery", "limit"),
            SensorDeviceClass.BATTERY, None,
            PERCENTAGE, "mdi:battery-charging-high",
        ),
        # -- 12 V aux battery ------------------------------------------
        SensorSpec(
            "aux_battery_voltage", "12V电瓶电压", ("battery12v", "voltage"),
            SensorDeviceClass.VOLTAGE, SensorStateClass.MEASUREMENT,
            UnitOfElectricPotential.VOLT, "mdi:car-battery",
        ),
        SensorSpec(
            "aux_battery_level", "12V电瓶电量", ("battery12v", "soc"),
            None, SensorStateClass.MEASUREMENT,
            PERCENTAGE, "mdi:car-battery",
        ),
        # -- cabin air / service ---------------------------------------
        SensorSpec(
            "service_distance", "保养剩余里程", ("service", "distance_to_service"),
            SensorDeviceClass.DISTANCE, None,
            UnitOfLength.KILOMETERS, "mdi:wrench-clock",
        ),
        SensorSpec(
            "service_days", "保养剩余天数", ("service", "days_to_service"),
            SensorDeviceClass.DURATION, None,
            UnitOfTime.DAYS, "mdi:calendar-clock",
        ),
        # -- diagnostics -------------------------------------------------
        # Not telemetry about the car, but about the *data*: when the car last
        # uploaded.  This is what tells you whether a lagging value is Home
        # Assistant polling too slowly or the car simply not reporting.
        SensorSpec(
            "report_time", "车况上报时间", ("report_time",),
            SensorDeviceClass.TIMESTAMP, None,
            None, "mdi:clock-check-outline",
            category=EntityCategory.DIAGNOSTIC,
        ),
    ]

    for pos in _TYRE_POSITIONS:
        specs.append(
            SensorSpec(
                f"tyre_pressure_{pos}", f"胎压 {_TYRE_LABEL[pos]}",
                ("tyres", "pressure", pos),
                SensorDeviceClass.PRESSURE, SensorStateClass.MEASUREMENT,
                UnitOfPressure.KPA, "mdi:car-tire-alert",
            )
        )
        specs.append(
            SensorSpec(
                f"tyre_temperature_{pos}", f"胎温 {_TYRE_LABEL[pos]}",
                ("tyres", "temp", pos),
                SensorDeviceClass.TEMPERATURE, SensorStateClass.MEASUREMENT,
                UnitOfTemperature.CELSIUS, "mdi:thermometer",
            )
        )

    return specs


SENSOR_SPECS = _build_specs()


def _as_datetime(value: Any) -> datetime | None:
    """Turn a gateway epoch stamp into an aware datetime.

    GRIC reports milliseconds; a seconds stamp has been seen on the SNC side,
    so anything that would land before 1973 is read as seconds instead.
    """
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return None
    if stamp <= 0:
        return None
    if stamp > 1e11:  # milliseconds
        stamp /= 1000.0
    try:
        return datetime.fromtimestamp(stamp, tz=dt_util.UTC)
    except (OverflowError, OSError, ValueError):
        return None


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the sensor platform."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    VehicleEntityManager(
        hass,
        entry,
        coordinator,
        async_add_entities,
        lambda vin: [ZeekrSensor(coordinator, vin, spec) for spec in SENSOR_SPECS],
    ).start()


class ZeekrSensor(ZeekrEntity, SensorEntity):
    """A single telemetry value read from the canonical state."""

    def __init__(self, coordinator: ZeekrCoordinator, vin: str,
                 spec: SensorSpec) -> None:
        super().__init__(coordinator, vin, spec.key)
        self._spec = spec
        self._attr_name = spec.name
        self._attr_device_class = spec.device_class
        self._attr_state_class = spec.state_class
        if spec.unit:
            self._attr_native_unit_of_measurement = spec.unit
        if spec.icon:
            self._attr_icon = spec.icon
        if spec.category:
            self._attr_entity_category = spec.category

    @property
    def native_value(self):
        value = self.get(*self._spec.path)
        if value is None:
            return None
        if self._spec.device_class == SensorDeviceClass.TIMESTAMP:
            return _as_datetime(value)
        if self._spec.divisor and self._spec.divisor != 1.0:
            try:
                return round(float(value) / self._spec.divisor, 1)
            except (TypeError, ValueError):
                return None
        return value
