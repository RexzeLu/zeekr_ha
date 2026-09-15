"""Sensor platform — read-only vehicle telemetry."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
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

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .entity import VehicleEntityManager, ZeekrEntity

_TYRE_POSITIONS = ("fl", "fr", "rl", "rr")
_TYRE_LABEL = {"fl": "左前", "fr": "右前", "rl": "左后", "rr": "右后"}


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
    icon_on: str | None = None
    divisor: float = 1.0


def _build_specs() -> list[SensorSpec]:
    specs: list[SensorSpec] = [
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
            "range_at_20", "20%电量续航", ("battery", "range_at_20"),
            SensorDeviceClass.DISTANCE, SensorStateClass.MEASUREMENT,
            UnitOfLength.KILOMETERS, "mdi:map-marker-distance",
        ),
        SensorSpec(
            "range_at_80", "满电续航", ("battery", "range_at_80"),
            SensorDeviceClass.DISTANCE, SensorStateClass.MEASUREMENT,
            UnitOfLength.KILOMETERS, "mdi:map-marker-distance",
        ),
        SensorSpec(
            "odometer", "总里程", ("odometer",),
            SensorDeviceClass.DISTANCE, SensorStateClass.TOTAL_INCREASING,
            UnitOfLength.KILOMETERS, "mdi:counter",
        ),
        SensorSpec(
            "inside_temperature", "车内温度", ("climate", "inside_temp"),
            SensorDeviceClass.TEMPERATURE, SensorStateClass.MEASUREMENT,
            UnitOfTemperature.CELSIUS, "mdi:thermometer",
        ),
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
        SensorSpec(
            "speed", "车速", ("safety", "speed"),
            SensorDeviceClass.SPEED, SensorStateClass.MEASUREMENT,
            UnitOfSpeed.KILOMETERS_PER_HOUR, "mdi:speedometer",
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

    @property
    def native_value(self):
        value = self.get(*self._spec.path)
        if value is None:
            return None
        if self._spec.divisor and self._spec.divisor != 1.0:
            try:
                return round(float(value) / self._spec.divisor, 1)
            except (TypeError, ValueError):
                return None
        return value
