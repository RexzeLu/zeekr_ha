"""Tolerant parsing / normalisation of Zeekr vehicle payloads.

The Zeekr mobile gateways (LINE/GW2 and SNCTSP/GW3) return vehicle status
payloads whose field names, nesting and value encodings differ between
endpoints, vehicle models and firmware revisions.  Instead of hard-coding a
single schema we flatten the payload into an index of every leaf value and
look fields up through a list of aliases.

The result is a *canonical* dict that the entity platforms consume.  Keeping
that boundary stable means a backend rename only requires adding an alias
here, not touching a dozen platform modules.

Canonical shape (all keys always present, values may be ``None``)::

    {
      "vehicle":  {"vin", "plate", "model", "series", "nickname"},
      "battery":  {"soc", "range", "range_at_20", "range_at_80", "charging",
                   "charger_state", "plugged", "power", "voltage", "current",
                   "charge_speed", "remaining_minutes", "limit"},
      "odometer": float | None,
      "climate":  {"inside_temp", "ac_on", "defrost", "steering_wheel_heat",
                   "curtain_open", "curtain_pos"},
      "doors":    {"fl", "fr", "rl", "rr", "trunk", "hood"},
      "windows":  {"fl", "fr", "rl", "rr"},
      "window_pos": {"fl", "fr", "rl", "rr"},
      "tyres":    {"pressure": {...}, "temp": {...},
                   "pressure_warning": {...}, "temp_warning": {...}},
      "locks":    {"central", "charge_lid"},   # True = locked
      "safety":   {"park_brake", "sentry", "engine_status", "vehicle_status",
                   "speed"},
      "position": {"latitude", "longitude", "speed", "heading",
                   "altitude", "timestamp", "valid"},
      "charge_plan": {"command", "start_time", "end_time", "bc_cycle", "bc_temp"},
      "travel_plan": {"command", "scheduled_time", "ac", "steering_wheel_heat"},
      "raw": <original payload>,
    }
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterable

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Low level helpers
# ---------------------------------------------------------------------------


def normalise_key(value: Any) -> str:
    """Lower-case and strip every non alphanumeric character from a key."""
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _iter_leaves(obj: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:
    """Yield ``(dotted_path, value)`` for every scalar leaf in *obj*."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _iter_leaves(value, child)
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            child = f"{prefix}.{index}" if prefix else str(index)
            yield from _iter_leaves(value, child)
    elif obj is not None:
        yield prefix, obj


class PayloadIndex:
    """Look-up index over a payload's leaves.

    ``full`` maps the normalised dotted path to a value; ``leaf`` maps the
    normalised final segment to a value.  Look-ups try the full path first so
    an explicit ``electricVehicleStatus.chargeLevel`` beats a stray
    ``chargeLevel`` elsewhere in the tree, then fall back to the leaf.
    """

    __slots__ = ("full", "leaf")

    def __init__(self, full: dict[str, Any], leaf: dict[str, Any]) -> None:
        self.full = full
        self.leaf = leaf

    def find(self, *names: str, default: Any = None) -> Any:
        """Return the first alias present with a non-``None`` value."""
        for name in names:
            key = normalise_key(name)
            if key in self.full and self.full[key] is not None:
                return self.full[key]
        for name in names:
            key = normalise_key(name)
            if key in self.leaf and self.leaf[key] is not None:
                return self.leaf[key]
        return default

    def contains(self, *names: str) -> bool:
        return any(
            normalise_key(name) in self.full or normalise_key(name) in self.leaf
            for name in names
        )


def build_index(obj: Any) -> PayloadIndex:
    """Build a :class:`PayloadIndex` from an arbitrary payload."""
    full: dict[str, Any] = {}
    leaf: dict[str, Any] = {}
    for path, value in _iter_leaves(obj):
        if not path:
            continue
        full.setdefault(normalise_key(path), value)
        leaf.setdefault(normalise_key(path.split(".")[-1]), value)
    return PayloadIndex(full, leaf)


# ---------------------------------------------------------------------------
# Coercion
# ---------------------------------------------------------------------------


def as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except (TypeError, ValueError):
        return None


def as_int(value: Any) -> int | None:
    number = as_float(value)
    return int(number) if number is not None else None


_TRUE_TOKENS = {"1", "true", "on", "yes", "open", "opened", "active", "running"}
_FALSE_TOKENS = {"0", "2", "false", "off", "no", "close", "closed", "inactive",
                 "stopped", "idle", "none"}


def as_bool(value: Any, *, true_tokens: set[str] | None = None,
            false_tokens: set[str] | None = None) -> bool | None:
    """Best-effort tri-state boolean.

    Returns ``None`` when the token is not recognised so entities report
    *unknown* rather than a wrong state.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value in (0, 2):
            return False
        return None
    token = str(value).strip().lower()
    if token in (true_tokens or _TRUE_TOKENS):
        return True
    if token in (false_tokens or _FALSE_TOKENS):
        return False
    return None


def _first_number(text: Any) -> float | None:
    return as_float(text)


# ---------------------------------------------------------------------------
# Alias tables
# ---------------------------------------------------------------------------

_ALIAS = {
    # battery / charging
    # NB: dotted / more specific aliases are listed before generic ones and
    # ``PayloadIndex.find`` resolves full paths before bare leaves, so a nested
    # ``chargingLimit.soc`` can never shadow the pack SOC.
    "soc": ("electricVehicleStatus.chargeLevel", "chargeLevel", "batteryLevel",
            "powerBatteryLevel", "batterySoc", "evSoc", "soc",
            "remainingBatteryPercentage"),
    "range": ("remainKm", "range", "distanceToEmptyOnBatteryOnly",
              "remainingRange", "evRange", "mileage", "electricRange",
              "distanceToEmpty"),
    "range_at_20": ("mileageAt20Soc", "distanceToEmptyOnBattery20Soc",
                    "rangeAt20Soc"),
    "range_at_80": ("mileageAt80Soc", "mileageAt100Soc",
                    "distanceToEmptyOnBattery100Soc",
                    "distanceToEmptyOnBattery80Soc", "rangeAt100Soc"),
    "charger_state": ("chargeStatus", "chargerState", "chargingStatus",
                      "chargeState", "chargingState", "bmsChargingStatus"),
    "plugged": ("chargePlugStatus", "statusOfChargerConnection", "plugStatus",
                "plugged", "chargeGunStatus", "chargingGunStatus"),
    "charge_power": ("chargePower", "chargingPower", "chargePowerKw",
                     "dcChargePower", "acChargePower"),
    "charge_voltage": ("chargeVoltage", "bmsChargeVoltage", "chargingVoltage"),
    "charge_current": ("chargeCurrent", "bmsChargeCurrent", "chargingCurrent"),
    "charge_speed": ("chargeSpeed", "chargingSpeed", "chargeRate",
                     "chargingRate"),
    "remaining_minutes": ("remainingChargeTime", "timeToFullyCharged",
                          "remainingChargingTime", "leftChargeTime"),
    "charge_limit": ("chargingLimit.soc", "chargingLimitSoc", "chargeLimitSoc",
                     "chargeLimit", "socLimit", "targetSoc", "maxSoc"),
    # odometer
    "odometer": ("totalOdometer", "odometer", "totalMileage", "totalDistance",
                 "maintenanceStatus.odometer", "vehicleMileage"),
    # climate
    "inside_temp": ("temperatureInside", "interiorTemp", "cabinTemp",
                    "insideTemp", "temperatureInCar", "climateStatus.interiorTemp",
                    "carInsideTemp"),
    "ac_on": ("acStatus", "acOn", "preClimateActive",
              "climateStatus.preClimateActive", "airConditionerStatus",
              "airConStatus", "climateActive"),
    "defrost": ("defrostStatus", "frontDefrostStatus", "defrost", "DF",
                "dfStatus"),
    "steering_wheel_heat": ("steerWhlHeatingSts", "steeringWheelHeat",
                            "steeringWheelHeatingStatus", "swhStatus",
                            "steerWheelHeatStatus"),
    "curtain_open": ("curtainOpenStatus", "sunshadeOpenStatus",
                     "curtainStatus", "sunShadeStatus"),
    "curtain_pos": ("curtainPos", "sunshadePosition", "curtainPosition"),
    # locks / safety
    "central_lock": ("centralLockingStatus", "centralLockStatus", "lockStatus",
                     "doorLockStatus", "vehicleLockStatus"),
    "charge_lid_lock": ("chargeLidDcAcStatus", "chargeLidStatus",
                        "chargePortStatus", "chargeLid", "chargePortLidStatus"),
    "park_brake": ("parkBrakeStatus", "electricParkBrakeStatus", "epbStatus",
                   "parkingBrakeStatus"),
    "sentry": ("vstdModeState", "sentryMode", "sentryModeState",
               "remoteControlState.vstdModeState"),
    "engine_status": ("drivingState", "engineStatus", "vehicleState",
                      "usageMode", "basicVehicleStatus.usageMode"),
    "vehicle_status": ("vehicleState", "usageMode", "drivingState",
                       "vehicleStatusState"),
    "speed": ("speed", "vehicleSpeed", "currentSpeed", "velocity"),
    "trunk": ("trunkStatus", "trunkOpenStatus", "trunkDoorStatus",
              "tailGateStatus"),
    "hood": ("hoodStatus", "engineHoodOpenStatus", "hoodOpenStatus",
             "frontHoodStatus", "bonnetStatus"),
    # windows
    "window_open": ("winStatus", "windowStatus", "winOpenStatus",
                    "windowOpenStatus"),
    "window_pos": ("winPos", "windowPosition", "winPosition",
                   "windowOpenPercent"),
    # seats (heat level 0-3; vent comes as a status + detail pair)
    "seat_heat_fl": ("drvHeatSts", "driverHeatStatus", "seatHeatDriver"),
    "seat_heat_fr": ("passHeatingSts", "passHeatSts", "passengerHeatStatus"),
    "seat_heat_rl": ("rlHeatingSts", "rearLeftHeatSts", "seatHeatRearLeft"),
    "seat_heat_rr": ("rrHeatingSts", "rearRightHeatSts", "seatHeatRearRight"),
    "seat_vent_fl_sts": ("drvVentSts", "driverVentStatus"),
    "seat_vent_fl_level": ("drvVentDetail", "driverVentLevel"),
    "seat_vent_fr_sts": ("passVentSts", "passengerVentStatus"),
    "seat_vent_fr_level": ("passVentDetail", "passengerVentLevel"),
    # position
    "latitude": ("latitude", "lat", "gpsLatitude", "gpsLat", "position.latitude",
                 "location.latitude", "basicVehicleStatus.position.latitude",
                 "gps.latitude", "lastPosition.latitude"),
    "longitude": ("longitude", "lon", "lng", "gpsLongitude", "gpsLon",
                  "position.longitude", "location.longitude",
                  "basicVehicleStatus.position.longitude", "gps.longitude",
                  "lastPosition.longitude"),
    "heading": ("heading", "direction", "course", "position.heading",
                "gpsHeading", "bearing"),
    "altitude": ("altitude", "elevation", "position.altitude", "gpsAltitude"),
    "position_time": ("positionTime", "gpsTime", "timestamp",
                      "position.timestamp", "updateTime", "locationTime",
                      "reportTime", "positionUpdateTime"),
    # plans
    "charge_plan_command": ("chargePlan.command", "chargePlanCommand",
                            "chargeScheduleCommand"),
    "charge_plan_start": ("chargePlan.startTime", "chargeStartTime",
                          "chargePlanStartTime", "startTime"),
    "charge_plan_end": ("chargePlan.endTime", "chargeEndTime",
                        "chargePlanEndTime", "endTime"),
    "travel_plan_command": ("travelPlan.command", "travelPlanCommand"),
    "travel_plan_time": ("travelPlan.scheduledTime", "scheduledTime",
                         "departureTime", "travelPlanTime"),
    "travel_plan_ac": ("travelPlan.ac", "departureAc", "travelAc"),
    "travel_plan_swh": ("travelPlan.bw", "departureSwh"),
}

# Position suffixes seen in the wild -> canonical position key.
_POSITION_ALIASES: dict[str, tuple[str, ...]] = {
    "fl": ("fl", "frontleft", "driver", "lhdfrontleft", "leftfront"),
    "fr": ("fr", "frontright", "passenger", "lhdfrontright", "rightfront"),
    "rl": ("rl", "rearleft", "driverrear", "lhdrearleft", "leftrear"),
    "rr": ("rr", "rearright", "passengerrear", "lhdrearright", "rightrear"),
}

_TYRE_BASES = {
    "pressure": ("tyrePressure", "tyrePress", "tirePressure", "tirePress",
                 "tyrePre", "tirePre", "tyrePres"),
    "temp": ("tyreTemp", "tyreTemperature", "tireTemp", "tireTemperature",
             "tyreTemprature", "tireTemprature"),
    "pressure_warning": ("tyrePreWarning", "tyrePressureWarning",
                         "tirePressureWarning", "tyrePreWarn",
                         "tyrePressureWarn"),
    "temp_warning": ("tyreTempWarning", "tyreTemperatureWarning",
                     "tireTempWarning", "tyreTempWarn", "tyreTemperatureWarn"),
}

_DOOR_BASES = ("doorOpenStatus", "doorStatus", "doorOpen", "doorOpenedStatus")

_COORD_RE = re.compile(
    r"(-?\d{1,3}\.\d{3,})\s*[,;: ]\s*(-?\d{1,3}\.\d{3,})"
)

# Charger state codes observed in the Zeekr app trace.
_CHARGING_ACTIVE = {"1", "2", "3", "4", "5", "6", "7", "8", "15", "16", "17",
                    "18", "charging", "inprogress"}
_CHARGING_IDLE = {"0", "25", "26", "9", "10", "11", "12", "13", "14",
                  "idle", "stopped", "finished", "complete", "completed",
                  "notcharging"}


def _lookup(index: PayloadIndex, key: str) -> Any:
    return index.find(*_ALIAS[key])


def _per_position(index: PayloadIndex, bases: tuple[str, ...],
                  position: str) -> Any:
    """Find a per-corner value trying ``base+pos`` and ``pos+base`` forms."""
    tokens = _POSITION_ALIASES[position]
    names: list[str] = []
    for base in bases:
        for token in tokens:
            names.extend((f"{base}{token}", f"{token}{base}", f"{base}.{token}"))
    return index.find(*names)


def _charging_state(value: Any) -> bool | None:
    if value is None:
        return None
    token = str(value).strip().lower()
    if token in _CHARGING_ACTIVE:
        return True
    if token in _CHARGING_IDLE:
        return False
    return None


def _extract_position(index: PayloadIndex, raw: Any) -> dict[str, Any]:
    """Extract GPS position from structured or string payloads."""
    latitude = as_float(_lookup(index, "latitude"))
    longitude = as_float(_lookup(index, "longitude"))

    if latitude is None or longitude is None:
        # Some endpoints return "lat,lon" inside a single string field.
        for path, value in _iter_leaves(raw):
            if not isinstance(value, str):
                continue
            match = _COORD_RE.search(value)
            if match:
                latitude = as_float(match.group(1))
                longitude = as_float(match.group(2))
                break

    # Guard against obviously invalid coordinates (0,0 placeholder).
    valid = (
        latitude is not None
        and longitude is not None
        and -90 <= latitude <= 90
        and -180 <= longitude <= 180
        and not (abs(latitude) < 1e-6 and abs(longitude) < 1e-6)
    )

    return {
        "latitude": latitude,
        "longitude": longitude,
        "speed": as_float(_lookup(index, "speed")),
        "heading": as_float(_lookup(index, "heading")),
        "altitude": as_float(_lookup(index, "altitude")),
        "timestamp": _lookup(index, "position_time"),
        "valid": valid,
    }


_VEHICLE_ALIAS = {
    "plate": ("plateNo", "plate", "licensePlate", "plateNumber", "carPlate"),
    "model": ("model", "vehicleModel", "modelName", "carType"),
    "series": ("series", "seriesName", "vehicleSeries"),
    "nickname": ("nickname", "vehicleName", "carName", "name", "alias"),
}


def extract_vehicle_meta(payload: Any) -> dict[str, Any]:
    """Pull human friendly vehicle metadata out of a vehicle-list entry."""
    if not isinstance(payload, dict):
        return {}
    index = build_index(payload)
    vin = index.find("vin", "VIN", "vehicleIdentificationNumber")
    return {
        "vin": vin,
        "plate": index.find(*_VEHICLE_ALIAS["plate"]),
        "model": index.find(*_VEHICLE_ALIAS["model"]),
        "series": index.find(*_VEHICLE_ALIAS["series"]),
        "nickname": index.find(*_VEHICLE_ALIAS["nickname"]),
    }


def extract_location(raw: Any) -> dict[str, Any]:
    """Convenience wrapper: extract just the position block."""
    return _extract_position(build_index(raw), raw)


def normalize_vehicle_data(raw: Any, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalise an arbitrary gateway payload into the canonical dict."""
    canonical: dict[str, Any] = {
        "vehicle": dict(meta or {}),
        "battery": {},
        "odometer": None,
        "climate": {},
        "seats": {},
        "doors": {},
        "windows": {},
        "window_pos": {},
        "tyres": {"pressure": {}, "temp": {},
                  "pressure_warning": {}, "temp_warning": {}},
        "locks": {},
        "safety": {},
        "position": {},
        "charge_plan": {},
        "travel_plan": {},
        "raw": raw,
    }

    if not isinstance(raw, dict) or not raw:
        return canonical

    index = build_index(raw)

    canonical["odometer"] = as_float(_lookup(index, "odometer"))

    # -- battery ---------------------------------------------------------
    charger_state = _lookup(index, "charger_state")
    plugged = as_bool(_lookup(index, "plugged"))
    charging = _charging_state(charger_state)
    canonical["battery"] = {
        "soc": as_float(_lookup(index, "soc")),
        "range": as_float(_lookup(index, "range")),
        "range_at_20": as_float(_lookup(index, "range_at_20")),
        "range_at_80": as_float(_lookup(index, "range_at_80")),
        "charging": charging,
        "charger_state": charger_state,
        "plugged": plugged,
        "power": as_float(_lookup(index, "charge_power")),
        "voltage": as_float(_lookup(index, "charge_voltage")),
        "current": as_float(_lookup(index, "charge_current")),
        "charge_speed": as_float(_lookup(index, "charge_speed")),
        "remaining_minutes": as_float(_lookup(index, "remaining_minutes")),
        "limit": as_float(_lookup(index, "charge_limit")),
    }

    # -- climate ---------------------------------------------------------
    canonical["climate"] = {
        "inside_temp": as_float(_lookup(index, "inside_temp")),
        "ac_on": as_bool(_lookup(index, "ac_on")),
        "defrost": as_bool(_lookup(index, "defrost")),
        "steering_wheel_heat": as_bool(_lookup(index, "steering_wheel_heat")),
        "curtain_open": as_bool(_lookup(index, "curtain_open")),
        "curtain_pos": as_int(_lookup(index, "curtain_pos")),
    }

    # -- seats -----------------------------------------------------------
    canonical["seats"] = {
        "heat": {
            "fl": as_int(_lookup(index, "seat_heat_fl")),
            "fr": as_int(_lookup(index, "seat_heat_fr")),
            "rl": as_int(_lookup(index, "seat_heat_rl")),
            "rr": as_int(_lookup(index, "seat_heat_rr")),
        },
        "vent": {
            "fl": {
                "sts": as_int(_lookup(index, "seat_vent_fl_sts")),
                "level": as_int(_lookup(index, "seat_vent_fl_level")),
            },
            "fr": {
                "sts": as_int(_lookup(index, "seat_vent_fr_sts")),
                "level": as_int(_lookup(index, "seat_vent_fr_level")),
            },
        },
    }

    # -- doors / windows -------------------------------------------------
    for pos in _POSITION_ALIASES:
        canonical["doors"][pos] = as_bool(
            _per_position(index, _DOOR_BASES, pos)
        )
        window_raw = _per_position(index, _ALIAS["window_open"], pos)
        window_pos = as_int(_per_position(index, _ALIAS["window_pos"], pos))
        canonical["windows"][pos] = _window_is_open(window_raw, window_pos)
        canonical["window_pos"][pos] = window_pos
    canonical["doors"]["trunk"] = as_bool(_lookup(index, "trunk"))
    canonical["doors"]["hood"] = as_bool(_lookup(index, "hood"))

    # -- tyres -----------------------------------------------------------
    for kind, bases in _TYRE_BASES.items():
        for pos in _POSITION_ALIASES:
            value = _per_position(index, bases, pos)
            if kind.endswith("warning"):
                canonical["tyres"][kind][pos] = as_bool(
                    value, true_tokens={"1", "true", "warn", "warning"},
                    false_tokens={"0", "2", "false", "normal", "ok"},
                )
            else:
                canonical["tyres"][kind][pos] = as_float(value)

    # -- locks (True = locked) -------------------------------------------
    central = as_bool(_lookup(index, "central_lock"))
    # Some firmwares report the charge lid as 1=open / 2=closed.
    charge_lid_raw = _lookup(index, "charge_lid_lock")
    charge_lid: bool | None
    if charge_lid_raw is None:
        charge_lid = None
    else:
        token = str(charge_lid_raw).strip().lower()
        if token in ("1", "open", "opened"):
            charge_lid = False
        elif token in ("2", "0", "closed", "close"):
            charge_lid = True
        else:
            charge_lid = None
    canonical["locks"] = {"central": central, "charge_lid": charge_lid}

    # -- safety ----------------------------------------------------------
    canonical["safety"] = {
        "park_brake": as_bool(_lookup(index, "park_brake")),
        "sentry": as_bool(_lookup(index, "sentry")),
        "engine_status": _lookup(index, "engine_status"),
        "vehicle_status": _lookup(index, "vehicle_status"),
        "speed": as_float(_lookup(index, "speed")),
    }

    # -- position --------------------------------------------------------
    canonical["position"] = _extract_position(index, raw)

    # -- plans -----------------------------------------------------------
    canonical["charge_plan"] = {
        "command": _lookup(index, "charge_plan_command"),
        "start_time": _lookup(index, "charge_plan_start"),
        "end_time": _lookup(index, "charge_plan_end"),
        "bc_cycle": index.find("chargePlan.bcCycleActive", "bcCycleActive"),
        "bc_temp": index.find("chargePlan.bcTempActive", "bcTempActive"),
    }
    canonical["travel_plan"] = {
        "command": _lookup(index, "travel_plan_command"),
        "scheduled_time": _lookup(index, "travel_plan_time"),
        "ac": _lookup(index, "travel_plan_ac"),
        "steering_wheel_heat": _lookup(index, "travel_plan_swh"),
    }

    return canonical


def _window_is_open(raw_value: Any, position: int | None) -> bool | None:
    """Interpret the window status codes.

    Observed encoding: ``1`` open (or partially), ``2`` closed, ``0`` fully
    closed.  A position > 0 also implies open.
    """
    if position is not None and position > 0:
        return True
    if raw_value is None:
        return None
    token = str(raw_value).strip().lower()
    if token in ("1", "open", "opened"):
        return True
    if token in ("2", "0", "closed", "close"):
        return False
    return None


def describe_payload(raw: Any) -> dict[str, Any]:
    """Small structured summary used by the diagnostics download."""
    if not isinstance(raw, dict):
        return {"type": type(raw).__name__}
    index = build_index(raw)
    tyre_bases = tuple(normalise_key(base) for base in _TYRE_BASES["pressure"])
    return {
        "top_level_keys": sorted(str(k) for k in raw.keys()),
        "leaf_count": len(index.leaf),
        "has_position": index.contains(*_ALIAS["latitude"]),
        "has_battery": index.contains(*_ALIAS["soc"]),
        "has_tyres": any(
            key.startswith(base) for key in index.leaf for base in tyre_bases
        ),
    }
