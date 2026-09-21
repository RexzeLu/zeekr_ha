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
      "vehicle":  {"vin", "plate", "model", "series", "brand", "nickname"},
      "battery":  {"soc", "range", "range_20soc", "range_100soc", "charging",
                   "charger_state", "plugged", "power", "voltage", "current",
                   "charge_speed", "remaining_minutes", "limit",
                   "power_consumption", "dc_pile_voltage"},
      "battery12v": {"soc", "voltage", "health"},
      "odometer": float | None,
      "trips":    {"trip1", "trip2", "avg_speed"},
      "climate":  {"inside_temp", "outside_temp", "target_temp", "ac_on",
                   "target_temp_raw", "blower", "defrost", "steering_wheel_heat",
                   "temp_reported_at",
                   "curtain_open", "curtain_open_status", "curtain_pos",
                   "sunshade_supported",
                   "sunroof_open", "sunroof_pos", "sunroof_supported"},
      "air":      {"pm25", "pm25_level", "humidity"},
      "service":  {"days_to_service", "distance_to_service", "warning"},
      "doors":    {"fl", "fr", "rl", "rr", "trunk", "hood"},
      "windows":  {"fl", "fr", "rl", "rr"},
      "window_pos": {"fl", "fr", "rl", "rr"},
      "tyres":    {"pressure": {...}, "temp": {...},
                   "pressure_warning": {...}, "temp_warning": {...}},
      "locks":    {"central", "central_status", "charge_lid", "raw": {...}},
      "safety":   {"park_brake", "sentry", "engine_status", "engine_on",
                   "vehicle_status", "speed", "alarm", "park_time"},
      "position": {"latitude", "longitude", "speed", "heading",
                   "altitude", "timestamp", "valid", "coordinate_system"},
      "charge_plan": {"command", "start_time", "end_time", "bc_cycle", "bc_temp"},
      "travel_plan": {"command", "scheduled_time", "ac", "steering_wheel_heat"},
      "raw": <original payload>,
    }

Calibration notes (observed on a real 2026.1.1 install, two vehicles
``BX1E`` + ``DC1E`` — see ``docs``/tests fixtures):

* ``chargeLevel`` exists twice, once under ``maintenanceStatus.mainBatteryStatus``
  (the 12 V aux battery) and once under ``electricVehicleStatus`` (the traction
  pack).  The pack value is the one users expect; ``_ALIAS["soc"]`` therefore
  excludes ``mainbatterystatus`` paths explicitly.
* Tyre pressure lives in ``tyreStatus{Position}`` (kPa), not ``tyrePressure*``.
* ``position.latitude`` / ``longitude`` are fixed-point integers; the divisor is
  detected at runtime (see :data:`_COORD_DIVISORS`).
* ``*LockStatus*`` fields read ``0`` when unlocked and non-zero when locked.
* ``curtainPos`` / ``sunroofPos`` / ``sunCurtainRearPos`` report ``101`` on cars
  that do not have the part at all (confirmed against a BX1E with no sunshade).
  Anything above 100 is therefore treated as "not equipped" rather than as a
  valid position.
* ``relHumSts`` has been seen at ``103``; out-of-range percentages are reported
  as unknown instead of being clamped.
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


def _alias_segments(name: str) -> list[str]:
    """Split an alias into lower-cased dotted segments.

    ``electricVehicleStatus.chargeLevel`` -> ``["electricvehiclestatus",
    "chargelevel"]``.  Keeping the boundaries is what stops ``chargeSts`` from
    matching ``disChargeSts`` (which it would if separators were stripped first).
    """
    return [seg for seg in re.split(r"[^a-z0-9]+", str(name).lower()) if seg]


class _Record:
    """One payload leaf, kept in the original plus normalised forms."""

    __slots__ = ("path", "norm", "leaf", "value")

    def __init__(self, path: str, value: Any) -> None:
        self.path = path.lower()
        self.norm = normalise_key(path)
        self.leaf = normalise_key(path.split(".")[-1])
        self.value = value


class PayloadIndex:
    """Look-up index over a payload's leaves.

    Look-ups run in three passes so a precise alias always beats a vague one:

    1. exact normalised full path (``electricvehiclestatuschargelevel``);
    2. **segment aware** dotted-path suffix match, which is what makes aliases
       such as ``electricVehicleStatus.chargeLevel`` resolve against a deeply
       nested payload without spelling out the whole path.  Because the match
       compares whole segments, ``chargeSts`` cannot be satisfied by
       ``disChargeSts``;
    3. last-segment match, also accepting an alias whose segments are flattened
       into a single field name (``chargingLimit.soc`` -> ``chargingLimitSoc``).

    ``exclude`` accepts normalised path fragments that must *not* appear in the
    resolved path.  It is what keeps ``mainBatteryStatus.chargeLevel`` (the 12 V
    aux battery) from shadowing the traction pack SOC.
    """

    __slots__ = ("full", "records")

    def __init__(self, full: dict[str, Any], records: list[_Record]) -> None:
        self.full = full
        self.records = records

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _skip(path: str, exclude: tuple[str, ...]) -> bool:
        return bool(exclude) and any(token in path for token in exclude)

    def find_with_path(self, *names: str,
                       exclude: tuple[str, ...] = ()) -> tuple[str | None, Any]:
        """Resolve *names* and also report the path the value came from."""
        wanted: list[tuple[list[str], str, str]] = []
        for name in names:
            segments = _alias_segments(name)
            if not segments:
                continue
            wanted.append((segments, normalise_key(name), segments[-1]))
        if not wanted:
            return None, None

        for segments, norm, _ in wanted:  # 1. exact full path
            value = self.full.get(norm)
            if value is not None and not self._skip(norm, exclude):
                return norm, value

        for segments, _, _ in wanted:  # 2. segment-aware dotted suffix
            depth = len(segments)
            for record in self.records:
                if record.value is None or self._skip(record.norm, exclude):
                    continue
                parts = record.path.split(".")
                if len(parts) >= depth and parts[-depth:] == segments:
                    return record.norm, record.value

        for _, norm, last in wanted:  # 3. leaf / flattened alias
            for record in self.records:
                if record.value is None or self._skip(record.norm, exclude):
                    continue
                if record.leaf == last or record.leaf == norm:
                    return record.norm, record.value

        return None, None

    def find(self, *names: str, default: Any = None,
             exclude: tuple[str, ...] = ()) -> Any:
        """Return the first alias present with a non-``None`` value."""
        _, value = self.find_with_path(*names, exclude=exclude)
        return default if value is None else value

    def contains(self, *names: str) -> bool:
        return self.find_with_path(*names)[0] is not None

    @property
    def leaf_count(self) -> int:
        return len(self.records)

    def leaf_keys(self) -> set[str]:
        return {record.leaf for record in self.records}

    def paths(self) -> list[str]:
        return [record.path for record in self.records]


def build_index(obj: Any) -> PayloadIndex:
    """Build a :class:`PayloadIndex` from an arbitrary payload."""
    full: dict[str, Any] = {}
    records: list[_Record] = []
    for path, value in _iter_leaves(obj):
        if not path:
            continue
        record = _Record(path, value)
        full.setdefault(record.norm, value)
        records.append(record)
    return PayloadIndex(full, records)


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


def _positive_float(value: Any) -> float | None:
    """Like :func:`as_float` but treats 0 as "not set".

    Several Zeekr fields answer ``"0.0"`` when they have no meaningful value
    (the AC setpoint is the one that bit us: the seat-warmer style sentinel).
    Reporting it verbatim would show a bogus 0 °C setpoint.
    """
    number = as_float(value)
    return number if number else None


# The App's temperature picker is ``LO - 16 … 28 - HI``: the two ends are
# *not* numbers.  Whatever the car uploads for them is therefore a token rather
# than a setpoint, and :func:`as_float` turns it into ``None`` — which made the
# entity fall back to its own remembered value and look like "the setpoint
# never follows the phone".
#
# ``AC_HIGH_TEMP`` is observed: a real payload reported ``currentTemperature:
# "30.0"``, above the 28 the numeric range tops out at.  ``AC_LOW_TEMP`` is the
# mirror guess and still needs a payload with the low end selected to confirm.
AC_LOW_TEMP = 15.0
AC_HIGH_TEMP = 30.0
_AC_LOW_TOKENS = {"lo", "low", "min", "mincool", "coolest", "coldest",
                  "最低", "最冷", "极低"}
_AC_HIGH_TOKENS = {"hi", "high", "max", "maxheat", "hottest", "warmest",
                   "最高", "最热", "极高"}


def _ac_setpoint(value: Any) -> float | None:
    """A setpoint, accepting the App's non-numeric ``LO`` / ``HI`` extremes."""
    number = _positive_float(value)
    if number is not None:
        return number
    token = str(value).strip().lower() if value is not None else ""
    if token in _AC_LOW_TOKENS:
        return AC_LOW_TEMP
    if token in _AC_HIGH_TOKENS:
        return AC_HIGH_TEMP
    return None


_TRUE_TOKENS = {"1", "true", "on", "yes", "open", "opened", "active", "running",
                "locked", "armed", "engine_on"}
_FALSE_TOKENS = {"0", "2", "false", "off", "no", "close", "closed", "inactive",
                 "stopped", "idle", "none", "unlocked", "disarmed",
                 "engine_off"}


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


def _duration_minutes(value: Any) -> float | None:
    """Coerce a "minutes to full" value, dropping the backend's sentinel.

    ``2047`` is the "no estimate" sentinel returned while idle; ``0`` likewise
    means there is nothing to report.
    """
    minutes = as_float(value)
    if minutes is None or minutes <= 0 or minutes >= 2047:
        return None
    return minutes


def _charge_limit(value: Any) -> float | None:
    """Normalise the charge limit to a percentage.

    The gateway reports it in tenths on some channels — GRIC answers ``950`` for
    a 95 % limit — and in whole percent on others.  A limit can never exceed
    100 %, so anything above that is scaled down rather than taken at face
    value (``950 %`` in the UI is how this was found).
    """
    number = as_float(value)
    if number is None:
        return None
    if number > 100:
        number /= 10.0
    return number


def _percent(value: Any) -> float | None:
    """Coerce a 0..100 percentage, rejecting out-of-range readings.

    ``relHumSts`` has been observed at ``103``, which is impossible for
    humidity, so an out-of-range value is reported as "no reading" instead of
    being silently clamped to a plausible-looking number.
    """
    number = as_float(value)
    if number is None or number < 0 or number > 100:
        return None
    return number


def _resolve_opening(
    raw_position: Any, raw_status: Any
) -> tuple[bool | None, float | None, bool | None]:
    """Resolve a sunshade / sunroof style opening.

    Returns ``(is_open, position, supported)``.

    A ``*Pos`` value above 100 is a "not equipped" sentinel: cars without a
    sunshade or an opening roof report the very same ``101`` for ``curtainPos``,
    ``sunroofPos`` and ``sunCurtainRearPos``, and the accompanying
    ``*OpenStatus`` (``1``) carries no meaning in that case.  Reporting
    ``supported = False`` lets the cover entity go unavailable rather than
    claiming a part the car does not have is open.
    """
    if raw_position is None:
        # No position field at all: trust the plain status flag.
        return _open_state(raw_status, None), None, None
    position = as_float(raw_position)
    if position is None or position < 0 or position > 100:
        return None, None, False
    return position > 0, position, True


# ---------------------------------------------------------------------------
# Alias tables
# ---------------------------------------------------------------------------

_ALIAS = {
    # battery / charging
    # NB: dotted aliases resolve through full-path suffix matching, so
    # ``chargingLimit.soc`` can never shadow the traction pack SOC.
    "soc": ("electricVehicleStatus.chargeLevel", "batteryLevel",
            "powerBatteryLevel", "batterySoc", "evSoc", "soc",
            "remainingBatteryPercentage"),
    "range": ("distanceToEmptyOnBatteryOnly", "remainKm", "remainingRange",
              "evRange", "electricRange", "range", "distanceToEmpty"),
    "range_20soc": ("distanceToEmptyOnBattery20Soc", "mileageAt20Soc",
                    "rangeAt20Soc"),
    "range_100soc": ("distanceToEmptyOnBattery100Soc", "mileageAt100Soc",
                     "rangeAt100Soc"),
    "charger_state": ("chargeSts", "chargeStatus", "chargerState",
                      "chargingStatus", "chargeState", "chargingState",
                      "bmsChargingStatus"),
    "plugged": ("statusOfChargerConnection", "chargePlugStatus", "plugStatus",
                "plugged", "chargeGunStatus", "chargingGunStatus"),
    "charge_power": ("chargePower", "chargingPower", "chargePowerKw",
                     "dcChargePower", "acChargePower"),
    "charge_voltage": ("chargeUAct", "chargeVoltage", "bmsChargeVoltage",
                       "chargingVoltage"),
    "charge_current": ("chargeIAct", "chargeCurrent", "bmsChargeCurrent",
                       "chargingCurrent"),
    "charge_speed": ("chargeSpeed", "chargingSpeed", "chargeRate",
                     "chargingRate"),
    "remaining_minutes": ("timeToFullyCharged", "remainingChargeTime",
                          "remainingChargingTime", "leftChargeTime"),
    "charge_limit": ("chargingLimit.soc", "chargingLimitSoc", "chargeLimitSoc",
                     "chargeLimit", "socLimit", "targetSoc", "maxSoc"),
    "power_consumption": ("averPowerConsumption", "averagePowerConsumption",
                          "powerConsumption", "avgPowerConsumption"),
    "dc_pile_voltage": ("dcChargePileUAct", "dcChargePileVoltage"),
    # 12 V aux battery
    "aux_battery_soc": ("mainBatteryStatus.chargeLevel", "auxBatterySoc",
                        "battery12vSoc"),
    "aux_battery_voltage": ("mainBatteryStatus.voltage", "auxBatteryVoltage",
                            "battery12vVoltage"),
    "aux_battery_health": ("mainBatteryStatus.stateOfHealth",
                           "auxBatteryHealth"),
    # odometer / trips
    "odometer": ("maintenanceStatus.odometer", "totalOdometer", "odometer",
                 "totalMileage", "totalDistance", "vehicleMileage"),
    "trip1": ("tripMeter1", "trip1", "tripAMeter"),
    "trip2": ("tripMeter2", "trip2", "tripBMeter"),
    "avg_speed": ("avgSpeed", "averageSpeed"),
    # climate
    "inside_temp": ("climateStatus.interiorTemp", "interiorTemp",
                    "temperatureInside", "cabinTemp", "insideTemp",
                    "temperatureInCar", "carInsideTemp"),
    "outside_temp": ("exteriorTemp", "outsideTemp", "ambientTemp",
                     "externalTemp"),
    # ``currentTemperature`` is the AC setpoint the app pushes; unset reads as
    # "0.0", which is meaningless rather than cold, so 0 is mapped to None below.
    "target_temp": ("currentTemperature", "temperatureSetting",
                    "targetTemperature", "acTemperature", "acTemprature"),
    # When the car last uploaded the climate block.  Without it there is no way
    # to tell "the car has not uploaded yet" apart from "the integration is not
    # reading the value" — the two look identical from Home Assistant.
    "temp_reported_at": ("climateStatus.temperatureUpdateTime",
                         "temperatureUpdateTime"),
    # ``preClimateActive`` is the AC indicator; ``airBlowerActive`` is the cabin
    # blower, which on this platform only flips for the air-purification
    # (G-Clean) run.  An earlier revision read the blower first, so the AC showed
    # as off in Home Assistant even while it was running.
    #
    # ``climateStatus.activeStatus`` is deliberately *not* one of the aliases
    # below: a real GRIC payload with the AC, the blower and the defrost *all*
    # off still reports ``activeStatus: "1"``, so reading it pinned the climate
    # entity to "on" forever.  It also silently outranked ``preClimateActive``:
    # a dotted alias normalises to an exact full path, and those are resolved in
    # the first pass — ahead of the leaf match a single-segment alias needs.
    "ac_on": ("preClimateActive", "acStatus", "acOn", "airConditionerStatus",
              "airConStatus", "climateActive"),
    "blower": ("airBlowerActive", "blowerActive", "fanStatus"),
    "defrost": ("defrostStatus", "frontDefrostStatus", "climateStatus.defrost",
                "defrost", "dfStatus"),
    "steering_wheel_heat": ("steerWhlHeatingSts", "steeringWheelHeat",
                            "steeringWheelHeatingStatus", "swhStatus",
                            "steerWheelHeatStatus"),
    "curtain_open": ("curtainOpenStatus", "sunshadeOpenStatus", "curtainStatus",
                     "sunShadeStatus"),
    "curtain_pos": ("curtainPos", "sunshadePosition", "curtainPosition"),
    "sunroof_open": ("sunroofOpenStatus", "sunRoofOpenStatus"),
    "sunroof_pos": ("sunroofPos", "sunRoofPos"),
    # air quality
    "pm25": ("interiorPM25", "pm25", "pm2p5"),
    "pm25_level": ("interiorPM25Level", "pm25Level"),
    "humidity": ("relHumSts", "relativeHumidity", "humidity"),
    # service
    "days_to_service": ("daysToService", "remainingDaysToService"),
    "distance_to_service": ("distanceToService", "remainingDistanceToService"),
    "service_warning": ("serviceWarningStatus", "serviceWarning"),
    # locks / safety
    "central_lock": ("centralLockingStatus", "centralLockStatus",
                     "vehicleLockStatus", "lockStatus"),
    "charge_lid_lock": ("chargeLidDcAcStatus", "chargeLidAcStatus",
                        "chargeLidStatus", "chargePortLidStatus",
                        "chargePortStatus", "chargeLid"),
    "park_brake": ("electricParkBrakeStatus", "parkBrakeStatus", "epbStatus",
                   "parkingBrakeStatus"),
    "sentry": ("vstdModeState", "sentryMode", "sentryModeState",
               "remoteControlState.vstdModeState"),
    "engine_status": ("engineStatus", "drivingState", "vehicleState"),
    "vehicle_status": ("usageMode", "vehicleState", "drivingState"),
    "alarm": ("vehicleAlarm.alrmSt", "alarmStatus", "alrmSt"),
    "park_time": ("parkTime.status", "parkTime"),
    "speed": ("speed", "vehicleSpeed", "currentSpeed", "velocity"),
    "trunk": ("trunkOpenStatus", "trunkStatus", "trunkDoorStatus",
              "tailGateStatus"),
    "hood": ("engineHoodOpenStatus", "hoodStatus", "hoodOpenStatus",
             "frontHoodStatus", "bonnetStatus"),
    # windows
    "window_open": ("winStatus", "windowStatus", "winOpenStatus",
                    "windowOpenStatus"),
    "window_pos": ("winPos", "windowPosition", "winPosition",
                   "windowOpenPercent"),
    # seats (heat level 0-3; vent comes as a status + detail pair)
    #
    # The ``*HeatLv`` spellings come first because they are what this platform
    # actually sends: the status payload carries ``drvHeatLv`` / ``passHeatLv`` /
    # ``rlHeatLv`` / ``rrHeatLv``.  The ``*HeatSts`` aliases below never matched
    # anything, which left every seat heater reading as unknown.
    "seat_heat_fl": ("drvHeatLv", "drvHeatSts", "driverHeatStatus",
                     "driverHeatLevel", "seatHeatDriver"),
    "seat_heat_fr": ("passHeatLv", "passHeatingSts", "passHeatSts",
                     "passengerHeatStatus", "passengerHeatLevel"),
    "seat_heat_rl": ("rlHeatLv", "rlHeatingSts", "rearLeftHeatSts",
                     "seatHeatRearLeft"),
    "seat_heat_rr": ("rrHeatLv", "rrHeatingSts", "rearRightHeatSts",
                     "seatHeatRearRight"),
    "seat_vent_fl_sts": ("drvVentSts", "driverVentStatus"),
    "seat_vent_fl_level": ("drvVentDetail", "driverVentLevel"),
    "seat_vent_fr_sts": ("passVentSts", "passengerVentStatus"),
    "seat_vent_fr_level": ("passVentDetail", "passengerVentLevel"),
    # position
    "latitude": ("basicVehicleStatus.position.latitude", "position.latitude",
                 "latitude", "lat", "gpsLatitude", "gpsLat",
                 "location.latitude", "gps.latitude", "lastPosition.latitude"),
    "longitude": ("basicVehicleStatus.position.longitude",
                  "position.longitude", "longitude", "lon", "lng",
                  "gpsLongitude", "gpsLon", "location.longitude",
                  "gps.longitude", "lastPosition.longitude"),
    "heading": ("direction", "heading", "course", "position.heading",
                "gpsHeading", "bearing"),
    "altitude": ("position.altitude", "altitude", "elevation", "gpsAltitude"),
    "position_time": ("updateTime", "positionTime", "gpsTime", "timestamp",
                      "position.timestamp", "locationTime", "reportTime",
                      "positionUpdateTime"),
    "position_trusted": ("position.posCanBeTrusted", "posCanBeTrusted",
                         "positionTrusted"),
    "position_frame": ("position.marsCoordinates", "marsCoordinates"),
    # ``updateTime`` is the car's *own* upload stamp.  It is the only way to
    # tell "Home Assistant polled a while ago" apart from "the car has not
    # reported for a while" — and therefore whether a shorter polling interval
    # can buy anything at all.
    "report_time": ("updateTime", "statusTime", "vehicleStatusTime",
                    "statusUpdateTime", "reportTime"),
    # plans
    "charge_plan_command": ("chargePlan.command", "chargePlanCommand",
                            "chargeScheduleCommand"),
    "charge_plan_start": ("chargePlan.startTime", "chargeStartTime",
                          "chargePlanStartTime", "startTime"),
    "charge_plan_end": ("chargePlan.endTime", "chargeEndTime",
                        "chargePlanEndTime", "endTime"),
    "charge_plan_bc_cycle": ("chargePlan.bcCycleActive", "bcCycleActive"),
    "charge_plan_bc_temp": ("chargePlan.bcTempActive", "bcTempActive"),
    "travel_plan_command": ("travelPlan.command", "travelPlanCommand"),
    "travel_plan_time": ("travelPlan.scheduledTime", "scheduledTime",
                         "departureTime", "travelPlanTime"),
    "travel_plan_ac": ("travelPlan.ac", "departureAc", "travelAc"),
    "travel_plan_swh": ("travelPlan.bw", "departureSwh"),
}

# Position suffixes seen in the wild -> canonical position key.
# ``Driver`` / ``Passenger`` are front-left / front-right on a LHD car.
_POSITION_ALIASES: dict[str, tuple[str, ...]] = {
    "fl": ("driver", "frontleft", "lhdfrontleft", "leftfront", "fl"),
    "fr": ("passenger", "frontright", "lhdfrontright", "rightfront", "fr"),
    "rl": ("driverrear", "rearleft", "lhdrearleft", "leftrear", "rl"),
    "rr": ("passengerrear", "rearright", "lhdrearright", "rightrear", "rr"),
}

_TYRE_BASES = {
    "pressure": ("tyreStatus", "tireStatus", "tyrePressure", "tyrePress",
                 "tirePressure", "tirePress", "tyrePres"),
    "temp": ("tyreTemp", "tyreTemperature", "tireTemp", "tireTemperature",
             "tyreTemprature", "tireTemprature"),
    "pressure_warning": ("tyrePreWarning", "tyrePressureWarning",
                         "tirePressureWarning", "tyrePreWarn",
                         "tyrePressureWarn"),
    "temp_warning": ("tyreTempWarning", "tyreTemperatureWarning",
                     "tireTempWarning", "tyreTempWarn", "tyreTemperatureWarn"),
}

_DOOR_BASES = ("doorOpenStatus", "doorStatus", "doorOpen", "doorOpenedStatus")
_LOCK_BASES = ("doorLockStatus", "doorLock")
_TRUNK_LOCK_BASES = ("trunkLockStatus", "tailGateLockStatus")

_COORD_RE = re.compile(
    r"(-?\d{1,3}\.\d{3,})\s*[,;: ]\s*(-?\d{1,3}\.\d{3,})"
)

# Charging status codes.  ``0`` means idle on every payload seen so far; the
# active codes are still empirical and may need widening once a real charging
# session is captured (see ``docs``/diagnostics output).
_CHARGING_ACTIVE = {"1", "2", "3", "4", "5", "6", "7", "8", "15", "16", "17",
                    "18", "charging", "inprogress"}
_CHARGING_IDLE = {"0", "25", "26", "9", "10", "11", "12", "13", "14",
                  "idle", "stopped", "finished", "complete", "completed",
                  "notcharging"}

# ``latitude`` / ``longitude`` are fixed-point integers.  ``BX1E`` and ``DC1E``
# report degrees x 3_600_000; other firmwares use degrees x 1e7 or x 1e6.  The
# right divisor is detected per payload by requiring both axes to land inside
# mainland China before falling back to globally valid ranges.
_COORD_DIVISORS = (3_600_000.0, 10_000_000.0, 1_000_000.0, 1.0)
_LAT_RANGE = (15.0, 54.5)
_LON_RANGE = (72.0, 136.0)


def _lookup(index: PayloadIndex, key: str, **kwargs: Any) -> Any:
    return index.find(*_ALIAS[key], **kwargs)


def _lookup_path(index: PayloadIndex, key: str, **kwargs: Any) -> tuple[str | None, Any]:
    return index.find_with_path(*_ALIAS[key], **kwargs)


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


def _is_null_point(latitude: float | None, longitude: float | None) -> bool:
    return ((latitude is None or abs(latitude) < 1e-6)
            and (longitude is None or abs(longitude) < 1e-6))


def _in_china(latitude: float | None, longitude: float | None) -> bool:
    if latitude is None and longitude is None:
        return False
    if latitude is not None and not _LAT_RANGE[0] <= latitude <= _LAT_RANGE[1]:
        return False
    if longitude is not None and not _LON_RANGE[0] <= longitude <= _LON_RANGE[1]:
        return False
    return not _is_null_point(latitude, longitude)


def _globally_valid(latitude: float | None, longitude: float | None) -> bool:
    if latitude is None and longitude is None:
        return False
    if latitude is not None and not -90.0 <= latitude <= 90.0:
        return False
    if longitude is not None and not -180.0 <= longitude <= 180.0:
        return False
    return not _is_null_point(latitude, longitude)


def _normalise_coords(latitude: Any, longitude: Any
                      ) -> tuple[float | None, float | None]:
    """Resolve the fixed-point encoding used by the gateway.

    Both axes are required to land inside mainland China for the candidate
    divisor to be accepted; that is safe because the integration only supports
    China-mainland accounts.  A globally-valid fallback covers exported cars.
    """
    lat = as_float(latitude)
    lon = as_float(longitude)
    if lat is None and lon is None:
        return None, None

    for divisor in _COORD_DIVISORS:
        lat_c = None if lat is None else lat / divisor
        lon_c = None if lon is None else lon / divisor
        if _in_china(lat_c, lon_c):
            return lat_c, lon_c

    for divisor in _COORD_DIVISORS:
        lat_c = None if lat is None else lat / divisor
        lon_c = None if lon is None else lon / divisor
        if _globally_valid(lat_c, lon_c):
            return lat_c, lon_c

    _LOGGER.debug("无法解析坐标: %s / %s", latitude, longitude)
    return None, None


def _extract_position(index: PayloadIndex, raw: Any) -> dict[str, Any]:
    """Extract GPS position from structured or string payloads."""
    latitude_raw = _lookup(index, "latitude")
    longitude_raw = _lookup(index, "longitude")
    latitude, longitude = _normalise_coords(latitude_raw, longitude_raw)

    if latitude is None or longitude is None:
        # Some endpoints return "lat,lon" inside a single string field, already
        # expressed in plain degrees.
        for _, value in _iter_leaves(raw):
            if not isinstance(value, str):
                continue
            match = _COORD_RE.search(value)
            if match:
                candidate_lat = as_float(match.group(1))
                candidate_lon = as_float(match.group(2))
                if _in_china(candidate_lat, candidate_lon):
                    latitude, longitude = candidate_lat, candidate_lon
                    break

    trusted = as_bool(_lookup(index, "position_trusted"))
    has_fix = latitude is not None and longitude is not None
    # ``posCanBeTrusted`` is the backend's own opinion; when it is absent fall
    # back to "the coordinates look sane".
    valid = trusted if trusted is not None else has_fix

    frame_raw = _lookup(index, "position_frame")
    if frame_raw is None:
        frame = None
    else:
        frame = "gcj02" if as_bool(frame_raw) else "wgs84"

    return {
        "latitude": latitude,
        "longitude": longitude,
        "speed": as_float(_lookup(index, "speed")),
        "heading": as_float(_lookup(index, "heading")),
        "altitude": as_float(_lookup(index, "altitude")),
        "timestamp": _lookup(index, "position_time"),
        "valid": valid,
        "has_fix": has_fix,
        "coordinate_system": frame,
    }


_VEHICLE_ALIAS = {
    "plate": ("plateNo", "plateNum", "plateNumber", "licensePlate", "carPlate",
              "plate"),
    "model": ("model", "modelName", "vehicleModel", "vehModel", "carType"),
    "series": ("series", "seriesName", "seriesCode", "vehicleSeries"),
    # ``brandCode`` is how the GRIC vehicle list names the brand ("ZEEKR");
    # the SNC list uses ``brandName``.
    "brand": ("brandName", "brand", "vehicleBrand", "brandCode"),
    "nickname": ("nickName", "nickname", "vehName", "vehicleName",
                 "carNickName", "vehicleNickName", "userVehicleName",
                 "displayName", "carName", "alias", "name"),
}


def _clean_text(value: Any) -> str | None:
    """Trim a string field, turning blank values into ``None``.

    The backend happily returns ``"plateNo": ""`` for a car without a plate;
    left as an empty string it is falsy but still looks like real data in the
    diagnostics (and silently falls through the device-name chain).
    """
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_vehicle_meta(payload: Any) -> dict[str, Any]:
    """Pull human friendly vehicle metadata out of a vehicle-list entry."""
    if not isinstance(payload, dict):
        return {}
    index = build_index(payload)
    vin = _clean_text(index.find("vin", "VIN", "vehicleIdentificationNumber"))
    return {
        "vin": vin,
        "plate": _clean_text(index.find(*_VEHICLE_ALIAS["plate"])),
        "model": _clean_text(index.find(*_VEHICLE_ALIAS["model"])),
        "series": _clean_text(index.find(*_VEHICLE_ALIAS["series"])),
        "brand": _clean_text(index.find(*_VEHICLE_ALIAS["brand"])),
        "nickname": _clean_text(index.find(*_VEHICLE_ALIAS["nickname"])),
    }


# Marketing names for the Zeekr platform codes that show up in ``series``.
#
# The vehicle list also carries ``modelName``, but that is the *catalogue trim*
# and it cannot be trusted: the Guangzhou 极氪 X (a four-seat AWD car) is
# returned as ``modelName = "四座后驱版-001"`` — the drive type does not even
# match the actual car.  The platform code is the only label we can rely on
# offline, so it wins over the trim.  Codes we do not know keep whatever the
# backend sent, so a new model still shows something sensible.
_SERIES_DISPLAY_NAMES = {
    "bx1e": "极氪 X",
    "dc1e": "极氪 001",
}

# ``"四座后驱版-001"`` / ``"YOU版-013"`` / ``"X (001)"`` -> drop the trailing
# catalogue index.  A separator is required so a real name like ``极氪001`` is
# never mangled.
_VARIANT_SUFFIX_RE = re.compile(
    r"(?:\s*[-_·]\s*\d{1,4}|\s*[（(]\s*\d{1,4}\s*[)）])\s*$"
)


def _strip_variant_suffix(value: Any) -> str | None:
    """Drop the trailing catalogue index from a backend model name."""
    text = _clean_text(value)
    if not text:
        return None
    stripped = _VARIANT_SUFFIX_RE.sub("", text).strip()
    return stripped or text


def vehicle_series_name(meta: dict[str, Any] | None) -> str | None:
    """Return the most trustworthy model label we can derive offline.

    Used for the device's *name* and *model*: the platform marketing name when
    the series code is known, otherwise the backend's trim with its trailing
    index stripped, otherwise the raw series code.
    """
    meta = meta or {}
    series = _clean_text(meta.get("series"))
    if series and (known := _SERIES_DISPLAY_NAMES.get(series.lower())):
        return known
    return _strip_variant_suffix(meta.get("model")) or series


def vehicle_display_name(meta: dict[str, Any] | None) -> str:
    """Pick a human friendly device name for a vehicle.

    Order matters: the user's own name for the car wins, then the plate, then
    the platform marketing name / catalogue trim.  Falling back to the VIN is a
    last resort — it used to be hit for every car without a plate, which is why
    devices showed up named after their VIN.
    """
    meta = meta or {}
    for key in ("nickname", "plate"):
        value = _clean_text(meta.get(key))
        if value:
            return value
    if series_name := vehicle_series_name(meta):
        return series_name
    return _clean_text(meta.get("vin")) or "Zeekr EV"


def extract_location(raw: Any) -> dict[str, Any]:
    """Convenience wrapper: extract just the position block."""
    return _extract_position(build_index(raw), raw)


def _lock_state(value: Any) -> bool | None:
    """Interpret a ``*LockStatus*`` field.

    Observed encoding: ``0`` = unlocked, any non-zero = locked.  ``None`` means
    the field was missing or carried an unrecognised token.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    token = str(value).strip().lower()
    if token in ("locked", "lock", "true"):
        return True
    if token in ("unlocked", "unlock", "false"):
        return False
    number = as_int(token)
    if number is None:
        return None
    return number != 0


def _charge_lid_closed(value: Any) -> bool | None:
    """Charge flap: ``1`` = open on the firmwares seen, ``0``/``2`` = closed."""
    if value is None:
        return None
    token = str(value).strip().lower()
    if token in ("1", "open", "opened"):
        return False
    if token in ("0", "2", "closed", "close"):
        return True
    return None


def _open_state(status: Any, position: float | None) -> bool | None:
    """Resolve an open/closed flag, preferring the continuous position.

    ``*OpenStatus`` uses ``1`` = open / ``2`` = closed.  A known position wins
    because it cannot be confused with a status flag.
    """
    if position is not None:
        return position > 0
    if status is None:
        return None
    token = str(status).strip().lower()
    if token in ("1", "open", "opened", "true"):
        return True
    if token in ("0", "2", "closed", "close", "false"):
        return False
    return None


def _window_is_open(raw_value: Any, position: int | None) -> bool | None:
    """Interpret the window status codes.

    Observed encoding: ``1`` open, ``2``/``0`` closed.  A position > 0 also
    implies open.
    """
    return _open_state(raw_value, None if position is None else float(position))


def _central_lock(index: PayloadIndex) -> tuple[bool | None, dict[str, Any]]:
    """Derive the central lock state from the per-door flags when possible."""
    per_door: dict[str, Any] = {}
    states: list[bool] = []
    for pos in _POSITION_ALIASES:
        raw = _per_position(index, _LOCK_BASES, pos)
        per_door[pos] = as_int(raw) if raw is not None else None
        state = _lock_state(raw)
        if state is not None:
            states.append(state)

    trunk_raw = index.find(*_TRUNK_LOCK_BASES)
    per_door["trunk"] = as_int(trunk_raw) if trunk_raw is not None else None

    if states:
        if all(states):
            return True, per_door
        if not any(states):
            return False, per_door
        # Mixed report: trust the central flag if it is available.
    central = _lock_state(_lookup(index, "central_lock"))
    if central is not None:
        return central, per_door
    if states:
        return any(states), per_door
    return None, per_door


def normalize_vehicle_data(raw: Any, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalise an arbitrary gateway payload into the canonical dict."""
    canonical: dict[str, Any] = {
        "vehicle": dict(meta or {}),
        "battery": {},
        "battery12v": {},
        "odometer": None,
        "trips": {},
        "climate": {},
        "air": {},
        "service": {},
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
    # ``chargeLevel`` also exists on the 12 V aux battery, so exclude it here.
    soc = _lookup(index, "soc", exclude=("mainbatterystatus",))
    if soc is None:
        soc = index.find("chargeLevel", "soc",
                         exclude=("mainbatterystatus", "charginglimit"))

    charger_state = _lookup(index, "charger_state")
    charging = _charging_state(charger_state)
    current = as_float(_lookup(index, "charge_current"))
    voltage = as_float(_lookup(index, "charge_voltage"))
    power = as_float(_lookup(index, "charge_power"))
    if power is None and voltage is not None and current is not None:
        power = round(voltage * current / 1000.0, 2) or None
    if charging is None and current is not None:
        # Current actually flowing is the most reliable "charging" signal.
        charging = current > 0 if charging is None else charging

    canonical["battery"] = {
        "soc": as_float(soc),
        "range": as_float(_lookup(index, "range")),
        "range_20soc": as_float(_lookup(index, "range_20soc")),
        "range_100soc": as_float(_lookup(index, "range_100soc")),
        "charging": charging,
        "charger_state": charger_state,
        "plugged": as_bool(_lookup(index, "plugged")),
        "power": power,
        "voltage": voltage,
        "current": current,
        "charge_speed": as_float(_lookup(index, "charge_speed")),
        "remaining_minutes": _duration_minutes(_lookup(index, "remaining_minutes")),
        "limit": _charge_limit(_lookup(index, "charge_limit")),
        "power_consumption": as_float(_lookup(index, "power_consumption")),
        "dc_pile_voltage": as_float(_lookup(index, "dc_pile_voltage")),
    }

    # -- 12 V aux battery ------------------------------------------------
    canonical["battery12v"] = {
        "soc": as_float(_lookup(index, "aux_battery_soc", 
                                exclude=("electricvehiclestatus",))),
        "voltage": as_float(_lookup(index, "aux_battery_voltage")),
        "health": as_float(_lookup(index, "aux_battery_health")),
    }

    # -- trips -----------------------------------------------------------
    canonical["trips"] = {
        "trip1": as_float(_lookup(index, "trip1")),
        "trip2": as_float(_lookup(index, "trip2")),
        "avg_speed": as_float(_lookup(index, "avg_speed")),
    }

    # -- climate ---------------------------------------------------------
    curtain_status = _lookup(index, "curtain_open")
    curtain_open, curtain_pos, sunshade_supported = _resolve_opening(
        _lookup(index, "curtain_pos"), curtain_status
    )
    sunroof_open, sunroof_pos, sunroof_supported = _resolve_opening(
        _lookup(index, "sunroof_pos"), _lookup(index, "sunroof_open")
    )
    raw_setpoint = _lookup(index, "target_temp")
    canonical["climate"] = {
        "inside_temp": as_float(_lookup(index, "inside_temp")),
        "outside_temp": as_float(_lookup(index, "outside_temp")),
        # 0.0 is the "no setpoint" sentinel, not a temperature.
        "target_temp": _ac_setpoint(raw_setpoint),
        # Kept verbatim so a "LO"/"HI" style upload is visible instead of
        # silently turning into a number we guessed.
        "target_temp_raw": None if raw_setpoint is None else str(raw_setpoint),
        "temp_reported_at": as_int(_lookup(index, "temp_reported_at")),
        "ac_on": as_bool(_lookup(index, "ac_on")),
        "blower": as_bool(_lookup(index, "blower")),
        "defrost": as_bool(_lookup(index, "defrost")),
        "steering_wheel_heat": as_bool(_lookup(index, "steering_wheel_heat")),
        "curtain_open": curtain_open,
        "curtain_open_status": curtain_status,
        "curtain_pos": curtain_pos,
        "sunshade_supported": sunshade_supported,
        "sunroof_open": sunroof_open,
        "sunroof_pos": sunroof_pos,
        "sunroof_supported": sunroof_supported,
    }

    # -- air quality / service -------------------------------------------
    canonical["air"] = {
        "pm25": as_float(_lookup(index, "pm25")),
        "pm25_level": as_float(_lookup(index, "pm25_level")),
        "humidity": _percent(_lookup(index, "humidity")),
    }
    canonical["service"] = {
        "days_to_service": as_float(_lookup(index, "days_to_service")),
        "distance_to_service": as_float(_lookup(index, "distance_to_service")),
        "warning": as_bool(_lookup(index, "service_warning")),
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
        window_status = _per_position(index, _ALIAS["window_open"], pos)
        window_pos = as_int(_per_position(index, _ALIAS["window_pos"], pos))
        canonical["windows"][pos] = _window_is_open(window_status, window_pos)
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

    # -- locks (True = locked / closed) ----------------------------------
    central, lock_raw = _central_lock(index)
    canonical["locks"] = {
        "central": central,
        "central_status": as_int(_lookup(index, "central_lock")),
        "charge_lid": _charge_lid_closed(_lookup(index, "charge_lid_lock")),
        "raw": lock_raw,
    }

    # -- safety ----------------------------------------------------------
    engine_status = _lookup(index, "engine_status")
    canonical["safety"] = {
        "park_brake": as_bool(_lookup(index, "park_brake")),
        "sentry": as_bool(_lookup(index, "sentry")),
        "engine_status": engine_status,
        "engine_on": as_bool(engine_status),
        "vehicle_status": _lookup(index, "vehicle_status"),
        "speed": as_float(_lookup(index, "speed")),
        "alarm": as_int(_lookup(index, "alarm")),
        "park_time": _lookup(index, "park_time"),
    }

    # -- position --------------------------------------------------------
    canonical["position"] = _extract_position(index, raw)

    # -- freshness -------------------------------------------------------
    # When the car last uploaded, not when we last asked.  Exposed so a stale
    # entity can be told apart from a stale poll.
    canonical["report_time"] = _lookup(index, "report_time")

    # -- plans -----------------------------------------------------------
    canonical["charge_plan"] = {
        "command": _lookup(index, "charge_plan_command"),
        "start_time": _lookup(index, "charge_plan_start"),
        "end_time": _lookup(index, "charge_plan_end"),
        "bc_cycle": _lookup(index, "charge_plan_bc_cycle"),
        "bc_temp": _lookup(index, "charge_plan_bc_temp"),
    }
    canonical["travel_plan"] = {
        "command": _lookup(index, "travel_plan_command"),
        "scheduled_time": _lookup(index, "travel_plan_time"),
        "ac": _lookup(index, "travel_plan_ac"),
        "steering_wheel_heat": _lookup(index, "travel_plan_swh"),
    }

    return canonical


# Canonical leaf -> alias table key.  Used by ``describe_payload`` to report
# which payload field every important value was resolved from, which makes
# calibrating a new firmware a single round-trip.
_PROBE_FIELDS: tuple[tuple[str, str], ...] = (
    ("battery.soc", "soc"),
    ("battery.range", "range"),
    ("battery.charging", "charger_state"),
    ("battery.plugged", "plugged"),
    ("battery.remaining_minutes", "remaining_minutes"),
    ("battery.limit", "charge_limit"),
    ("battery12v.soc", "aux_battery_soc"),
    ("battery12v.voltage", "aux_battery_voltage"),
    ("odometer", "odometer"),
    ("climate.inside_temp", "inside_temp"),
    ("climate.outside_temp", "outside_temp"),
    ("climate.target_temp", "target_temp"),
    ("climate.ac_on", "ac_on"),
    ("climate.curtain_pos", "curtain_pos"),
    ("locks.central", "central_lock"),
    ("locks.charge_lid", "charge_lid_lock"),
    ("position.latitude", "latitude"),
    ("position.longitude", "longitude"),
    ("position.valid", "position_trusted"),
    ("tyres.pressure.fl", "tyre_status_probe"),
    ("air.pm25", "pm25"),
    ("service.days_to_service", "days_to_service"),
    ("report_time", "report_time"),
)


def describe_payload(raw: Any) -> dict[str, Any]:
    """Small structured summary used by the diagnostics download."""
    if not isinstance(raw, dict):
        return {"type": type(raw).__name__}
    index = build_index(raw)

    tyre_pressure_keys = tuple(
        normalise_key(base) for base in _TYRE_BASES["pressure"]
    )
    has_tyres = any(
        key.startswith(base) for key in index.leaf_keys()
        for base in tyre_pressure_keys
    )

    resolved: dict[str, Any] = {}
    for label, alias_key in _PROBE_FIELDS:
        if alias_key == "tyre_status_probe":
            path, value = index.find_with_path(
                *(f"{base}driver" for base in _TYRE_BASES["pressure"]),
                "tyreStatusDriver", "tyrePressureDriver", "tirePressureDriver",
            )
        else:
            path, value = _lookup_path(index, alias_key)
        resolved[label] = {"path": path, "value": value}

    return {
        "top_level_keys": sorted(str(k) for k in raw.keys()),
        "leaf_count": index.leaf_count,
        "has_position": index.contains(*_ALIAS["latitude"]),
        "has_battery": index.contains(*_ALIAS["soc"]),
        "has_tyres": has_tyres,
        "resolved": resolved,
    }
