"""Regression tests for the tolerant payload parser.

The fixtures under ``tests/fixtures`` are real gateway responses captured from
a 2026.1.1 install (two vehicles, a ``BX1E`` and a ``DC1E``) with the VINs and
the plate scrubbed.  They encode a number of traps that already cost us one
debugging round, so they are asserted explicitly:

* ``chargeLevel`` exists on both the 12 V aux battery and the traction pack;
* ``chargerState`` must not be satisfied by ``disChargeSts``;
* tyre pressure lives in ``tyreStatus*`` (kPa), not ``tyrePressure*``;
* GPS coordinates are fixed-point integers (degrees x 3_600_000 here);
* ``timeToFullyCharged`` reports ``2047`` as a "no estimate" sentinel;
* ``pm25`` must not be shadowed by ``interiorPM25Level``.

The parser module is loaded straight from its file so the suite runs without a
Home Assistant installation.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PARSER_PATH = _ROOT / "custom_components" / "zeekr_ev" / "parser.py"
_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vehicle_payload.json"

_spec = importlib.util.spec_from_file_location("zeekr_parser", _PARSER_PATH)
parser = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(parser)

VIN_X = "LTESTVIN0000000001"   # BX1E, 四座后驱版
VIN_001 = "LTESTVIN0000000002"  # DC1E, YOU版


@pytest.fixture(scope="module")
def fixture() -> dict:
    with _FIXTURE.open(encoding="utf-8") as handle:
        return json.load(handle)


def _normalise(fixture: dict, vin: str) -> dict:
    meta = next(v for v in fixture["vehicles"] if v["vin"] == vin)
    return parser.normalize_vehicle_data(fixture["payloads"][vin], meta)


@pytest.fixture(scope="module")
def bx1e(fixture: dict) -> dict:
    return _normalise(fixture, VIN_X)


@pytest.fixture(scope="module")
def dc1e(fixture: dict) -> dict:
    return _normalise(fixture, VIN_001)


# ---------------------------------------------------------------------------
# Battery: the traction pack must never be confused with the 12 V aux battery
# ---------------------------------------------------------------------------


def test_traction_soc_is_the_pack_not_the_aux_battery(bx1e, dc1e):
    assert bx1e["battery"]["soc"] == 86.0
    assert dc1e["battery"]["soc"] == 61.0


def test_aux_battery_is_reported_separately(bx1e, dc1e):
    assert bx1e["battery12v"]["soc"] == 97.6
    assert bx1e["battery12v"]["voltage"] == 12.85
    assert dc1e["battery12v"]["soc"] == 100.0
    assert dc1e["battery12v"]["voltage"] == 12.6


def test_charging_state_uses_charge_sts_not_discharge_sts(bx1e):
    assert bx1e["battery"]["charger_state"] == "0"
    assert bx1e["battery"]["charging"] is False
    assert bx1e["battery"]["plugged"] is False


def test_time_to_full_sentinel_is_dropped(bx1e, dc1e):
    """2047 means "no estimate" and must surface as unknown, not 2047 minutes."""
    assert bx1e["battery"]["remaining_minutes"] is None
    assert dc1e["battery"]["remaining_minutes"] is None


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def test_odometer_and_range(bx1e, dc1e):
    assert bx1e["odometer"] == 41065.0
    assert bx1e["battery"]["range"] == 321.0
    assert dc1e["odometer"] == 146512.0
    assert dc1e["battery"]["range"] == 345.0


def test_tyre_pressure_comes_from_tyre_status(bx1e, dc1e):
    assert bx1e["tyres"]["pressure"]["fl"] == pytest.approx(244.394)
    assert bx1e["tyres"]["pressure"]["fr"] == pytest.approx(234.783)
    assert bx1e["tyres"]["pressure"]["rl"] == pytest.approx(240.275)
    assert bx1e["tyres"]["pressure"]["rr"] == pytest.approx(240.275)
    assert dc1e["tyres"]["pressure"]["rl"] == pytest.approx(267.735)


def test_tyre_position_mapping(bx1e):
    """``Driver`` is front-left on a LHD car, ``PassengerRear`` is rear-right."""
    assert bx1e["tyres"]["temp"]["fl"] == 37.0
    assert bx1e["tyres"]["temp"]["fr"] == 37.0
    assert bx1e["tyres"]["temp"]["rl"] == 36.0
    assert bx1e["tyres"]["temp"]["rr"] == 35.0


def test_tyre_warnings_are_tri_state(bx1e, dc1e):
    assert bx1e["tyres"]["pressure_warning"]["fl"] is False
    # The DC1E payload omits the warning fields entirely -> unknown, not False.
    assert dc1e["tyres"]["pressure_warning"]["fl"] is None


def test_climate_values(bx1e, dc1e):
    assert bx1e["climate"]["inside_temp"] == 26.3
    assert bx1e["climate"]["outside_temp"] == 29.9
    assert bx1e["climate"]["target_temp"] == 28.0
    assert bx1e["climate"]["ac_on"] is False
    assert dc1e["climate"]["inside_temp"] == 44.1
    assert dc1e["climate"]["outside_temp"] == 32.0


def test_air_quality_is_not_shadowed_by_the_level_field(bx1e, dc1e):
    """``interiorPM25Level`` is a level code, not a concentration."""
    assert bx1e["air"]["pm25"] is None
    assert dc1e["air"]["pm25"] == 8.0
    assert bx1e["air"]["humidity"] == 92.0


def test_service_and_consumption(bx1e, dc1e):
    assert bx1e["service"]["days_to_service"] == 54.0
    assert bx1e["service"]["distance_to_service"] == 5380.0
    assert bx1e["battery"]["power_consumption"] == 16.2
    assert dc1e["battery"]["power_consumption"] == 12.9


def test_doors_and_windows_closed(bx1e):
    assert set(bx1e["doors"].values()) == {False}
    assert set(bx1e["windows"].values()) == {False}
    assert set(bx1e["window_pos"].values()) == {0}


# ---------------------------------------------------------------------------
# Locks
# ---------------------------------------------------------------------------


def test_lock_status_fields_decode_non_zero_as_locked(bx1e, dc1e):
    assert bx1e["locks"]["central"] is True
    assert bx1e["locks"]["charge_lid"] is True
    assert dc1e["locks"]["central"] is True
    # Raw per-corner values are kept for diagnostics.
    assert bx1e["locks"]["raw"]["fl"] == 1
    assert bx1e["locks"]["raw"]["trunk"] == 1


def test_zero_means_unlocked():
    payload = {
        "additionalVehicleStatus": {
            "drivingSafetyStatus": {
                "centralLockingStatus": "0",
                "doorLockStatusDriver": "0",
                "doorLockStatusPassenger": "0",
                "doorLockStatusDriverRear": "0",
                "doorLockStatusPassengerRear": "0",
            }
        }
    }
    assert parser.normalize_vehicle_data(payload)["locks"]["central"] is False


# ---------------------------------------------------------------------------
# Position: the fixed-point divisor is detected at runtime
# ---------------------------------------------------------------------------


def test_position_from_real_payload(bx1e, dc1e):
    assert bx1e["position"]["latitude"] == pytest.approx(23.1034, abs=1e-3)
    assert bx1e["position"]["longitude"] == pytest.approx(113.3771, abs=1e-3)
    assert dc1e["position"]["latitude"] == pytest.approx(36.6731, abs=1e-3)
    assert dc1e["position"]["longitude"] == pytest.approx(117.0070, abs=1e-3)


def test_position_trust_flag(bx1e, dc1e):
    assert bx1e["position"]["valid"] is False   # posCanBeTrusted = false
    assert dc1e["position"]["valid"] is True
    assert bx1e["position"]["has_fix"] is True


@pytest.mark.parametrize(
    "latitude, longitude, expected",
    [
        ("83172354", "408157388", (23.1034, 113.3771)),      # degrees x 3.6e6
        ("365000000", "1170000000", (36.5, 117.0)),          # degrees x 1e7
        ("36500000", "117000000", (36.5, 117.0)),            # degrees x 1e6
        ("36.5", "117.0", (36.5, 117.0)),                    # already degrees
    ],
)
def test_position_divisor_detection(latitude, longitude, expected):
    payload = {"position": {"latitude": latitude, "longitude": longitude}}
    position = parser.normalize_vehicle_data(payload)["position"]
    assert position["latitude"] == pytest.approx(expected[0], abs=5e-3)
    assert position["longitude"] == pytest.approx(expected[1], abs=5e-3)


def test_null_island_is_rejected():
    payload = {"position": {"latitude": "0", "longitude": "0"}}
    position = parser.normalize_vehicle_data(payload)["position"]
    assert position["latitude"] is None
    assert position["longitude"] is None
    assert position["has_fix"] is False


# ---------------------------------------------------------------------------
# Generic parsing behaviour
# ---------------------------------------------------------------------------


def test_flat_payload_still_resolves_battery():
    payload = {"chargeLevel": "72", "odometer": "1000", "range": "300"}
    battery = parser.normalize_vehicle_data(payload)["battery"]
    assert battery["soc"] == 72.0
    assert battery["range"] == 300.0


def test_charge_lid_open_codes():
    for raw in ("1", "open"):
        payload = {"additionalVehicleStatus": {
            "electricVehicleStatus": {"chargeLidDcAcStatus": raw}}}
        assert parser.normalize_vehicle_data(payload)["locks"]["charge_lid"] is False
    for raw in ("2", "0", "closed"):
        payload = {"additionalVehicleStatus": {
            "electricVehicleStatus": {"chargeLidDcAcStatus": raw}}}
        assert parser.normalize_vehicle_data(payload)["locks"]["charge_lid"] is True


def test_empty_and_garbage_payloads_return_the_skeleton():
    for payload in ({}, None, [], "nonsense", 42):
        canonical = parser.normalize_vehicle_data(payload)
        assert canonical["battery"] == {}
        assert canonical["locks"] == {}
        assert canonical["position"] == {}


def test_seat_shape_is_stable(bx1e):
    seats = bx1e["seats"]
    assert set(seats["heat"]) == {"fl", "fr", "rl", "rr"}
    assert set(seats["vent"]) == {"fl", "fr"}
    assert seats["vent"]["fl"] == {"sts": 2, "level": 0}


def test_vehicle_meta_is_passed_through(bx1e):
    assert bx1e["vehicle"]["series"] == "BX1E"
    assert bx1e["vehicle"]["vin"] == VIN_X


def test_as_bool_is_tri_state():
    assert parser.as_bool("1") is True
    assert parser.as_bool("2") is False
    assert parser.as_bool("0") is False
    assert parser.as_bool("3") is None
    assert parser.as_bool("engine_off") is False
    assert parser.as_bool(None) is None


# ---------------------------------------------------------------------------
# Diagnostics: field provenance is what makes calibration a one-round-trip job
# ---------------------------------------------------------------------------


def test_describe_payload_reports_field_provenance(fixture):
    summary = parser.describe_payload(fixture["payloads"][VIN_X])
    assert summary["has_tyres"] is True
    assert summary["has_position"] is True
    assert summary["has_battery"] is True

    resolved = summary["resolved"]
    assert resolved["battery.soc"]["path"].endswith("electricvehiclestatuschargelevel")
    assert resolved["battery.charging"]["path"].endswith("chargests")
    assert resolved["battery12v.soc"]["path"].endswith("mainbatterystatuschargelevel")
    assert resolved["tyres.pressure.fl"]["path"].endswith("tyrestatusdriver")
    assert resolved["locks.central"]["value"] == "2"
    assert resolved["air.pm25"]["path"] is None


def test_describe_payload_handles_non_dict():
    assert parser.describe_payload(None) == {"type": "NoneType"}
