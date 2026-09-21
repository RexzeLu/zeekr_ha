"""Tests for the adaptive polling backoff.

A parked car keeps returning the same payload for hours, so a fixed one-minute
timer burned ~1440 requests/day·car.  ``polling.py`` has no Home Assistant
imports so it loads straight from disk — same trick as ``test_optimistic.py``.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_MODULE = _ROOT / "custom_components" / "zeekr_ev" / "polling.py"

_spec = importlib.util.spec_from_file_location("zeekr_polling", _MODULE)
polling = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(polling)

VIN = "L6T77HCE9PF081833"
_NOW = datetime(2026, 9, 21, 19, 0, 0)


def _vehicle(**overrides) -> dict:
    """A parked, sleeping car — the case that used to be polled 1440×/day."""
    vehicle = {
        "report_time": "1789981366178",
        "battery": {
            "soc": 78.0, "range": 291.0, "charging": False, "plugged": False,
            "power": 0.0,
        },
        "climate": {
            "inside_temp": 27.5, "outside_temp": 34.2, "ac_on": False,
            "defrost": False, "blower": False,
        },
        "safety": {"speed": 0.0},
        "doors": {"fl": False, "fr": False, "rl": False, "rr": False},
        "windows": {"fl": False, "fr": False, "rl": False, "rr": False},
    }
    vehicle.update(overrides)
    return vehicle


def _data(**overrides) -> dict:
    return {VIN: _vehicle(**overrides)}


# -- backoff ladder --------------------------------------------------------


def test_ladder_doubles_then_caps():
    assert [polling.backoff_minutes(1, idle) for idle in range(7)] == [
        1, 2, 4, 8, 15, 15, 15,
    ]


def test_ladder_never_slower_than_the_configured_interval():
    assert polling.backoff_minutes(60, 5) == 60
    assert polling.backoff_minutes(45, 3) == 45


def test_ladder_never_faster_than_the_configured_interval():
    for idle in range(6):
        assert polling.backoff_minutes(10, idle) >= 10
    assert polling.backoff_minutes(10, 0) == 10


# -- activity detection ----------------------------------------------------


def test_parked_car_is_not_active():
    assert polling.vehicle_active(_vehicle()) is False


@pytest.mark.parametrize(
    "override",
    [
        {"battery": {"charging": True, "plugged": True, "power": 0.0}},
        {"battery": {"charging": False, "plugged": True, "power": 0.0}},
        {"battery": {"charging": False, "plugged": False, "power": 6.6}},
        {"climate": {"ac_on": True}},
        {"climate": {"defrost": True}},
        {"safety": {"speed": 12.0}},
        {"doors": {"fl": True}},
        {"windows": {"rr": True}},
    ],
)
def test_busy_car_is_active(override):
    vehicle = _vehicle()
    for key, value in override.items():
        merged = dict(vehicle[key])
        merged.update(value)
        vehicle[key] = merged
    assert polling.vehicle_active(vehicle) is True


def test_activity_seen_across_vehicles():
    assert polling.any_active({VIN: _vehicle()}) is False
    assert polling.any_active({VIN: _vehicle(), "OTHER": _vehicle(safety={"speed": 1.0})})


# -- AdaptivePolling -------------------------------------------------------


def test_unchanged_payloads_stretch_the_interval():
    adaptive = polling.AdaptivePolling(1)
    seen = [adaptive.note_poll(_data(), now=_NOW) for _ in range(6)]
    assert seen == [1, 2, 4, 8, 15, 15]
    assert adaptive.idle_polls == 5


def test_a_change_resets_the_backoff():
    adaptive = polling.AdaptivePolling(1)
    adaptive.note_poll(_data(), now=_NOW)
    adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=1))
    adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=3))
    assert adaptive.current_minutes == 4

    # The car woke up and uploaded: back to the configured interval.
    fresh = _data(report_time="1789989999000")
    assert adaptive.note_poll(fresh, now=_NOW + timedelta(minutes=5)) == 1
    assert adaptive.idle_polls == 0
    assert adaptive.last_change == _NOW + timedelta(minutes=5)


def test_active_car_keeps_the_base_interval():
    adaptive = polling.AdaptivePolling(1)
    charging = _data(battery={"charging": True, "plugged": True, "power": 7.0})
    assert [adaptive.note_poll(charging, now=_NOW) for _ in range(5)] == [1] * 5


def test_command_opens_a_fast_window():
    adaptive = polling.AdaptivePolling(1)
    for minute in range(4):
        adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=minute))
    assert adaptive.current_minutes == 8

    adaptive.mark_command(now=_NOW + timedelta(minutes=4))
    assert adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=4)) == 1

    # ...and the window expires, so an unchanged car backs off again.
    adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=5))
    adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=11))
    assert adaptive.current_minutes == 2


def test_pending_optimistic_keeps_polling_fast():
    adaptive = polling.AdaptivePolling(1)
    for minute in range(4):
        adaptive.note_poll(_data(), now=_NOW + timedelta(minutes=minute))
    assert adaptive.current_minutes == 8
    assert adaptive.note_poll(
        _data(), now=_NOW + timedelta(minutes=4), pending_optimistic=True
    ) == 1


def test_fingerprint_tracks_content_not_identity():
    first = polling.payload_fingerprint(_data())
    assert first == polling.payload_fingerprint(_data())
    assert first != polling.payload_fingerprint(_data(report_time="1"))


def test_diagnostics_view():
    adaptive = polling.AdaptivePolling(2)
    adaptive.note_poll(_data(), now=_NOW)
    info = adaptive.as_dict()
    assert info["base_minutes"] == 2
    assert info["current_minutes"] == 2
    assert info["max_minutes"] == 15
    assert info["last_change"] == _NOW.isoformat()
