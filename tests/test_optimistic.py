"""Tests for the optimistic-state overlay.

This is the piece that decides whether the UI believes a command worked.  The
original implementation trusted the very next poll, which still carries the
*old* state because the car needs time to wake up and report — so a lock command
visibly snapped back to "unlocked".  These tests pin the corrected behaviour.

``optimistic.py`` has no Home Assistant imports, so it loads directly.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_MODULE = _ROOT / "custom_components" / "zeekr_ev" / "optimistic.py"

_spec = importlib.util.spec_from_file_location("zeekr_optimistic", _MODULE)
optimistic = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(optimistic)

VIN = "LXXX"


def _state(locked: bool) -> dict:
    return {VIN: {"locks": {"central": locked}, "battery": {"soc": 86.0}}}


# ---------------------------------------------------------------------------
# dig / assign
# ---------------------------------------------------------------------------


def test_dig_reads_nested_paths():
    assert optimistic.dig({"a": {"b": {"c": 1}}}, ("a", "b", "c")) == 1
    assert optimistic.dig({"a": 1}, ("a", "b")) is None
    assert optimistic.dig({}, ("a",)) is None


def test_assign_creates_missing_parents():
    node: dict = {}
    assert optimistic.assign(node, ("a", "b", "c"), 5) is True
    assert node == {"a": {"b": {"c": 5}}}
    assert optimistic.assign(node, (), 1) is False


# ---------------------------------------------------------------------------
# Overlay behaviour
# ---------------------------------------------------------------------------


def test_pending_value_survives_stale_polls():
    """The car is still reporting 'unlocked' — the UI must keep showing 'locked'."""
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)

    for stamp in (10.0, 30.0, 60.0):
        data = store.apply(_state(False), now=stamp)
        assert data[VIN]["locks"]["central"] is True


def test_car_confirmation_ends_the_override():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)

    # The car finally reports "locked" — it wins and the pending entry is gone.
    data = store.apply(_state(True), now=30.0)
    assert data[VIN]["locks"]["central"] is True
    assert len(store) == 0

    # ...and a later poll that reports "unlocked" is now believed.
    data = store.apply(_state(False), now=40.0)
    assert data[VIN]["locks"]["central"] is False


def test_override_expires_so_a_failed_command_is_not_faked_forever():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)

    assert store.apply(_state(False), now=89.0)[VIN]["locks"]["central"] is True
    assert store.apply(_state(False), now=91.0)[VIN]["locks"]["central"] is False
    assert len(store) == 0


def test_missing_vehicle_drops_the_pending_value():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)

    assert store.apply({}, now=5.0) == {}
    assert len(store) == 0


def test_unrelated_state_changes_do_not_cancel_the_override():
    """A poll that only moves the odometer must not undo a pending lock."""
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)

    data = _state(False)
    data[VIN]["battery"]["soc"] = 70.0
    assert store.apply(data, now=10.0)[VIN]["locks"]["central"] is True


def test_multiple_paths_tracked_independently():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)
    store.set(VIN, ("climate", "ac_on"), True, baseline=False, now=0.0)
    store.set(VIN, ("seats", "vent", "fl"),
              {"sts": 1, "level": 2}, baseline={"sts": 2, "level": 0}, now=0.0)

    data = _state(False)
    data[VIN]["climate"] = {"ac_on": False}
    data[VIN]["seats"] = {"vent": {"fl": {"sts": 2, "level": 0}}}
    data = store.apply(data, now=5.0)

    assert data[VIN]["locks"]["central"] is True
    assert data[VIN]["climate"]["ac_on"] is True
    assert data[VIN]["seats"]["vent"]["fl"] == {"sts": 1, "level": 2}


def test_nested_dict_values_compare_by_equality():
    """Seat-vent values are dicts; the baseline comparison must still work."""
    store = optimistic.OptimisticStore(ttl=90)
    baseline = {"sts": 1, "level": 1}
    store.set(VIN, ("seats", "vent", "fl"),
              {"sts": 1, "level": 3}, baseline=baseline, now=0.0)

    data = {VIN: {"seats": {"vent": {"fl": {"sts": 1, "level": 3}}}}}
    assert store.apply(data, now=5.0)[VIN]["seats"]["vent"]["fl"] == {"sts": 1, "level": 3}
    assert len(store) == 0


def test_empty_path_is_ignored():
    store = optimistic.OptimisticStore()
    store.set(VIN, (), True, baseline=False)
    assert len(store) == 0
    assert store.apply(_state(False)) == _state(False)


def test_pending_view_is_json_friendly():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)
    assert store.pending() == {
        f"{VIN}.locks.central": {"baseline": False, "intended": True}
    }


def test_discard_and_clear():
    store = optimistic.OptimisticStore(ttl=90)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)
    store.set("OTHER", ("locks", "central"), True, baseline=False, now=0.0)

    store.discard(VIN)
    assert len(store) == 1
    store.clear()
    assert len(store) == 0


def test_custom_ttl_is_honoured():
    store = optimistic.OptimisticStore(ttl=5)
    store.set(VIN, ("locks", "central"), True, baseline=False, now=0.0)
    assert store.apply(_state(False), now=4.0)[VIN]["locks"]["central"] is True
    assert store.apply(_state(False), now=6.0)[VIN]["locks"]["central"] is False


@pytest.mark.parametrize("ttl", [0.0, 1.0, 90.0])
def test_no_pending_entries_returns_data_untouched(ttl):
    store = optimistic.OptimisticStore(ttl=ttl)
    data = _state(False)
    assert store.apply(data) is data
