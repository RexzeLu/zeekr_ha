"""Adaptive polling for a cloud-polled car.

The status payload carries the car's *own* upload stamp (``report_time`` /
``updateTime``).  A parked, sleeping car does not upload anything for hours at
a time — a real diagnostic snapshot showed ``updateTime`` two hours behind the
last poll, i.e. ~120 polls that returned byte-identical data.  Polling on a
fixed one-minute timer therefore costs ~1440 requests/day·car to observe a
handful of changes.

This module watches for change instead of trusting a timer:

* a poll whose payload differs from the previous one resets the backoff, so a
  car that *is* doing something (driving, charging, preconditioning) keeps the
  configured interval;
* consecutive unchanged polls double the wait, capped at
  :data:`IDLE_MAX_MINUTES` (and never slower than the interval the user asked
  for);
* a freshly issued command opens a short fast window, because the car has to
  wake up and report back and the optimistic overlay needs a poll to clear.

No Home Assistant imports on purpose — the decision logic is pure and is
covered by ``tests/test_polling.py`` without a Home Assistant install.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

# Consecutive unchanged polls double the wait...
IDLE_BACKOFF_FACTOR = 2
# ...but never beyond this, and never beyond the configured interval either.
# 15 minutes keeps the worst case for "changed it on the phone, when does Home
# Assistant show it" under a quarter of an hour while still cutting a sleeping
# car from ~1440 requests/day to ~100.
IDLE_MAX_MINUTES = 15
# How long polling stays at the base interval after a command.  GRIC reports a
# lock change after ~120 s, so the window has to outlast the command re-polls.
COMMAND_FAST_MINUTES = 5


def payload_fingerprint(data: dict[str, Any]) -> str:
    """Stable hash of everything the poll produced."""
    blob = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def vehicle_active(vehicle: dict[str, Any]) -> bool:
    """Is the car doing something worth polling for?

    Only states that make a fresh upload likely count.  Anything the parser
    may get wrong is left out — a false positive here only costs requests,
    a false negative costs latency, so this stays deliberately narrow.
    """
    battery = vehicle.get("battery") or {}
    if _truthy(battery.get("charging")) or _truthy(battery.get("plugged")):
        return True
    if _number(battery.get("power")) > 0:
        return True

    climate = vehicle.get("climate") or {}
    if any(_truthy(climate.get(key)) for key in ("ac_on", "defrost", "blower")):
        return True

    if _number((vehicle.get("safety") or {}).get("speed")) > 0:
        return True

    # An open door/window usually means somebody is at the car and more
    # uploads are coming.
    for group in ("doors", "windows"):
        values = vehicle.get(group) or {}
        if any(_truthy(value) for value in values.values()):
            return True
    return False


def any_active(data: dict[str, dict[str, Any]]) -> bool:
    """True when at least one vehicle is busy."""
    return any(vehicle_active(vehicle) for vehicle in data.values())


def backoff_minutes(base_minutes: int, idle_polls: int) -> int:
    """Interval (minutes) for ``idle_polls`` consecutive unchanged polls."""
    base = max(1, int(base_minutes))
    if idle_polls <= 0:
        return base
    ceiling = max(base, IDLE_MAX_MINUTES)
    return min(base * IDLE_BACKOFF_FACTOR ** idle_polls, ceiling)


class AdaptivePolling:
    """Tracks poll results and hands out the interval to use next."""

    def __init__(self, base_minutes: int) -> None:
        self.base_minutes = max(1, int(base_minutes))
        self.idle_polls = 0
        self.current_minutes = self.base_minutes
        self.last_change: datetime | None = None
        self.fast_until: datetime | None = None
        self._fingerprint: str | None = None

    # -- external events --------------------------------------------------

    def mark_command(self, now: datetime | None = None) -> None:
        """A command was issued (or the user asked for a refresh): go fast."""
        now = now or datetime.now()
        self.fast_until = now + timedelta(minutes=COMMAND_FAST_MINUTES)
        self.idle_polls = 0
        self.current_minutes = self.base_minutes

    # -- poll bookkeeping -------------------------------------------------

    def note_poll(self, data: dict[str, dict[str, Any]],
                  now: datetime | None = None,
                  *, pending_optimistic: bool = False) -> int:
        """Record a completed poll; returns the interval to use next (minutes).

        ``pending_optimistic`` keeps polling fast while a command is waiting
        for the car to confirm it.
        """
        now = now or datetime.now()
        digest = payload_fingerprint(data)
        first = self._fingerprint is None
        changed = not first and digest != self._fingerprint
        fast = self.fast_until is not None and now < self.fast_until

        if first or changed:
            self.last_change = now
            self.idle_polls = 0
        elif fast or pending_optimistic or any_active(data):
            self.idle_polls = 0
        else:
            self.idle_polls += 1

        self._fingerprint = digest
        self.current_minutes = backoff_minutes(self.base_minutes, self.idle_polls)
        return self.current_minutes

    def as_dict(self) -> dict[str, Any]:
        """Diagnostics view of the current backoff state."""
        return {
            "base_minutes": self.base_minutes,
            "current_minutes": self.current_minutes,
            "idle_polls": self.idle_polls,
            "max_minutes": max(self.base_minutes, IDLE_MAX_MINUTES),
            "fast_until": self.fast_until.isoformat() if self.fast_until else None,
            "last_change": self.last_change.isoformat() if self.last_change else None,
        }
