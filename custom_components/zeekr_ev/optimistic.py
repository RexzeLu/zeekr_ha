"""Optimistic (pending) state overlay for just-issued remote commands.

The car is cloud-polled.  When HA issues a command the gateway accepts it right
away, but the car itself has to be woken up and only then reports the new state
— typically 10-30 seconds later, and occasionally longer.  A naive
"optimistic update, then trust the next poll" therefore broke in the field: the
first re-poll still carried the *old* state, the UI snapped back, and a command
that had actually succeeded looked like it had failed.

:class:`OptimisticStore` fixes that by remembering, for each pending value, both
the value to show and the value it replaced:

* while a poll still returns the *baseline* value, the intended value is shown;
* as soon as the poll returns anything else, the car has spoken and the
  override is dropped;
* if :data:`DEFAULT_TTL` elapses without the car confirming, the override is
  dropped too — a stale guess is worse than admitting the command did not take.

This module deliberately has no Home Assistant imports so the algorithm can be
unit tested on its own.
"""

from __future__ import annotations

import time
from typing import Any

#: How long a pending value may override the polled state.
#:
#: Sized for the slowest channel rather than the fastest.  On GRIC a *lock*
#: command took the full ~120 s to show up in the status payload (unlock showed
#: up in ~5 s), so a window shorter than that would revoke the optimistic value
#: while the car was still perfectly on its way to obeying — the UI would flick
#: back to the old state and the command would look like it had failed.
DEFAULT_TTL = 180.0

_VIN = str
_Path = tuple[str, ...]
_Entry = tuple[Any, Any, float]  # baseline, intended value, expires_at


def dig(node: Any, path: _Path) -> Any:
    """Read a nested path out of a nested dict."""
    for step in path:
        if not isinstance(node, dict):
            return None
        node = node.get(step)
    return node


def assign(node: Any, path: _Path, value: Any) -> bool:
    """Write a nested path, creating missing parents. Returns success."""
    if not path:
        return False
    for step in path[:-1]:
        if not isinstance(node, dict):
            return False
        child = node.get(step)
        if not isinstance(child, dict):
            child = {}
            node[step] = child
        node = child
    if not isinstance(node, dict):
        return False
    node[path[-1]] = value
    return True


class OptimisticStore:
    """Pending intended values, keyed by ``(vin, path)``."""

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self._ttl = ttl
        self._pending: dict[tuple[_VIN, _Path], _Entry] = {}

    def __len__(self) -> int:
        return len(self._pending)

    def set(self, vin: str, path: _Path, value: Any, baseline: Any,
            *, now: float | None = None) -> None:
        """Record an intended value and the value it replaced."""
        if not path:
            return
        stamp = time.monotonic() if now is None else now
        self._pending[(vin, path)] = (baseline, value, stamp + self._ttl)

    def discard(self, vin: str) -> None:
        """Forget everything pending for one vehicle."""
        for key in [k for k in self._pending if k[0] == vin]:
            self._pending.pop(key, None)

    def clear(self) -> None:
        self._pending.clear()

    def pending(self) -> dict[str, Any]:
        """A JSON-friendly view, used by the diagnostics download."""
        return {
            f"{vin}." + ".".join(path): {"baseline": baseline, "intended": value}
            for (vin, path), (baseline, value, _) in self._pending.items()
        }

    def apply(self, data: dict[str, dict[str, Any]],
              *, now: float | None = None) -> dict[str, dict[str, Any]]:
        """Overlay pending values onto *data* (mutated in place and returned)."""
        if not self._pending:
            return data
        stamp = time.monotonic() if now is None else now
        for key, (baseline, value, expires) in list(self._pending.items()):
            vin, path = key
            state = data.get(vin)
            if state is None:
                # The vehicle disappeared from the poll; stop holding the value.
                self._pending.pop(key, None)
                continue
            if dig(state, path) != baseline:
                # The car reported a new state -- it wins.
                self._pending.pop(key, None)
                continue
            if stamp >= expires:
                self._pending.pop(key, None)
                continue
            assign(state, path, value)
        return data
