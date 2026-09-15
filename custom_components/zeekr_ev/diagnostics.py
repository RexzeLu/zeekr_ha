"""Diagnostics support — lets users export real payloads for field mapping."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import ZeekrCoordinator
from .parser import describe_payload

# Never leak credentials.  GPS coordinates are intentionally kept because the
# whole point of the export is to verify position mapping.
TO_REDACT = {
    "device_id",
    "jwt_token",
    "access_token",
    "refresh_token",
    "new_access_token",
    "new_refresh_token",
    "user_id",
    "client_id",
    "phone",
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator: ZeekrCoordinator = hass.data[DOMAIN][entry.entry_id]
    data = coordinator.data or {}

    return {
        "entry": {
            "title": entry.title,
            "version": entry.version,
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": dict(entry.options),
        },
        "vehicles": [
            {"vin": vehicle.vin, **dict(vehicle.meta)}
            for vehicle in coordinator.vehicles
        ],
        # The untouched vehicle-list entries.  Without these there is no way to
        # tell whether a missing name/plate is a parser gap or simply not
        # returned by the backend.
        "vehicle_list_raw": [
            {
                "vin": vehicle.vin,
                "display_name": vehicle.display_name,
                "entry": vehicle.raw,
            }
            for vehicle in coordinator.vehicles
        ],
        "commands_enabled": coordinator.commands_enabled,
        "last_poll": coordinator.latest_poll_time,
        # Values issued by a command but not yet confirmed by the car.  Handy
        # when a command "does not stick": if the entry is still here after the
        # TTL, the car never accepted (or never reported) the change.
        "pending_commands": coordinator.pending_optimistic(),
        "payload_summary": {
            vin: describe_payload(state.get("raw")) for vin, state in data.items()
        },
        "raw_payloads": {vin: state.get("raw") for vin, state in data.items()},
        "normalized": data,
    }
