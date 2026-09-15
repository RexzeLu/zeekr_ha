"""Diagnostics support — lets users export real payloads for field mapping."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import CONF_PHONE, DOMAIN
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


def _phone_tail(entry: ConfigEntry) -> str | None:
    """Last four digits of the account phone — enough to spot duplicates."""
    digits = "".join(ch for ch in str(entry.data.get(CONF_PHONE) or "") if ch.isdigit())
    return digits[-4:] if len(digits) >= 4 else (digits or None)


def _describe_config_entries(
    hass: HomeAssistant, entry: ConfigEntry
) -> list[dict[str, Any]]:
    """Every Zeekr config entry in this Home Assistant instance.

    Duplicate entries are the number one cause of "some entities are
    unavailable": they publish identical ``unique_id``s, Home Assistant keeps
    only one set and the loser's entities end up *restored*.  Without this list
    that is invisible in a diagnostics dump.
    """
    described: list[dict[str, Any]] = []
    for other in hass.config_entries.async_entries(DOMAIN):
        coordinator = hass.data.get(DOMAIN, {}).get(other.entry_id)
        described.append(
            {
                "entry_id": other.entry_id,
                "title": other.title,
                "is_current": other.entry_id == entry.entry_id,
                "state": other.state.value
                if isinstance(other.state, ConfigEntryState)
                else str(other.state),
                "phone_tail": _phone_tail(other),
                "vins": sorted(coordinator.vehicle_vins())
                if isinstance(coordinator, ZeekrCoordinator)
                else [],
                "last_update_success": coordinator.last_update_success
                if isinstance(coordinator, ZeekrCoordinator)
                else None,
            }
        )
    return described


def _describe_entities(hass: HomeAssistant, entry: ConfigEntry) -> list[dict[str, Any]]:
    """Entity-registry snapshot for this integration, with live states.

    ``state == "unavailable"`` combined with ``restored == True`` means the
    entity exists in the registry but no loaded config entry provides it — the
    classic leftover of a removed/duplicated entry.
    """
    registry = er.async_get(hass)
    described: list[dict[str, Any]] = []
    for reg_entry in registry.entities.values():
        if reg_entry.platform != DOMAIN:
            continue
        state = hass.states.get(reg_entry.entity_id)
        described.append(
            {
                "entity_id": reg_entry.entity_id,
                "unique_id": reg_entry.unique_id,
                "original_name": reg_entry.original_name,
                "config_entry_id": reg_entry.config_entry_id,
                "owned_by_current_entry": reg_entry.config_entry_id == entry.entry_id,
                "device_id": reg_entry.device_id,
                "disabled_by": str(reg_entry.disabled_by)
                if reg_entry.disabled_by
                else None,
                "state": state.state if state else None,
                "restored": bool(
                    state and state.attributes.get("restored") is True
                ),
            }
        )
    described.sort(key=lambda item: item["entity_id"] or "")
    return described


def _describe_devices(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Device-registry snapshot: shows name vs. user override."""
    registry = dr.async_get(hass)
    described: list[dict[str, Any]] = []
    for device in registry.devices.values():
        if not any(identifier[0] == DOMAIN for identifier in device.identifiers):
            continue
        described.append(
            {
                "id": device.id,
                "name": device.name,
                "name_by_user": device.name_by_user,
                "model": device.model,
                "manufacturer": device.manufacturer,
                "disabled_by": str(device.disabled_by) if device.disabled_by else None,
                "config_entries": sorted(device.config_entries),
                "identifiers": sorted(
                    identifier[1]
                    for identifier in device.identifiers
                    if identifier[0] == DOMAIN
                ),
            }
        )
    return described


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
        # Duplicate-entry / entity-ownership forensics.
        "config_entries": _describe_config_entries(hass, entry),
        "entities": _describe_entities(hass, entry),
        "devices": _describe_devices(hass),
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
        # Remote control is GW3-only; when it is missing, nothing works and
        # this block says why (login code/msg straight from the gateway).
        "gateways": coordinator.client.gateway_summary(),
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
