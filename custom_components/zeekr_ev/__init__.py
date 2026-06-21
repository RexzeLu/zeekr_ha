"""Custom integration to integrate Zeekr EV API Integration with Home Assistant.

For more details about this integration, please refer to
https://github.com/Fryyyyy/zeekr_homeassistant
"""

import logging
import importlib

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers.typing import ConfigType
import homeassistant.helpers.config_validation as cv

from .const import (
    CONF_HMAC_ACCESS_KEY,
    CONF_HMAC_SECRET_KEY,
    CONF_PASSWORD,
    CONF_PASSWORD_PUBLIC_KEY,
    CONF_PROD_SECRET,
    CONF_USERNAME,
    CONF_VIN_IV,
    CONF_VIN_KEY,
    CONF_COUNTRY_CODE,
    CONF_USE_LOCAL_API,
    DOMAIN,
    PLATFORMS,
    STARTUP_MESSAGE,
)
from .coordinator import ZeekrCoordinator
from .coordinator_sms import ZeekrSmsCoordinator
from .request_stats import ZeekrRequestStats
from .const import CONF_LOGIN_TYPE, LOGIN_TYPE_SMS, CONF_PHONE

_LOGGER: logging.Logger = logging.getLogger(__package__)

# Service constants
SERVICE_GET_TRIP_TRACKPOINTS = "get_trip_trackpoints"
ATTR_VIN = "vin"
ATTR_TRIP_ID = "trip_id"
ATTR_TRIP_REPORT_TIME = "trip_report_time"

# Service schema
SERVICE_GET_TRIP_TRACKPOINTS_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_VIN): cv.string,
        vol.Required(ATTR_TRIP_ID): cv.positive_int,
        vol.Required(ATTR_TRIP_REPORT_TIME): cv.positive_int,
    }
)


def get_zeekr_client_class(use_local: bool = False):
    """Dynamically import ZeekrClient from local or installed package."""
    if use_local:
        try:
            # Try to import from local custom_components folder
            module = importlib.import_module("custom_components.zeekr_ev_api.client")
            _LOGGER.debug("Using local zeekr_ev_api from custom_components")
            return module.ZeekrClient
        except ImportError as ex:
            raise ImportError(
                "Local zeekr_ev_api not found in custom_components. "
                "Please install it or disable 'Use local API' option."
            ) from ex

    # Try to import from installed package (pip)
    try:
        module = importlib.import_module("zeekr_ev_api.client")
        _LOGGER.debug("Using installed zeekr_ev_api package")
        return module.ZeekrClient
    except ImportError as ex:
        raise ImportError(
            "zeekr_ev_api package not installed. "
            "Please install it via pip or enable 'Use local API' option."
        ) from ex


async def async_setup(hass: HomeAssistant, config: ConfigType):
    """Set up this integration using YAML is not supported."""
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    "Set up this integration using UI."
    if hass.data.get(DOMAIN) is None:
        hass.data.setdefault(DOMAIN, {})
        _LOGGER.info(STARTUP_MESSAGE)
    login_type = entry.data.get(CONF_LOGIN_TYPE, LOGIN_TYPE_SMS)
    if login_type == LOGIN_TYPE_SMS:
        return await _async_setup_sms_entry(hass, entry)
    else:
        return await _async_setup_email_entry(hass, entry)

async def async_setup_services(hass: HomeAssistant) -> None:
    """Set up services for the Zeekr integration."""

    async def async_get_trip_trackpoints(call: ServiceCall) -> ServiceResponse:
        """Handle the get_trip_trackpoints service call."""
        vin = call.data[ATTR_VIN]
        trip_id = call.data[ATTR_TRIP_ID]
        trip_report_time = call.data[ATTR_TRIP_REPORT_TIME]

        # Find the coordinator for this VIN
        coordinator = None
        for entry_id, coord in hass.data[DOMAIN].items():
            if entry_id.startswith("_"):
                continue
            if isinstance(coord, ZeekrCoordinator):
                for vehicle in coord.vehicles:
                    if vehicle.vin == vin:
                        coordinator = coord
                        break
            if coordinator:
                break

        if not coordinator:
            raise HomeAssistantError(f"Vehicle with VIN {vin} not found")

        vehicle = coordinator.get_vehicle_by_vin(vin)
        if not vehicle:
            raise HomeAssistantError(f"Vehicle with VIN {vin} not found")

        try:
            # Increment API request counter
            await coordinator.request_stats.async_inc_request()

            # Fetch trackpoints
            trackpoints = await hass.async_add_executor_job(
                vehicle.get_trip_trackpoints, trip_report_time, trip_id
            )

            _LOGGER.debug(
                "Fetched %d trackpoints for trip %d", len(trackpoints), trip_id
            )

            return {
                "vin": vin,
                "trip_id": trip_id,
                "trip_report_time": trip_report_time,
                "trackpoints": trackpoints,
                "count": len(trackpoints),
            }

        except Exception as ex:
            _LOGGER.error("Failed to fetch trip trackpoints: %s", ex)
            raise HomeAssistantError(f"Failed to fetch trackpoints: {ex}") from ex

    # Only register if not already registered
    if not hass.services.has_service(DOMAIN, SERVICE_GET_TRIP_TRACKPOINTS):
        hass.services.async_register(
            DOMAIN,
            SERVICE_GET_TRIP_TRACKPOINTS,
            async_get_trip_trackpoints,
            schema=SERVICE_GET_TRIP_TRACKPOINTS_SCHEMA,
            supports_response=SupportsResponse.ONLY,
        )
        _LOGGER.debug("Registered service: %s.%s", DOMAIN, SERVICE_GET_TRIP_TRACKPOINTS)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Handle removal of an entry."""
    coordinator = hass.data[DOMAIN].get(entry.entry_id)
    if coordinator and hasattr(coordinator, 'request_stats'):
        await coordinator.request_stats.async_shutdown()

    if unloaded := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    # Unregister services if no more entries
    remaining_entries = [
        k for k in hass.data.get(DOMAIN, {}).keys() if not k.startswith("_")
    ]
    if not remaining_entries:
        hass.services.async_remove(DOMAIN, SERVICE_GET_TRIP_TRACKPOINTS)
        _LOGGER.debug("Unregistered service: %s.%s", DOMAIN, SERVICE_GET_TRIP_TRACKPOINTS)

    return unloaded


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
