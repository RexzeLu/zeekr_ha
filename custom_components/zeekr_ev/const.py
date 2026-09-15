"""Constants for the Zeekr EV (SMS login) integration."""

from __future__ import annotations

import json
from pathlib import Path

# Base component constants
NAME = "Zeekr EV API Integration"
DOMAIN = "zeekr_ev"
DOMAIN_DATA = f"{DOMAIN}_data"

# Config entry data keys
CONF_PHONE = "phone"
CONF_REGION_CODE = "region_code"
CONF_DEVICE_ID = "device_id"

# Config entry option keys
CONF_POLLING_INTERVAL = "polling_interval"
CONF_DRIVE_SIDE = "drive_side"
CONF_SEAT_DURATION = "seat_duration"
CONF_AC_DURATION = "ac_duration"
CONF_STEERING_WHEEL_DURATION = "steering_wheel_duration"
CONF_ENABLE_COMMANDS = "enable_commands"

DRIVE_SIDE_LHD = "lhd"
DRIVE_SIDE_RHD = "rhd"

DEFAULT_NAME = DOMAIN
DEFAULT_POLLING_INTERVAL = 5  # minutes
DEFAULT_REGION_CODE = "+86"
DEFAULT_SEAT_DURATION = 15  # minutes
DEFAULT_AC_DURATION = 15  # minutes
DEFAULT_STEERING_WHEEL_DURATION = 15  # minutes
DEFAULT_ENABLE_COMMANDS = True

# Polling interval bounds (minutes)
MIN_POLLING_INTERVAL = 1
MAX_POLLING_INTERVAL = 60

# Command duration bounds (minutes)
MIN_DURATION = 1
MAX_DURATION = 60

# Tokens persisted in the config entry so the integration can resume
# without a fresh SMS challenge.
STORAGE_DEVICE_ID = "device_id"
STORAGE_JWT_TOKEN = "jwt_token"
STORAGE_ACCESS_TOKEN = "access_token"
STORAGE_REFRESH_TOKEN = "refresh_token"
STORAGE_USER_ID = "user_id"
STORAGE_CLIENT_ID = "client_id"
STORAGE_NEW_ACCESS_TOKEN = "new_access_token"
STORAGE_NEW_REFRESH_TOKEN = "new_refresh_token"


def _load_manifest_version() -> str:
    """Read the integration version from manifest.json.

    Keeps startup logging and the HA UI version aligned with the metadata.
    """
    manifest_path = Path(__file__).with_name("manifest.json")
    try:
        with manifest_path.open(encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
    except (OSError, ValueError):
        return "unknown"
    return str(manifest.get("version", "unknown"))


INTEGRATION_VERSION = _load_manifest_version()

ISSUE_URL = "https://github.com/RexzeLu/zeekr_ha/issues"

# Icons
ICON = "mdi:format-quote-close"

# Platforms
BINARY_SENSOR = "binary_sensor"
BUTTON = "button"
CLIMATE = "climate"
COVER = "cover"
DATETIME = "datetime"
DEVICE_TRACKER = "device_tracker"
LOCK = "lock"
NUMBER = "number"
SELECT = "select"
SENSOR = "sensor"
SWITCH = "switch"
TIME = "time"
PLATFORMS = [
    BINARY_SENSOR,
    BUTTON,
    CLIMATE,
    COVER,
    DATETIME,
    DEVICE_TRACKER,
    LOCK,
    NUMBER,
    SELECT,
    SENSOR,
    SWITCH,
    TIME,
]

# Services
SERVICE_REFRESH = "refresh"
SERVICE_DUMP_RAW = "dump_raw_status"

# Service attributes
ATTR_VIN = "vin"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"

STARTUP_MESSAGE = f"""
-------------------------------------------------------------------
{NAME}
Version: {INTEGRATION_VERSION}
Zeekr China mainland SMS (+86) login
If you have any issues with this you need to open an issue here:
{ISSUE_URL}
-------------------------------------------------------------------
"""
