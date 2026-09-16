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

# The new Zeekr (SNCTSP) platform addresses a car with an *opaque per-vehicle
# token* in the ``X-VIN`` header rather than with the plain VIN — and that token
# both addresses **and authorises** the car, so it carries capabilities that
# encrypting the VIN ourselves cannot reproduce.  It is stable per car but
# minted inside the app, so the owner pastes it in (see README, "车辆 X-VIN
# 令牌").  Empty = fall back to encrypting the VIN locally.
CONF_VEHICLE_TOKEN = "vehicle_token"

# ``loginDeviceId`` is not a free-form id: the app sends a composite
# ``{brand}-{model}-{sdkInt}-{osRelease}`` string, and the mobile SDK parses it
# to describe the device a session belongs to.  A bare uuid is not that shape,
# so the gateway has no device profile to attach the session to — which is the
# most plausible reason endpoints that need a car's capabilities answer
# ``079001 此接口未被授权`` while plain reads still work.  The reference
# implementation hard-codes an equally synthetic string
# (``google-sdk_gphone64_x86_64-36-16``) and works, so the *shape* is what
# matters, not the device's authenticity.  This one is verbatim from the
# captured app traffic.
DEFAULT_LOGIN_DEVICE_ID = "Android-Android SDK built for arm64-26-8.0.0"

# Bumped whenever the shape of the login request changes in a way that should
# invalidate tokens minted by an older build.  ``store_tokens`` drops the stored
# GW3 token when the entry was written by a different revision, which forces one
# fresh ``snc_login`` instead of silently reusing a session the gateway built
# from the old request — without it, a fix like the device id above would never
# take effect until the token happened to expire.
CREDENTIAL_REVISION = 2

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

# Which build's login shape minted the stored tokens (see CREDENTIAL_REVISION).
STORAGE_CREDENTIAL_REVISION = "credential_revision"


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
