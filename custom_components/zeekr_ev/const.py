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

# ---------------------------------------------------------------------------
# Authentication channel
# ---------------------------------------------------------------------------
# Which gateway the entry talks to.  The two are genuinely different products:
# SNC (``snc-tsp-api.zeekrlife.com``, app id ``ZEEKRCNCH001M0001``) issues one
# session per SMS login, while GRIC (``gric-*.geely.com``, app id
# ``GEELYCNCH001M0001``) is the gateway the official app itself uses.
#
# The distinction matters for shared cars: the SNC gateway refuses every
# vehicle interface for a non-owner account (``079001``), and no amount of
# re-logging in changes that.  GRIC serves the same account fine.
CONF_AUTH_METHOD = "auth_method"
AUTH_METHOD_SMS = "sms"
AUTH_METHOD_GRIC = "gric"
DEFAULT_AUTH_METHOD = AUTH_METHOD_SMS

# The app's own per-vehicle ``x-vehicle-identifier``.  The GRIC signature signs
# it, and every per-vehicle route *decrypts* it — a wrong value is answered with
# ``00A06 Decrypt X-VEHICLE-IDENTIFIER failed``.  So it is an encrypted form of
# the car's identity rather than a random id, and since its construction is not
# solved offline it is supplied by the owner (see README).
CONF_VEHICLE_IDENTIFIER = "vehicle_identifier"

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
# The device profile the captured app used, kept in one place: GW1 sends the
# model and SDK as headers while GW3 sends brand-model-sdk-release as
# ``loginDeviceId``, and the two must describe the same device.
DEVICE_BRAND = "Android"
DEVICE_MODEL = "Android SDK built for arm64"
DEVICE_SDK = "26"
DEVICE_OS_RELEASE = "8.0.0"
DEFAULT_LOGIN_DEVICE_ID = (
    f"{DEVICE_BRAND}-{DEVICE_MODEL}-{DEVICE_SDK}-{DEVICE_OS_RELEASE}"
)

# Bumped whenever the shape of the login request changes in a way that should
# invalidate tokens minted by an older build.  ``store_tokens`` drops the stored
# GW3 token when the entry was written by a different revision, which forces one
# fresh ``snc_login`` instead of silently reusing a session the gateway built
# from the old request — without it, a fix like the device id above would never
# take effect until the token happened to expire.
#
# Rev 3: no request change — it exists to *observe* one successful login
# response.  The diagnostics had only ever captured failed logins, so the field
# structure of a successful one (the only place the platform could hand out a
# per-vehicle token) was unknown.
#
# Rev 4: the client identity changed — GW1 now asks as the Android app the
# capture shows instead of an iOS client, and the App version tracks the real
# App (5.0.5) rather than the eight-month-old captured value.  A token minted
# under the old identity would keep the old answer alive until it expired, so
# the stored one is dropped and minted again.
CREDENTIAL_REVISION = 4

DRIVE_SIDE_LHD = "lhd"
DRIVE_SIDE_RHD = "rhd"

DEFAULT_NAME = DOMAIN
# Five minutes made a change made in the phone app take up to five minutes to
# reach Home Assistant, which reads as "the integration is broken".  Two is the
# balance: worst-case lag halves, and the extra requests stay modest (each poll
# costs three calls per vehicle).  One minute is available for anyone who wants
# the floor; below that the car's own upload cadence becomes the bottleneck.
DEFAULT_POLLING_INTERVAL = 2  # minutes
DEFAULT_REGION_CODE = "+86"
DEFAULT_SEAT_DURATION = 15  # minutes
DEFAULT_AC_DURATION = 15  # minutes
# Used when a climate start has no explicit setpoint.  The car reports "0.0"
# while the AC is off, so that value must never be sent back as a setpoint.
DEFAULT_TARGET_TEMP = 22.0
DEFAULT_STEERING_WHEEL_DURATION = 15  # minutes
DEFAULT_ENABLE_COMMANDS = True

# Polling interval bounds (minutes)
MIN_POLLING_INTERVAL = 1
MAX_POLLING_INTERVAL = 60

# Command duration bounds (minutes)
MIN_DURATION = 1
MAX_DURATION = 60

# Entities a given car may simply not have.
#
# The gateway's capability bitmap is per *service*, not per seat position: it
# says the car can do seat heating, never that the rear bench is heated.  The
# status payload is no help either — a car without rear heaters still returns
# ``rlHeatLv``/``rrHeatLv``, as a plain 0.  So whether these controls are real
# is something only the owner knows, and this option lets them say so.
CONF_HIDDEN_ENTITIES = "hidden_entities"
DEFAULT_HIDDEN_ENTITIES: list[str] = []

HIDABLE_ENTITIES: dict[str, str] = {
    "seat_heat_driver": "座椅 · 主驾加热",
    "seat_heat_passenger": "座椅 · 副驾加热",
    "seat_heat_rear_left": "座椅 · 左后加热",
    "seat_heat_rear_right": "座椅 · 右后加热",
    "seat_vent_driver": "座椅 · 主驾通风",
    "seat_vent_passenger": "座椅 · 副驾通风",
    "steering_wheel_heat": "方向盘加热",
    "sunshade": "遮阳帘",
    "charge_lid_lock": "充电口盖",
    "sentry": "哨兵模式",
}

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

# GRIC channel tokens.  Kept separate from the SNC ones above: the two are
# independent sessions and an entry uses exactly one, so sharing a key would let
# a value left over from the other channel be picked up as if it were valid.
STORAGE_GRIC_ACCESS_TOKEN = "gric_access_token"
STORAGE_GRIC_REFRESH_TOKEN = "gric_refresh_token"

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
SERVICE_SET_CLIMATE = "set_climate"

# Service attributes
ATTR_VIN = "vin"
ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_TEMPERATURE = "temperature"
ATTR_DURATION = "duration"
ATTR_ENABLED = "enabled"

STARTUP_MESSAGE = f"""
-------------------------------------------------------------------
{NAME}
Version: {INTEGRATION_VERSION}
Zeekr China mainland SMS (+86) login
If you have any issues with this you need to open an issue here:
{ISSUE_URL}
-------------------------------------------------------------------
"""
