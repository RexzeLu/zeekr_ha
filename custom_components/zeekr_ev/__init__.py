"""The Zeekr EV integration.

Two authentication channels are supported and chosen per config entry:

* **SMS (+86)** — the classic login against ``api-gw-toc.zeekrlife.com``.  This
  is what the car's *owner* uses.
* **GRIC** — seeded with the app's own refresh token (``gric-*.geely.com``),
  which is the channel that works for an account the SNC gateway refuses, such
  as a shared car (``isOwner: false``).

Both clients expose the same surface, so the platforms never branch on it.
"""

from __future__ import annotations

import logging
import re

import homeassistant.helpers.config_validation as cv
import homeassistant.helpers.entity_registry as er
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse, callback
from homeassistant.exceptions import (
    ConfigEntryError,
    ConfigEntryNotReady,
    HomeAssistantError,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api_gric import ZeekrGricApiClient
from .api_sms import ZeekrSmsApiClient
from .const import (
    ATTR_CONFIG_ENTRY_ID,
    ATTR_DURATION,
    ATTR_ENABLED,
    ATTR_TEMPERATURE,
    ATTR_VIN,
    AUTH_METHOD_GRIC,
    CONF_AC_DURATION,
    CONF_AUTH_METHOD,
    CONF_PHONE,
    CONF_REGION_CODE,
    CONF_VEHICLE_IDENTIFIER,
    CONF_VEHICLE_TOKEN,
    DEFAULT_AC_DURATION,
    DEFAULT_AUTH_METHOD,
    DOMAIN,
    MAX_DURATION,
    MIN_DURATION,
    PLATFORMS,
    SERVICE_DUMP_RAW,
    SERVICE_REFRESH,
    SERVICE_SET_CLIMATE,
    STARTUP_MESSAGE,
)
from .coordinator import ZeekrCoordinator

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


def _auth_method(entry: ConfigEntry) -> str:
    """Which gateway this entry talks to.

    Entries written before the channel existed carry no ``auth_method`` at all,
    and those are SMS ones — the default is what keeps them loading unchanged.
    """
    return str(
        entry.options.get(CONF_AUTH_METHOD)
        or entry.data.get(CONF_AUTH_METHOD)
        or DEFAULT_AUTH_METHOD
    )


def _build_client(session, entry: ConfigEntry
                  ) -> ZeekrSmsApiClient | ZeekrGricApiClient:
    """Instantiate the client for the entry's channel and seed it.

    Both clients expose the same surface, so nothing downstream branches on the
    channel — only this factory does.
    """
    if _auth_method(entry) == AUTH_METHOD_GRIC:
        gric = ZeekrGricApiClient(session)
        gric.store_tokens(entry.data)
        # The app's per-vehicle ``x-vehicle-identifier``; without it the car can
        # be listed but not read or driven (see api_gric).
        gric.set_vehicle_identifier(
            entry.options.get(CONF_VEHICLE_IDENTIFIER)
            or entry.data.get(CONF_VEHICLE_IDENTIFIER)
        )
        return gric

    sms = ZeekrSmsApiClient(session)
    sms.store_tokens(entry.data)
    # The platform's own per-vehicle X-VIN token, when the owner supplied one.
    sms.set_vehicle_token(
        entry.options.get(CONF_VEHICLE_TOKEN)
        or entry.data.get(CONF_VEHICLE_TOKEN)
    )
    return sms


def _account_key(entry: ConfigEntry) -> str | None:
    """Return a comparable key for the account behind an entry."""
    digits = re.sub(r"\D", "", str(entry.data.get(CONF_PHONE) or ""))
    if not digits:
        return None
    region = str(entry.data.get(CONF_REGION_CODE) or "").strip()
    return f"{region}{digits}"


def _async_guard_against_duplicate_account(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Refuse to load a second entry that logs into the same account.

    Two entries for one account publish the exact same entity ``unique_id``s
    (``{vin}_{key}``) and Home Assistant can only keep one of them: the newer
    entry's entities are silently dropped ("Platform zeekr_ev does not generate
    unique IDs") and, once the older entry stops loading, its entities linger as
    *restored* ones, which the UI renders as ``unavailable``.  That looks like a
    parser/position bug but is really a duplicate-account problem, so fail with
    an explicit message instead of half-working.
    """
    account = _account_key(entry)
    if account is None:
        return

    for other in hass.config_entries.async_entries(DOMAIN):
        if other.entry_id == entry.entry_id or _account_key(other) != account:
            continue
        if other.state is not ConfigEntryState.LOADED:
            # The other entry is broken/disabled; this one takes over.
            continue
        raise ConfigEntryError(
            "检测到重复的极氪配置项"
            f"「{other.title}」（{other.entry_id}），它与本配置项登录的是同一个账号。"
            "两者的实体唯一 ID 会冲突，导致位置等实体长期显示“不可用”。"
            "请到「设置 → 设备与服务 → 极氪」删除多余的配置项后重启 "
            "Home Assistant。"
        )


def _async_guard_against_shared_vehicles(
    hass: HomeAssistant, entry: ConfigEntry, coordinator: ZeekrCoordinator
) -> None:
    """Refuse an entry whose car is already published by another entry.

    Entity ``unique_id``s are ``{vin}_{key}`` — derived from the *car*, not from
    the account.  Two entries that can both see one car therefore fight over the
    same ids: Home Assistant keeps the first set and silently drops the second
    ("Platform zeekr_ev does not generate unique IDs"), after which the loser's
    entities linger as *restored* ones the UI renders as ``unavailable``.

    That is a confusing way to fail, and it is exactly what happens when someone
    swaps accounts by *adding* the new one instead of replacing the old — so say
    it outright, with the step that fixes it.
    """
    claimed: dict[str, str] = {}
    for other_id, other in hass.data.get(DOMAIN, {}).items():
        if other_id == entry.entry_id or not isinstance(other, ZeekrCoordinator):
            continue
        for vin in other.vehicle_vins():
            claimed.setdefault(vin, other_id)

    shared = [vin for vin in coordinator.vehicle_vins() if vin in claimed]
    if not shared:
        return

    owner_id = claimed[shared[0]]
    titles = {
        other.entry_id: other.title
        for other in hass.config_entries.async_entries(DOMAIN)
    }
    raise ConfigEntryError(
        f"车辆 {', '.join(shared)} 已经由配置项"
        f"「{titles.get(owner_id, owner_id)}」（{owner_id}）提供实体。"
        "同一辆车只能交给一个配置项：实体唯一 ID 是按车辆生成的，两个配置项会"
        "争抢同一组 ID，后者的实体会被 Home Assistant 忽略并长期显示“不可用”。"
        "如果本配置项是要换用另一个账号，请先到「设置 → 设备与服务 → 极氪」"
        "删除上面那个配置项，再重新添加。"
    )


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Integration is configured through the UI only."""
    hass.data.setdefault(DOMAIN, {})
    return True


@callback
def _async_purge_hidden_entities(hass: HomeAssistant, entry: ConfigEntry,
                                 coordinator: "ZeekrCoordinator") -> None:
    """Drop registry entries for controls this car does not have.

    Simply not adding the entity is not enough — Home Assistant keeps registry
    entries around, so ticking "rear seat heaters" in the options would leave a
    dead control that only ever reads *unavailable*.  Removing the entry is
    what actually makes it disappear.
    """
    hidden = coordinator.hidden_entities
    if not hidden:
        return
    prefixes = [f"{vin}_" for vin in coordinator.vehicle_vins()]
    if not prefixes:
        return
    registry = er.async_get(hass)
    for entity in list(registry.entities.values()):
        if entity.config_entry_id != entry.entry_id:
            continue
        unique_id = entity.unique_id or ""
        for prefix in prefixes:
            # ``unique_id`` is "<vin>_<key>"; the key itself contains
            # underscores, so match on the VIN prefix rather than splitting.
            if unique_id.startswith(prefix) and unique_id[len(prefix):] in hidden:
                _LOGGER.debug("移除本车没有的功能实体: %s", entity.entity_id)
                registry.async_remove(entity.entity_id)
                break


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a Zeekr account from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    if hass.data[DOMAIN].get(entry.entry_id) is not None:
        return True

    _async_guard_against_duplicate_account(hass, entry)

    _LOGGER.info(STARTUP_MESSAGE)

    session = async_get_clientsession(hass)
    client = _build_client(session, entry)

    coordinator = ZeekrCoordinator(hass, client, entry)
    await coordinator.async_init_stats()

    try:
        # Raises ConfigEntryAuthFailed (-> reauth) or ConfigEntryNotReady.
        await coordinator.async_config_entry_first_refresh()
    except Exception as err:  # noqa: BLE001 - re-raised as ConfigEntryNotReady
        if isinstance(err, (ConfigEntryNotReady, HomeAssistantError)):
            raise
        raise ConfigEntryNotReady(f"初始化极氪账户失败: {err}") from err

    try:
        _async_guard_against_shared_vehicles(hass, entry, coordinator)
    except ConfigEntryError:
        # The entry already spent requests on its first refresh; keep the tally.
        await coordinator.request_stats.async_shutdown()
        raise

    hass.data[DOMAIN][entry.entry_id] = coordinator

    _async_purge_hidden_entities(hass, entry, coordinator)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _async_register_services(hass)
    hass.data[DOMAIN][_options_snapshot_key(entry.entry_id)] = dict(entry.options)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    coordinator: ZeekrCoordinator | None = hass.data.get(DOMAIN, {}).get(
        entry.entry_id
    )
    if coordinator is not None:
        await coordinator.request_stats.async_shutdown()

    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        hass.data[DOMAIN].pop(_options_snapshot_key(entry.entry_id), None)

    if not hass.data.get(DOMAIN):
        for service in (SERVICE_REFRESH, SERVICE_DUMP_RAW):
            if hass.services.has_service(DOMAIN, service):
                hass.services.async_remove(DOMAIN, service)
    return unloaded


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Reject entries created by the removed email/password flow."""
    if entry.version > 1:
        return True

    data = entry.data or {}
    looks_like_email = (
        "username" in data
        or "password" in data
        or data.get("login_type") == "email"
    )
    if looks_like_email:
        _LOGGER.error(
            "配置项 %s 使用已移除的邮箱登录方式。邮箱登录在中国大陆不可用，"
            "请删除该配置项后使用手机号短信验证码重新添加。",
            entry.entry_id,
        )
        return False
    return True


def _options_snapshot_key(entry_id: str) -> str:
    return f"options::{entry_id}"


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload when the *options* change.

    Rotated gateway tokens are written back into the entry as well, and
    reloading the integration every time one is refreshed would be both
    pointless and disruptive — hence the options snapshot comparison.
    """
    key = _options_snapshot_key(entry.entry_id)
    current = dict(entry.options)
    if hass.data.get(DOMAIN, {}).get(key) == current:
        return
    hass.data.setdefault(DOMAIN, {})[key] = current
    await hass.config_entries.async_reload(entry.entry_id)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def _async_register_services(hass: HomeAssistant) -> None:
    """Register the integration services (idempotent)."""

    async def _service_refresh(call: ServiceCall) -> None:
        entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
        targets = [
            coord
            for eid, coord in hass.data.get(DOMAIN, {}).items()
            if isinstance(coord, ZeekrCoordinator) and (not entry_id or eid == entry_id)
        ]
        if not targets:
            raise HomeAssistantError("未找到匹配的极氪配置项")
        for coordinator in targets:
            await coordinator.async_force_discovery()

    async def _service_dump_raw(call: ServiceCall) -> dict:
        entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
        vin = call.data.get(ATTR_VIN)
        result: dict[str, dict] = {}
        for eid, coordinator in hass.data.get(DOMAIN, {}).items():
            if not isinstance(coordinator, ZeekrCoordinator):
                continue
            if entry_id and eid != entry_id:
                continue
            dump = coordinator.dump_raw()
            if vin:
                dump["raw_payloads"] = {
                    key: value
                    for key, value in (dump.get("raw_payloads") or {}).items()
                    if key == vin
                }
            result[eid] = dump
        if not result:
            raise HomeAssistantError("未找到匹配的极氪配置项")
        return result

    async def _service_set_climate(call: ServiceCall) -> dict:
        """Start/stop the cabin AC with an explicit run time.

        This is the App's "run the AC for N minutes and stop" as a callable, so
        an automation can pick the duration per call instead of sharing the one
        value stored in the options.
        """
        entry_id = call.data.get(ATTR_CONFIG_ENTRY_ID)
        vin = call.data.get(ATTR_VIN)
        enabled = bool(call.data.get(ATTR_ENABLED, True))
        temperature = call.data.get(ATTR_TEMPERATURE)
        duration = call.data.get(ATTR_DURATION)

        if temperature is not None:
            temperature = float(temperature)
        if duration is not None:
            duration = int(duration)
            if not MIN_DURATION <= duration <= MAX_DURATION:
                raise HomeAssistantError(
                    f"duration 需在 {MIN_DURATION}–{MAX_DURATION} 分钟之间，收到 {duration}"
                )

        results: dict[str, dict] = {}
        for eid, coordinator in hass.data.get(DOMAIN, {}).items():
            if not isinstance(coordinator, ZeekrCoordinator):
                continue
            if entry_id and eid != entry_id:
                continue
            targets = [vin] if vin else [
                vehicle.vin for vehicle in coordinator.vehicles
            ]
            for target in targets:
                results[target] = await coordinator.async_set_climate(
                    target,
                    enabled=enabled,
                    temperature=temperature,
                    duration=duration,
                )
        if not results:
            raise HomeAssistantError("未找到匹配的极氪配置项或车辆")
        return results

    if not hass.services.has_service(DOMAIN, SERVICE_REFRESH):
        hass.services.async_register(
            DOMAIN,
            SERVICE_REFRESH,
            _service_refresh,
            schema=vol.Schema({vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string}),
        )

    if not hass.services.has_service(DOMAIN, SERVICE_DUMP_RAW):
        hass.services.async_register(
            DOMAIN,
            SERVICE_DUMP_RAW,
            _service_dump_raw,
            schema=vol.Schema(
                {
                    vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
                    vol.Optional(ATTR_VIN): cv.string,
                }
            ),
            supports_response=SupportsResponse.ONLY,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_SET_CLIMATE):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SET_CLIMATE,
            _service_set_climate,
            schema=vol.Schema(
                {
                    vol.Optional(ATTR_CONFIG_ENTRY_ID): cv.string,
                    vol.Optional(ATTR_VIN): cv.string,
                    vol.Optional(ATTR_ENABLED, default=True): cv.boolean,
                    vol.Optional(ATTR_TEMPERATURE): vol.Coerce(float),
                    vol.Optional(ATTR_DURATION): vol.All(
                        vol.Coerce(int), vol.Range(min=MIN_DURATION, max=MAX_DURATION)
                    ),
                }
            ),
            supports_response=SupportsResponse.ONLY,
        )
