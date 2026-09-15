"""The Zeekr EV integration — China mainland (SMS / +86) login only."""

from __future__ import annotations

import logging

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import (
    ConfigEntryNotReady,
    HomeAssistantError,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api_sms import ZeekrSmsApiClient
from .const import (
    ATTR_CONFIG_ENTRY_ID,
    ATTR_VIN,
    DOMAIN,
    PLATFORMS,
    SERVICE_DUMP_RAW,
    SERVICE_REFRESH,
    STARTUP_MESSAGE,
)
from .coordinator import ZeekrCoordinator

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Integration is configured through the UI only."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a Zeekr account from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    if hass.data[DOMAIN].get(entry.entry_id) is not None:
        return True

    _LOGGER.info(STARTUP_MESSAGE)

    session = async_get_clientsession(hass)
    client = ZeekrSmsApiClient(session)
    client.store_tokens(entry.data)

    coordinator = ZeekrCoordinator(hass, client, entry)
    await coordinator.async_init_stats()

    try:
        # Raises ConfigEntryAuthFailed (-> reauth) or ConfigEntryNotReady.
        await coordinator.async_config_entry_first_refresh()
    except Exception as err:  # noqa: BLE001 - re-raised as ConfigEntryNotReady
        if isinstance(err, (ConfigEntryNotReady, HomeAssistantError)):
            raise
        raise ConfigEntryNotReady(f"初始化极氪账户失败: {err}") from err

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _async_register_services(hass)
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


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload when options change."""
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
