"""DataUpdateCoordinator for the Zeekr EV integration.

Wraps :class:`~.api_sms.ZeekrSmsApiClient` and exposes:

* ``_async_update_data`` – poll + normalise every vehicle's status;
* ``async_send_command`` / ``async_set_charge_plan`` / ``async_set_travel_plan``
  – the single funnel every entity platform uses to talk to the car;
* ``set_optimistic`` – reflect a just-issued command in the UI immediately;
* option accessors for durations, polling interval and the command switch.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers.event import async_call_later, async_track_time_change
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .api_sms import ZeekrApiError, ZeekrAuthError, ZeekrSmsApiClient, ZeekrVehicle
from .const import (
    CONF_AC_DURATION,
    CONF_ENABLE_COMMANDS,
    CONF_POLLING_INTERVAL,
    CONF_SEAT_DURATION,
    CONF_STEERING_WHEEL_DURATION,
    DEFAULT_AC_DURATION,
    DEFAULT_ENABLE_COMMANDS,
    DEFAULT_POLLING_INTERVAL,
    DEFAULT_SEAT_DURATION,
    DEFAULT_STEERING_WHEEL_DURATION,
    DOMAIN,
)
from .request_stats import ZeekrRequestStats

_LOGGER = logging.getLogger(__name__)

# Seconds to wait after a command before re-polling the car.
COMMAND_REFRESH_DELAY = 12


class ZeekrCoordinator(DataUpdateCoordinator[dict[str, dict[str, Any]]]):
    """Fetch and normalise Zeekr vehicle state."""

    def __init__(self, hass: HomeAssistant, client: ZeekrSmsApiClient,
                 entry: ConfigEntry) -> None:
        self.client = client
        self.entry = entry
        self.request_stats = ZeekrRequestStats(hass)
        self.latest_poll_time: str | None = None

        polling = self._option(CONF_POLLING_INTERVAL, DEFAULT_POLLING_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(minutes=int(polling)),
        )

        self._unsub_reset = async_track_time_change(
            hass, self._handle_daily_reset, hour=0, minute=0, second=0
        )
        self.entry.async_on_unload(self._unsub_reset)
        self._unsub_refresh = None

    # -- options ----------------------------------------------------------

    def _option(self, key: str, default: Any) -> Any:
        if key in self.entry.options:
            return self.entry.options[key]
        return self.entry.data.get(key, default)

    @property
    def seat_duration(self) -> int:
        return int(self._option(CONF_SEAT_DURATION, DEFAULT_SEAT_DURATION))

    @property
    def ac_duration(self) -> int:
        return int(self._option(CONF_AC_DURATION, DEFAULT_AC_DURATION))

    @property
    def steering_wheel_duration(self) -> int:
        return int(
            self._option(CONF_STEERING_WHEEL_DURATION, DEFAULT_STEERING_WHEEL_DURATION)
        )

    @property
    def commands_enabled(self) -> bool:
        return bool(self._option(CONF_ENABLE_COMMANDS, DEFAULT_ENABLE_COMMANDS))

    # -- accessors --------------------------------------------------------

    @property
    def vehicles(self) -> list[ZeekrVehicle]:
        return self.client.vehicles

    def get_vehicle(self, vin: str) -> ZeekrVehicle | None:
        return self.client.get_vehicle(vin)

    def vehicle_vins(self) -> list[str]:
        """VINs from the vehicle list plus anything we already have data for."""
        vins = [vehicle.vin for vehicle in self.client.vehicles]
        for vin in (self.data or {}):
            if vin not in vins:
                vins.append(vin)
        return vins

    async def async_init_stats(self) -> None:
        await self.request_stats.async_load()

    async def _handle_daily_reset(self, now) -> None:
        await self.request_stats.async_reset_today()

    # -- polling ----------------------------------------------------------

    async def _async_update_data(self) -> dict[str, dict[str, Any]]:
        try:
            if not self.client.vehicles:
                await self.client.async_get_vehicle_list()
            await self.request_stats.async_inc_request()
            data = await self.client.async_fetch_all()
        except ZeekrAuthError as err:
            # Surfaces as a reauth prompt in the UI.
            raise ConfigEntryAuthFailed(str(err)) from err
        except ZeekrApiError as err:
            raise UpdateFailed(str(err)) from err
        except Exception as err:  # noqa: BLE001
            raise UpdateFailed(f"与极氪服务通信失败: {err}") from err

        if not data:
            _LOGGER.warning(
                "未获取到任何车辆数据：账号下可能没有车辆，或列表接口暂时不可用。"
                "集成会继续重试。"
            )
        self.latest_poll_time = datetime.now().isoformat()
        return data

    async def async_force_discovery(self) -> None:
        """Re-query the vehicle list (used by the refresh service/button)."""
        await self.client.async_get_vehicle_list()
        await self.async_request_refresh()

    # -- optimistic state -------------------------------------------------

    @callback
    def set_optimistic(self, vin: str, *path: str, value: Any) -> None:
        """Write a value into the cached state and notify listeners.

        Keeps the UI responsive between issuing a command and the next poll.
        """
        if not self.data or vin not in self.data:
            return
        node: Any = self.data[vin]
        for step in path[:-1]:
            if not isinstance(node, dict):
                return
            node = node.setdefault(step, {})
        if not isinstance(node, dict) or not path:
            return
        node[path[-1]] = value
        self.async_update_listeners()

    # -- commands ---------------------------------------------------------

    def _ensure_commands_enabled(self) -> None:
        if not self.commands_enabled:
            raise HomeAssistantError(
                "指令下发已在集成选项中关闭，请到「配置 → 选项」中开启。"
            )

    async def async_send_command(self, vin: str, command: str, service_id: str,
                                 setting: dict[str, Any]) -> dict[str, Any]:
        """Send a remote-control command (raises on failure)."""
        self._ensure_commands_enabled()
        await self.request_stats.async_inc_invoke()
        return await self.client.async_do_remote_control(
            vin, command, service_id, setting
        )

    async def async_send_and_refresh(self, vin: str, command: str,
                                     service_id: str,
                                     setting: dict[str, Any],
                                     delay: int = COMMAND_REFRESH_DELAY
                                     ) -> dict[str, Any]:
        """Send a command then re-poll shortly afterwards."""
        result = await self.async_send_command(vin, command, service_id, setting)
        self._schedule_refresh(delay)
        return result

    def _schedule_refresh(self, delay: int) -> None:
        if self._unsub_refresh is not None:
            self._unsub_refresh()
            self._unsub_refresh = None

        async def _refresh(_now) -> None:
            self._unsub_refresh = None
            await self.async_request_refresh()

        self._unsub_refresh = async_call_later(self.hass, delay, _refresh)

    async def async_set_charge_plan(self, vin: str, start_time: str,
                                    end_time: str, command: str,
                                    bc_cycle: bool = False,
                                    bc_temp: bool = False) -> dict[str, Any]:
        self._ensure_commands_enabled()
        await self.request_stats.async_inc_invoke()
        result = await self.client.async_set_charge_plan(
            vin, start_time, end_time, command, bc_cycle, bc_temp
        )
        self._schedule_refresh()
        return result

    async def async_set_travel_plan(self, vin: str, command: str,
                                    start_time: str, scheduled_time: str,
                                    ac_preconditioning: bool = True,
                                    steering_wheel_heating: bool = False
                                    ) -> dict[str, Any]:
        self._ensure_commands_enabled()
        await self.request_stats.async_inc_invoke()
        result = await self.client.async_set_travel_plan(
            vin, command, start_time, scheduled_time,
            ac_preconditioning, steering_wheel_heating,
        )
        self._schedule_refresh()
        return result

    # -- diagnostics ------------------------------------------------------

    def dump_raw(self) -> dict[str, Any]:
        return self.client.dump_raw()


# Backwards-compatible alias (older code/tests referenced this name).
ZeekrSmsCoordinator = ZeekrCoordinator
