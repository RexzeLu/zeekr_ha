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
from collections.abc import Callable
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

from .api_gric import ZeekrGricApiClient
from .api_sms import (
    ZeekrApiError,
    ZeekrAuthError,
    ZeekrError,
    ZeekrSmsApiClient,
    ZeekrVehicle,
)
from .const import (
    CONF_AC_DURATION,
    CONF_ENABLE_COMMANDS,
    CONF_HIDDEN_ENTITIES,
    CONF_POLLING_INTERVAL,
    CONF_SEAT_DURATION,
    CONF_STEERING_WHEEL_DURATION,
    DEFAULT_AC_DURATION,
    DEFAULT_ENABLE_COMMANDS,
    DEFAULT_HIDDEN_ENTITIES,
    DEFAULT_POLLING_INTERVAL,
    DEFAULT_SEAT_DURATION,
    DEFAULT_STEERING_WHEEL_DURATION,
    DEFAULT_TARGET_TEMP,
    DOMAIN,
)
from .optimistic import OptimisticStore, assign, dig
from .request_stats import ZeekrRequestStats

_LOGGER = logging.getLogger(__name__)

# Seconds to wait after a command before re-polling the car.  The car has to be
# woken up by the command and needs a while to report back, so a single short
# re-poll normally still returns the *old* state -- which silently undid the
# optimistic update and made successful commands look like failures.  Poll a few
# times instead, spread over a minute.
#
# This is the SNC default.  A channel may override it with its own
# ``command_refresh_delays`` attribute (GRIC does: its lock report took ~120 s).
COMMAND_REFRESH_DELAYS: tuple[int, ...] = (10, 30, 60)


class ZeekrCoordinator(DataUpdateCoordinator[dict[str, dict[str, Any]]]):
    """Fetch and normalise Zeekr vehicle state."""

    def __init__(self, hass: HomeAssistant,
                 client: ZeekrSmsApiClient | ZeekrGricApiClient,
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
        self._unsub_refreshes: list[Callable[[], None]] = []
        self.entry.async_on_unload(self._cancel_scheduled_refreshes)
        self._optimistic = OptimisticStore()
        # Set by the number entity; falls back to the stored option.
        self._ac_duration_override: int | None = None

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
        """Minutes the next climate start should run for.

        The stored option is the default; a value set on the number entity wins
        because it is what the user asked for most recently.  The App behaves
        the same way — you pick a duration each time you start the cabin AC.
        """
        if self._ac_duration_override is not None:
            return int(self._ac_duration_override)
        return int(self._option(CONF_AC_DURATION, DEFAULT_AC_DURATION))

    def set_ac_duration(self, minutes: int) -> None:
        """Set the runtime override used by the next climate start."""
        self._ac_duration_override = int(minutes)

    @property
    def steering_wheel_duration(self) -> int:
        return int(
            self._option(CONF_STEERING_WHEEL_DURATION, DEFAULT_STEERING_WHEEL_DURATION)
        )

    @property
    def commands_enabled(self) -> bool:
        return bool(self._option(CONF_ENABLE_COMMANDS, DEFAULT_ENABLE_COMMANDS))

    @property
    def hidden_entities(self) -> set[str]:
        """Entity keys the user asked us not to create.

        Used for hardware this particular car does not have.  The capability
        bitmap cannot express it (it is per service, not per seat) and the
        status payload reports a plain 0 either way, so the owner is the only
        authority — see :data:`~.const.HIDABLE_ENTITIES`.
        """
        raw = self._option(CONF_HIDDEN_ENTITIES, DEFAULT_HIDDEN_ENTITIES)
        if isinstance(raw, (list, tuple, set)):
            return {str(item) for item in raw}
        return set()

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
            if not self.client.has_gw3_token:
                _LOGGER.warning(
                    "同时没有 GW3 访问令牌，远程指令（车锁 / 空调等）不可用。"
                    "原因：%s",
                    self.client.gateway_summary().get("gw3_login_error"),
                )
        self.latest_poll_time = datetime.now().isoformat()
        self._async_persist_tokens()
        return self._optimistic.apply(data)

    def _async_persist_tokens(self) -> None:
        """Store rotated gateway tokens back into the config entry.

        Only the login-time snapshot used to be persisted, so a token rotated
        mid-session was lost on restart — and a stale refresh token can be
        rejected outright.  The config-entry update listener ignores data-only
        updates, so this does not trigger a reload.
        """
        tokens = {
            key: value
            for key, value in self.client.get_token_storage().items()
            if value and self.entry.data.get(key) != value
        }
        if not tokens:
            return
        _LOGGER.debug("已持久化更新的令牌字段: %s", sorted(tokens))
        self.hass.config_entries.async_update_entry(
            self.entry, data={**self.entry.data, **tokens}
        )

    async def async_force_discovery(self) -> None:
        """Re-query the vehicle list (used by the refresh service/button)."""
        await self.client.async_get_vehicle_list()
        await self.async_request_refresh()

    # -- optimistic state -------------------------------------------------

    @callback
    def set_optimistic(self, vin: str, *path: str, value: Any) -> None:
        """Reflect a just-issued command in the UI immediately.

        The car is cloud-polled, so the first poll after a command usually still
        carries the *previous* state.  The intended value is handed to the
        :class:`~.optimistic.OptimisticStore`, which re-applies it on subsequent
        polls until the car reports something different.
        """
        if not self.data or vin not in self.data or not path:
            return
        cached = self.data[vin]
        self._optimistic.set(vin, tuple(path), value, dig(cached, tuple(path)))
        if assign(cached, tuple(path), value):
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
        try:
            return await self.client.async_do_remote_control(
                vin, command, service_id, setting
            )
        except ZeekrError as err:
            # HomeAssistantError surfaces the text in the UI; a bare Exception
            # only ever showed up as "unknown error".
            raise HomeAssistantError(str(err)) from err

    async def async_send_and_refresh(self, vin: str, command: str,
                                     service_id: str,
                                     setting: dict[str, Any],
                                     delay: int | None = None
                                     ) -> dict[str, Any]:
        """Send a command then re-poll shortly afterwards."""
        result = await self.async_send_command(vin, command, service_id, setting)
        self._schedule_refresh(delay)
        return result

    def _schedule_refresh(self, delay: int | None = None) -> None:
        """Queue re-polls after a command.

        Defaults to :data:`COMMAND_REFRESH_DELAYS` because the car has to wake up
        and report back; pass an explicit ``delay`` to poll just once.
        """
        self._cancel_scheduled_refreshes()
        delays = (delay,) if delay is not None else getattr(
            self.client, "command_refresh_delays", COMMAND_REFRESH_DELAYS
        )

        async def _refresh(_now) -> None:
            await self.async_request_refresh()

        for seconds in delays:
            self._unsub_refreshes.append(
                async_call_later(self.hass, seconds, _refresh)
            )

    @callback
    def _cancel_scheduled_refreshes(self) -> None:
        for unsub in self._unsub_refreshes:
            unsub()
        self._unsub_refreshes.clear()

    def _sane_target_temp(self, vin: str) -> float:
        """Last setpoint the car reported, or the default if it is unusable.

        The cloud answers ``"0.0"`` for ``currentTemperature`` whenever the AC
        is off, and echoing that back would ask the car to cool to zero.
        """
        cached = (self.data or {}).get(vin) or {}
        try:
            value = float((cached.get("climate") or {}).get("target_temp"))
        except (TypeError, ValueError):
            return DEFAULT_TARGET_TEMP
        return value if value > 0 else DEFAULT_TARGET_TEMP

    async def async_set_climate(self, vin: str, *, enabled: bool = True,
                                temperature: float | None = None,
                                duration: int | None = None
                                ) -> dict[str, Any]:
        """Start or stop the cabin AC, optionally for a set number of minutes.

        ``AC.duration`` is what makes the car stop pre-conditioning on its own,
        which is how the App starts it; a start without it inherits whatever the
        last call left behind.  Both the climate entity and the ``set_climate``
        service go through here so the payload cannot drift apart.
        """
        if duration is not None:
            self.set_ac_duration(int(duration))
        parameters = [{"key": "AC", "value": "true" if enabled else "false"}]
        if enabled:
            if temperature is None:
                temperature = self._sane_target_temp(vin)
            parameters.append({"key": "AC.temp", "value": str(temperature)})
            parameters.append(
                {"key": "AC.duration", "value": str(self.ac_duration)}
            )

        result = await self.async_send_and_refresh(
            vin, "start", "ZAF", {"serviceParameters": parameters}
        )
        self.set_optimistic(vin, "climate", "ac_on", value=enabled)
        if enabled and temperature is not None:
            self.set_optimistic(vin, "climate", "target_temp", value=float(temperature))
        return result

    async def async_set_charge_plan(self, vin: str, start_time: str,
                                    end_time: str, command: str,
                                    bc_cycle: bool = False,
                                    bc_temp: bool = False) -> dict[str, Any]:
        self._ensure_commands_enabled()
        await self.request_stats.async_inc_invoke()
        try:
            result = await self.client.async_set_charge_plan(
                vin, start_time, end_time, command, bc_cycle, bc_temp
            )
        except ZeekrError as err:
            raise HomeAssistantError(str(err)) from err
        self._schedule_refresh()
        return result

    async def async_set_travel_plan(self, vin: str, command: str,
                                    start_time: str, scheduled_time: str,
                                    ac_preconditioning: bool = True,
                                    steering_wheel_heating: bool = False
                                    ) -> dict[str, Any]:
        self._ensure_commands_enabled()
        await self.request_stats.async_inc_invoke()
        try:
            result = await self.client.async_set_travel_plan(
                vin, command, start_time, scheduled_time,
                ac_preconditioning, steering_wheel_heating,
            )
        except ZeekrError as err:
            raise HomeAssistantError(str(err)) from err
        self._schedule_refresh()
        return result

    # -- diagnostics ------------------------------------------------------

    def pending_optimistic(self) -> dict[str, Any]:
        """Intended values still waiting for the car to confirm them."""
        return self._optimistic.pending()

    def dump_raw(self) -> dict[str, Any]:
        return self.client.dump_raw()


# Backwards-compatible alias (older code/tests referenced this name).
ZeekrSmsCoordinator = ZeekrCoordinator
