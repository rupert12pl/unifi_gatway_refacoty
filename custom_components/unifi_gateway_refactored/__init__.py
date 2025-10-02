"""The UniFi Gateway Dashboard Analyzer integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers.typing import ConfigType

__all__ = ["async_setup", "async_setup_entry", "async_unload_entry"]

from .const import (
    CONF_HOST,
    CONF_SPEEDTEST_ENTITIES,
    DATA_RUNNER,
    DATA_UNDO_TIMER,
    DEFAULT_SPEEDTEST_ENTITIES,
    DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
    DOMAIN,
    PLATFORMS,
)
from .config import normalize_speedtest_entity_ids, resolve_speedtest_interval_seconds, get_wifi_settings
from .client_factory import async_get_client
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .migrations import async_migrate_speedtest_button_unique_id, async_migrate_interface_unique_ids
from .monitor import SpeedtestRunner

_LOGGER = logging.getLogger(__name__)

async def async_setup(hass: "HomeAssistant", config: "ConfigType") -> bool:
    """Set up the UniFi Gateway Dashboard Analyzer component."""
    _LOGGER.debug("Setting up UniFi Gateway Dashboard Analyzer integration")
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Set up UniFi Gateway Dashboard Analyzer from a config entry."""
    _LOGGER.debug("Setting up config entry %s", entry.title)

    client = await async_get_client(hass, entry)
    options = entry.options or {}

    speedtest_interval_seconds = resolve_speedtest_interval_seconds(options, entry.data)
    wifi_guest, wifi_iot = get_wifi_settings(options, entry.data)

    coordinator = UniFiGatewayDataUpdateCoordinator(
        hass,
        client,
        speedtest_interval=speedtest_interval_seconds,
    )
    await coordinator.async_config_entry_first_refresh()

    if speedtest_interval_seconds <= 0:
        interval_minutes = DEFAULT_SPEEDTEST_INTERVAL_MINUTES
    else:
        interval_minutes = max(5, round(speedtest_interval_seconds / 60))

    raw_entities = options.get(CONF_SPEEDTEST_ENTITIES, DEFAULT_SPEEDTEST_ENTITIES)
    entity_ids = normalize_speedtest_entity_ids(raw_entities)

    async def _noop_result_callback(
        *, success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        return None

    base_name = entry.title or entry.data.get(CONF_HOST) or "UniFi Gateway"

    entry_data = hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
        "on_result_cb": _noop_result_callback,
        DATA_RUNNER: None,
        DATA_UNDO_TIMER: None,
        "speedtest_entities": list(entity_ids),
        "speedtest_interval_minutes": interval_minutes,
        "device_name": base_name,
        "wifi_guest": wifi_guest,
        "wifi_iot": wifi_iot,
        "wifi_overrides": {"guest": wifi_guest, "iot": wifi_iot},
    }

    async def _dispatch_result(
        success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        store = hass.data.get(DOMAIN, {})
        data = store.get(entry.entry_id)
        if not data:
            return
        callback = data.get("on_result_cb")
        if callback is None:
            return
        await callback(
            success=success,
            duration_ms=duration_ms,
            error=error,
            trace_id=trace_id,
        )

    runner = SpeedtestRunner(hass, entity_ids, _dispatch_result, client, coordinator)
    entry_data[DATA_RUNNER] = runner

    _LOGGER.debug(
        "UniFi Gateway Dashboard Analyzer entry %s setup complete; scheduling platform forwards",
        entry.entry_id,
    )

    await async_migrate_speedtest_button_unique_id(hass, entry)
    await async_migrate_interface_unique_ids(hass, entry, client, coordinator.data)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    hass.async_create_task(runner.async_trigger(reason="init"))

    async def _periodic(_now) -> None:
        await runner.async_trigger(reason="schedule")

    from homeassistant.helpers.event import async_track_time_interval

    undo = async_track_time_interval(
        hass,
        _periodic,
        timedelta(minutes=interval_minutes),
    )
    entry_data[DATA_UNDO_TIMER] = undo

    _LOGGER.info(
        "UniFi Gateway Dashboard Analyzer entry %s fully initialized; Speedtest every %s minutes (entities=%s)",
        entry.entry_id,
        interval_minutes,
        entity_ids,
    )
    return True


async def async_unload_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Unload a config entry."""
    _LOGGER.debug("Unloading config entry %s", entry.title)
    stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if stored and (undo := stored.get(DATA_UNDO_TIMER)):
        undo()
        stored[DATA_UNDO_TIMER] = None
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        stored = hass.data.get(DOMAIN)
        if stored and entry.entry_id in stored:
            stored.pop(entry.entry_id)
        _LOGGER.debug(
            "UniFi Gateway Dashboard Analyzer entry %s unloaded", entry.entry_id
        )
    return unload_ok


