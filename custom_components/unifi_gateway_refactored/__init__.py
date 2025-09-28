"""The UniFi Gateway Dashboard Analyzer integration."""
from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from functools import partial
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import entity_registry as er
    from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_SPEEDTEST_ENTITIES,
    CONF_SPEEDTEST_INTERVAL,
    DATA_RUNNER,
    DATA_UNDO_TIMER,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_SPEEDTEST_ENTITIES,
    DEFAULT_SPEEDTEST_INTERVAL,
    DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    LEGACY_CONF_SPEEDTEST_INTERVAL_MIN,
    PLATFORMS,
)
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient
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

    from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

    client_kwargs: dict[str, Any] = {
        "host": entry.data[CONF_HOST],
        "port": entry.data.get(CONF_PORT, DEFAULT_PORT),
        "site_id": entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
        "ssl_verify": entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        "use_proxy_prefix": entry.data.get(
            CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
        ),
        "timeout": entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
    }

    username = entry.data.get(CONF_USERNAME)
    password = entry.data.get(CONF_PASSWORD)
    if username:
        client_kwargs["username"] = username
    if password:
        client_kwargs["password"] = password

    client_kwargs["instance_hint"] = entry.entry_id  # ensures stable unique_id across restarts

    client_factory = partial(UniFiOSClient, **client_kwargs)

    options = entry.options or {}

    def _coerce_int(value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    speedtest_interval_seconds: int | None = None
    for source in (options, entry.data):
        speedtest_interval_seconds = _coerce_int(source.get(CONF_SPEEDTEST_INTERVAL))
        if speedtest_interval_seconds is not None:
            break

    if speedtest_interval_seconds is None:
        legacy_minutes: int | None = None
        for source in (options, entry.data):
            legacy_minutes = _coerce_int(source.get(LEGACY_CONF_SPEEDTEST_INTERVAL_MIN))
            if legacy_minutes is not None:
                break
        if legacy_minutes is not None:
            speedtest_interval_seconds = max(0, legacy_minutes) * 60

    if speedtest_interval_seconds is None:
        speedtest_interval_seconds = DEFAULT_SPEEDTEST_INTERVAL
    else:
        speedtest_interval_seconds = max(0, speedtest_interval_seconds)

    try:
        client: UniFiOSClient = await hass.async_add_executor_job(client_factory)
    except AuthError as err:
        _LOGGER.error("Authentication failed while setting up entry %s: %s", entry.entry_id, err)
        raise ConfigEntryAuthFailed("Authentication with UniFi controller failed") from err
    except ConnectivityError as err:
        _LOGGER.error("Connectivity issue while setting up entry %s: %s", entry.entry_id, err)
        raise ConfigEntryNotReady(f"Cannot connect to UniFi controller: {err}") from err
    except APIError as err:
        _LOGGER.error("Controller error while setting up entry %s: %s", entry.entry_id, err)
        raise ConfigEntryNotReady(f"UniFi controller error: {err}") from err

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
    entity_ids: list[str] = []
    if isinstance(raw_entities, str):
        candidates = raw_entities.replace("\n", ",").split(",")
        entity_ids = [candidate.strip() for candidate in candidates if candidate.strip()]
    elif isinstance(raw_entities, (list, tuple, set)):
        for candidate in raw_entities:
            text = str(candidate).strip()
            if text:
                entity_ids.append(text)
    if not entity_ids:
        entity_ids = [
            candidate.strip()
            for candidate in DEFAULT_SPEEDTEST_ENTITIES.split(",")
            if candidate.strip()
        ]

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

    await _async_migrate_interface_unique_ids(hass, entry, client, coordinator.data)

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


async def _async_migrate_interface_unique_ids(
    hass: "HomeAssistant",
    entry: "ConfigEntry",
    client: UniFiOSClient,
    data: UniFiGatewayData | None,
) -> None:
    """Normalize WAN/LAN/WLAN sensor unique IDs."""

    from homeassistant.helpers import entity_registry as er
    from .sensor import (
        _wan_identifier_candidates,
        build_lan_unique_id,
        build_wan_unique_id,
        build_wlan_unique_id,
    )

    if not data:
        return

    mapping: dict[str, str] = {}
    instance_prefix = f"unifigw_{client.instance_key()}"

    for link in data.wan_links:
        if not isinstance(link, dict):
            continue
        link_id = str(link.get("id") or link.get("_id") or link.get("ifname") or "wan")
        link_name = link.get("name") or link_id
        identifiers = _wan_identifier_candidates(link_id, link_name, link)
        canonical = (sorted(identifiers) or [link_id])[0]
        old_key = hashlib.sha256(canonical.encode()).hexdigest()[:12]
        for suffix in ("status", "ip", "isp"):
            old_uid = f"{instance_prefix}_wan_{old_key}_{suffix}"
            new_uid = build_wan_unique_id(entry.entry_id, link, suffix)
            mapping[old_uid] = new_uid

    for network in data.lan_networks:
        if not isinstance(network, dict):
            continue
        net_id = str(
            network.get("_id") or network.get("id") or network.get("name") or "lan"
        )
        old_uid = f"{instance_prefix}_lan_{net_id}_clients"
        new_uid = build_lan_unique_id(entry.entry_id, network)
        mapping[old_uid] = new_uid

    for wlan in data.wlans:
        if not isinstance(wlan, dict):
            continue
        ssid = wlan.get("name") or wlan.get("ssid") or wlan.get("_id") or wlan.get("id")
        if not ssid:
            continue
        old_uid = f"{instance_prefix}_wlan_{ssid}_clients"
        new_uid = build_wlan_unique_id(entry.entry_id, wlan)
        mapping[old_uid] = new_uid

    if not mapping:
        _LOGGER.debug("No interface unique ID migrations required for entry %s", entry.entry_id)
        return

    registry = er.async_get(hass)

    async def _migrate(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
        if entity_entry.config_entry_id != entry.entry_id:
            return None
        new_uid = mapping.get(entity_entry.unique_id)
        if new_uid:
            return {"new_unique_id": new_uid}
        return None

    await er.async_migrate_entries(hass, DOMAIN, _migrate)
    _LOGGER.info(
        "Migrated %s interface entities to normalized unique IDs for entry %s",
        len(mapping),
        entry.entry_id,
    )


