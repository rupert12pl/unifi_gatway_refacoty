"""The UniFi Gateway Dashboard Analyzer integration."""
from __future__ import annotations

import asyncio
import hashlib
import logging
from datetime import timedelta
from functools import partial
from collections.abc import Mapping
from typing import Any, Iterable, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant
    from homeassistant.helpers import entity_registry as er
    from homeassistant.helpers.typing import ConfigType

from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from .async_client import UniFiGatewayAsyncClient

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
    CONF_WIFI_GUEST,
    CONF_WIFI_IOT,
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
from .async_wrapper import UniFiGatewayAsyncWrapper
from .monitor import SpeedtestRunner

_LOGGER = logging.getLogger(__name__)


def _split_entity_candidates(text: str) -> Iterable[str]:
    for candidate in text.replace("\n", ",").split(","):
        cleaned = candidate.strip()
        if cleaned:
            yield cleaned


_DEFAULT_SPEEDTEST_ENTITY_IDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        candidate
        for raw in DEFAULT_SPEEDTEST_ENTITIES
        for candidate in _split_entity_candidates(str(raw))
    )
) or (
    "sensor.speedtest_download",
    "sensor.speedtest_upload",
    "sensor.speedtest_ping",
)


def _normalize_speedtest_entity_ids(raw: Any) -> list[str]:
    """Normalize speedtest entity identifiers from options/data into a stable list."""

    normalized: dict[str, None] = {}

    def _add_from_text(text: str) -> None:
        for candidate in _split_entity_candidates(text):
            if candidate not in normalized:
                normalized[candidate] = None

    if isinstance(raw, str):
        _add_from_text(raw)
    elif isinstance(raw, (list, tuple, set)):
        for candidate in raw:
            if isinstance(candidate, str):
                _add_from_text(candidate)
            elif candidate is not None:
                text = str(candidate).strip()
                if text:
                    if text not in normalized:
                        normalized[text] = None

    if not normalized:
        return list(_DEFAULT_SPEEDTEST_ENTITY_IDS)

    return list(normalized)


def _resolve_speedtest_interval_seconds(
    options: Mapping[str, Any], data: Mapping[str, Any]
) -> int:
    """Determine the configured speedtest interval in seconds with legacy support."""

    def _coerce_int(value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    speedtest_interval_seconds: int | None = None
    for source in (options, data):
        candidate = _coerce_int(source.get(CONF_SPEEDTEST_INTERVAL))
        if candidate is not None:
            speedtest_interval_seconds = candidate
            break

    legacy_minutes: int | None = None
    for source in (options, data):
        candidate = _coerce_int(source.get(LEGACY_CONF_SPEEDTEST_INTERVAL_MIN))
        if candidate is not None:
            legacy_minutes = candidate
            break

    if legacy_minutes is not None:
        legacy_seconds = max(0, legacy_minutes) * 60
        if (
            legacy_minutes != DEFAULT_SPEEDTEST_INTERVAL_MINUTES
            or speedtest_interval_seconds is None
        ):
            speedtest_interval_seconds = legacy_seconds

    if speedtest_interval_seconds is None:
        speedtest_interval_seconds = DEFAULT_SPEEDTEST_INTERVAL

    return max(0, speedtest_interval_seconds)


def _normalize_wifi_option(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        cleaned = str(value).strip()
        return cleaned or None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    cleaned = str(value).strip()
    return cleaned or None


async def async_setup(hass: "HomeAssistant", config: "ConfigType") -> bool:
    """Set up the UniFi Gateway Dashboard Analyzer component."""
    _LOGGER.debug("Setting up UniFi Gateway Dashboard Analyzer integration")
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: "HomeAssistant", entry: "ConfigEntry") -> bool:
    """Set up UniFi Gateway Dashboard Analyzer from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    data = dict(entry.data)
    options = dict(entry.options)

    # Clean up existing client
    if entry.entry_id in hass.data[DOMAIN]:
        try:
            await hass.async_add_executor_job(
                lambda: hass.data[DOMAIN][entry.entry_id].close()
            )
        except Exception as err:
            _LOGGER.debug("Error closing existing client: %s", err)

    try:
        client = UniFiOSClient(
            host=data[CONF_HOST],
            username=data.get(CONF_USERNAME),
            password=data.get(CONF_PASSWORD),
            port=data.get(CONF_PORT, DEFAULT_PORT),
            site_id=data.get(CONF_SITE_ID, DEFAULT_SITE),
            ssl_verify=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            use_proxy_prefix=data.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
            timeout=data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        )

        # Test connection with retries
        for attempt in range(3):
            try:
                if not await hass.async_add_executor_job(client.ping):
                    raise ConnectivityError("Connection test failed")
                break
            except (ConnectivityError, APIError) as err:
                if attempt == 2:  # Last attempt
                    raise ConfigEntryNotReady(f"Connection failed: {err}")
                _LOGGER.warning(
                    "Connection attempt %d failed: %s, retrying...",
                    attempt + 1, 
                    err
                )
                await asyncio.sleep(2 * (attempt + 1))

        speedtest_interval = _resolve_speedtest_interval_seconds(options, data)
        coordinator = UniFiGatewayDataUpdateCoordinator(
            hass,
            client,
            speedtest_interval=speedtest_interval,
        )

        try:
            await coordinator.async_config_entry_first_refresh()
        except Exception as err:
            await hass.async_add_executor_job(client.close)
            raise ConfigEntryNotReady(f"Data refresh failed: {err}") from err
        
        hass.data[DOMAIN][entry.entry_id] = {
            "client": client,
            "coordinator": coordinator,
        }
        
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        return True
        
    except Exception as err:
        _LOGGER.error("Failed to set up %s: %s", entry.entry_id, err)
        if 'client' in locals():
            await hass.async_add_executor_job(client.close)
        raise ConfigEntryNotReady(f"Setup failed: {err}") from err
        async_client = UniFiGatewayAsyncClient(hass, client)

        # Verify connection
        if not await async_client.async_ping():
            raise ConnectivityError("Failed to connect")

        speedtest_interval = _resolve_speedtest_interval_seconds(options, data)
        
        coordinator = UniFiGatewayDataUpdateCoordinator(
            hass,
            client,
            speedtest_interval=speedtest_interval,
        )

        await coordinator.async_config_entry_first_refresh()

        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = {
            "client": async_client,
            "coordinator": coordinator,
        }

        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        return True

    except Exception as err:
        if 'client' in locals():
            await hass.async_add_executor_job(client.close)
        raise ConfigEntryNotReady(f"Failed to set up: {err}") from err


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload UniFi Gateway config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        if client := hass.data[DOMAIN].pop(entry.entry_id, {}).get("client"):
            await client.async_close()
    return unload_ok


async def _async_migrate_speedtest_button_unique_id(
    hass: "HomeAssistant", entry: "ConfigEntry"
) -> None:
    """Ensure the Run Speedtest button unique ID is namespaced per config entry."""

    from homeassistant.helpers import entity_registry as er

    try:
        from .utils import build_speedtest_button_unique_id
    except ImportError:  # pragma: no cover - defensive guard
        return

    old_unique_id = "unifi_gateway_refactored_run_speedtest"
    new_unique_id = build_speedtest_button_unique_id(entry.entry_id)

    if old_unique_id == new_unique_id:
        return

    migrated = False

    async def _migrate(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
        nonlocal migrated
        if entity_entry.config_entry_id != entry.entry_id:
            return None
        if entity_entry.unique_id != old_unique_id:
            return None
        migrated = True
        return {"new_unique_id": new_unique_id}

    await er.async_migrate_entries(hass, DOMAIN, _migrate)

    if migrated:
        _LOGGER.info(
            "Migrated Run Speedtest button unique ID for entry %s", entry.entry_id
        )


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
        for suffix in ("status", "ip", "ipv6", "isp"):
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

    async def _migrate(entity_entry: er.RegistryEntry) -> dict[str, str] | None:
        if entity_entry.config_entry_id != entry.entry_id:
            return None
        unique_id = entity_entry.unique_id
        if unique_id is None:
            return None
        new_uid = mapping.get(unique_id)
        if new_uid:
            return {"new_unique_id": new_uid}
        return None

    await er.async_migrate_entries(hass, DOMAIN, _migrate)
    _LOGGER.info(
        "Migrated %s interface entities to normalized unique IDs for entry %s",
        len(mapping),
        entry.entry_id,
    )


async def _validate_connection(hass: HomeAssistant, data: dict) -> None:
    """Validate the connection with retry logic."""
    for attempt in range(3):
        try:
            return await hass.async_add_executor_job(
                lambda: UniFiOSClient(
                    host=data[CONF_HOST],
                    username=data.get(CONF_USERNAME),
                    password=data.get(CONF_PASSWORD),
                    port=data.get(CONF_PORT, DEFAULT_PORT),
                    site_id=data.get(CONF_SITE_ID, DEFAULT_SITE),
                    ssl_verify=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                    use_proxy_prefix=data.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
                    timeout=max(data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT), 30),
                ).ping()
            )
        except (ConnectivityError, APIError) as err:
            if attempt == 2:
                raise
            await asyncio.sleep(2 * (attempt + 1))


