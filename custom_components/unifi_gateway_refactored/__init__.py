
from __future__ import annotations

import logging
from functools import partial
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
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
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .sensor import _stable_peer_key, _sanitize_stable_key
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug("Initialized UniFi Gateway integration domain store")
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})
    _LOGGER.debug("Starting setup for UniFi Gateway entry %s", entry.entry_id)

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

    coordinator = UniFiGatewayDataUpdateCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
    }

    _LOGGER.debug(
        "UniFi Gateway entry %s setup complete; scheduling platform forwards",
        entry.entry_id,
    )

    await _async_migrate_vpn_unique_ids(hass, entry, client, coordinator.data)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _LOGGER.info("UniFi Gateway entry %s fully initialized", entry.entry_id)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    _LOGGER.debug("Unloading UniFi Gateway entry %s", entry.entry_id)
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        stored = hass.data.get(DOMAIN)
        if stored and entry.entry_id in stored:
            stored.pop(entry.entry_id)
        _LOGGER.debug("UniFi Gateway entry %s unloaded", entry.entry_id)
    return unload_ok


async def _async_migrate_vpn_unique_ids(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client: UniFiOSClient,
    data: UniFiGatewayData | None,
) -> None:
    """Ensure VPN entity unique IDs include the role/template suffix."""

    mapping: dict[str, str] = {}

    if not data:
        return

    vpn_state = getattr(data, "vpn_state", {}) or {}

    def _map_records(records: list[dict[str, Any]] | None, kind: str, prefix: str) -> None:
        if not records:
            return
        for record in records:
            if not isinstance(record, dict):
                continue
            stable = _stable_peer_key(kind, record)
            old_uid = f"{entry.entry_id}::vpn::{kind}::{stable}"
            peer_id = record.get("id")
            if not isinstance(peer_id, str) or not peer_id:
                peer_id = _sanitize_stable_key(stable)
            new_uid = f"{entry.entry_id}::{prefix}::{peer_id}"
            mapping[old_uid] = new_uid

    _map_records(vpn_state.get("remote_users"), "remote_user", "vpn_remote_user")
    _map_records(vpn_state.get("s2s_peers"), "site_to_site", "vpn_s2s")
    teleport = vpn_state.get("teleport") or {}
    if isinstance(teleport, dict):
        _map_records(teleport.get("clients"), "teleport_client", "vpn_teleport_client")
        _map_records(teleport.get("servers"), "teleport_server", "vpn_teleport_server")

    if not mapping:
        _LOGGER.debug("No VPN unique ID migrations required for entry %s", entry.entry_id)
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
        "Migrated %s VPN entities to new unique IDs for entry %s",
        len(mapping),
        entry.entry_id,
    )
