
from __future__ import annotations

import hashlib
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
    CONF_VPN_FAMILY_OVERRIDE,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    PLATFORMS,
    VPN_FAMILY_AUTO,
)
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .sensor import (
    _sanitize_stable_key,
    _wan_identifier_candidates,
    build_lan_unique_id,
    build_wan_unique_id,
    build_wlan_unique_id,
)
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

    vpn_family_override = entry.options.get(
        CONF_VPN_FAMILY_OVERRIDE,
        entry.data.get(CONF_VPN_FAMILY_OVERRIDE, VPN_FAMILY_AUTO),
    )
    client_kwargs["vpn_family_override"] = vpn_family_override

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

    await _async_migrate_interface_unique_ids(hass, entry, client, coordinator.data)

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


async def _async_migrate_interface_unique_ids(
    hass: HomeAssistant,
    entry: ConfigEntry,
    client: UniFiOSClient,
    data: UniFiGatewayData | None,
) -> None:
    """Normalize WAN/LAN/WLAN sensor unique IDs."""

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


