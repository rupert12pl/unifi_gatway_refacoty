"""Migration helpers for the UniFi Gateway Dashboard Analyzer integration."""
from __future__ import annotations

import hashlib

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .coordinator import UniFiGatewayData
from .unifi_client import UniFiOSClient
from .utils import build_speedtest_button_unique_id
from .sensor import (
    _wan_identifier_candidates,
    build_lan_unique_id,
    build_wan_unique_id,
    build_wlan_unique_id,
)

_LOGGER = logging.getLogger(__name__)

async def async_migrate_speedtest_button_unique_id(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Ensure the Run Speedtest button unique ID is namespaced per config entry."""
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

async def async_migrate_interface_unique_ids(
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

    # Map WAN interfaces
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

    # Map LAN networks
    for network in data.lan_networks:
        if not isinstance(network, dict):
            continue
        net_id = str(
            network.get("_id") or network.get("id") or network.get("name") or "lan"
        )
        old_uid = f"{instance_prefix}_lan_{net_id}_clients"
        new_uid = build_lan_unique_id(entry.entry_id, network)
        mapping[old_uid] = new_uid

    # Map WLANs
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