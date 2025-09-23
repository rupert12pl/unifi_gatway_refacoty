from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiOSClient, VpnSnapshot

_LOGGER = logging.getLogger(__name__)


KIND_LABELS = {
    "remote_user": "VPN Remote User",
    "s2s_peer": "VPN Site-to-Site",
    "teleport_client": "Teleport Client",
    "teleport_server": "Teleport Server",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities,
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: UniFiOSClient = data["client"]
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]

    manager = VpnEntityManager(
        hass,
        entry,
        client,
        coordinator,
        async_add_entities,
    )
    await manager.async_setup()
    entry.async_on_unload(coordinator.async_add_listener(manager.handle_coordinator_update))


class VpnEntityManager:
    """Manage the lifecycle of VPN connection binary sensors."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: UniFiOSClient,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        async_add_entities,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._client = client
        self._coordinator = coordinator
        self._async_add_entities = async_add_entities
        self._entities: Dict[str, VpnConnectionBinarySensor] = {}

    async def async_setup(self) -> None:
        await self._async_sync()

    def handle_coordinator_update(self) -> None:
        self._hass.async_create_task(self._async_sync())

    async def _async_sync(self) -> None:
        data: Optional[UniFiGatewayData] = self._coordinator.data
        snapshot: Optional[VpnSnapshot] = getattr(data, "vpn_snapshot", None)

        controller_context = self._controller_context(data)

        connections = list(self._iterate_connections(snapshot)) if snapshot else []
        current_unique_ids: set[str] = set()
        new_entities: List[VpnConnectionBinarySensor] = []

        for connection in connections:
            unique_id = self._unique_id(snapshot, connection)
            current_unique_ids.add(unique_id)
            entity = self._entities.get(unique_id)
            if entity is None:
                entity = VpnConnectionBinarySensor(
                    self._coordinator,
                    self._client,
                    self._entry.entry_id,
                    unique_id,
                    connection,
                    snapshot,
                    controller_context,
                )
                self._entities[unique_id] = entity
                new_entities.append(entity)

        stale_ids = [uid for uid in self._entities if uid not in current_unique_ids]
        for uid in stale_ids:
            entity = self._entities.pop(uid)
            await entity.async_remove()
            _LOGGER.debug("Removed VPN connection sensor %s", uid)

        if new_entities:
            names = [entity.name for entity in new_entities]
            _LOGGER.debug(
                "Adding %s VPN connection sensors for entry %s: %s",
                len(new_entities),
                self._entry.entry_id,
                names,
            )
            self._async_add_entities(new_entities)

    def _controller_context(self, data: Optional[UniFiGatewayData]) -> Dict[str, Optional[str]]:
        context: Dict[str, Optional[str]] = {
            "controller_ui": self._client.get_controller_url(),
            "controller_api": self._client.get_controller_api_url(),
            "controller_site": self._client.get_site(),
        }
        controller_info = getattr(data, "controller", None)
        if isinstance(controller_info, dict):
            for key in ("url", "api_url", "site"):
                value = controller_info.get(key)
                if isinstance(value, str) and value:
                    if key == "url":
                        context["controller_ui"] = value
                    elif key == "api_url":
                        context["controller_api"] = value
                    elif key == "site":
                        context["controller_site"] = value
        return context

    def _unique_id(self, snapshot: VpnSnapshot, connection: Dict[str, Any]) -> str:
        site = connection.get("site") or snapshot.site
        kind = connection.get("kind") or "unknown"
        identifier = str(connection.get("id") or connection.get("uuid") or "peer")
        return f"vpn|{self._entry.entry_id}|{site}|{kind}|{identifier}"

    def _iterate_connections(
        self, snapshot: Optional[VpnSnapshot]
    ) -> Iterable[Dict[str, Any]]:
        if not snapshot:
            return []
        for collection in (
            snapshot.remote_users,
            snapshot.s2s_peers,
            snapshot.teleport_servers,
            snapshot.teleport_clients,
        ):
            for record in collection:
                if isinstance(record, dict):
                    yield record


class VpnConnectionBinarySensor(
    CoordinatorEntity[UniFiGatewayDataUpdateCoordinator], BinarySensorEntity
):
    """Binary sensor representing a single VPN connection."""

    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        unique_id: str,
        connection: Dict[str, Any],
        snapshot: VpnSnapshot,
        controller_context: Dict[str, Optional[str]],
    ) -> None:
        super().__init__(coordinator)
        self._client = client
        self._entry_id = entry_id
        self._connection: Dict[str, Any] = dict(connection)
        self._site = connection.get("site") or snapshot.site
        self._kind = connection.get("kind") or "unknown"
        self._family = connection.get("family") or snapshot.family.value
        self._controller_context = dict(controller_context)
        self._attr_unique_id = unique_id
        self._attr_name = self._format_name(connection)
        self._attr_available = True

    def _format_name(self, connection: Dict[str, Any]) -> str:
        label = KIND_LABELS.get(self._kind, "VPN Connection")
        base_name = connection.get("name") or connection.get("id") or "Unknown"
        return f"{label} {base_name}"

    @property
    def is_on(self) -> bool:
        return bool(self._connection.get("connected"))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        attrs: Dict[str, Any] = {
            "kind": self._kind,
            "name": self._connection.get("name"),
            "remote_ip": self._connection.get("remote_ip"),
            "local_ip": self._connection.get("local_ip"),
            "rx_bytes": self._connection.get("rx_bytes"),
            "tx_bytes": self._connection.get("tx_bytes"),
            "phase": self._connection.get("phase"),
            "state": self._connection.get("state"),
            "last_seen": self._connection.get("last_seen"),
            "family": self._connection.get("family") or self._family,
            "site": self._site,
            "controller_url": self._controller_context.get("controller_ui"),
            "controller_api": self._controller_context.get("controller_api"),
        }
        return attrs

    def handle_coordinator_update(self) -> None:
        data: Optional[UniFiGatewayData] = self.coordinator.data
        snapshot: Optional[VpnSnapshot] = getattr(data, "vpn_snapshot", None)
        if snapshot:
            for record in self._iterate_snapshot(snapshot):
                if str(record.get("id")) == str(self._connection.get("id")) and (
                    record.get("kind") == self._kind
                ):
                    self._connection = dict(record)
                    self._family = record.get("family") or self._family
                    self._attr_name = self._format_name(record)
                    self._attr_available = True
                    break
            else:
                self._attr_available = False
        else:
            self._attr_available = False
        super().handle_coordinator_update()

    def _iterate_snapshot(self, snapshot: VpnSnapshot) -> Iterable[Dict[str, Any]]:
        for collection in (
            snapshot.remote_users,
            snapshot.s2s_peers,
            snapshot.teleport_servers,
            snapshot.teleport_clients,
        ):
            for record in collection:
                if isinstance(record, dict):
                    yield record
