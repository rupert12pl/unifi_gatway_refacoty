from __future__ import annotations

import hashlib
import logging
import ipaddress
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiOSClient, vpn_peer_identity


_LOGGER = logging.getLogger(__name__)


SUBSYSTEM_SENSORS: Dict[str, tuple[str, str]] = {
    "wan": ("WAN", "mdi:shield-outline"),
    "lan": ("LAN", "mdi:lan"),
    "wlan": ("WLAN", "mdi:wifi"),
    "vpn": ("VPN", "mdi:folder-key-network"),
}


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    _LOGGER.debug(
        "Setting up UniFi Gateway sensors for config entry %s", entry.entry_id
    )
    data = hass.data[DOMAIN][entry.entry_id]
    client: UniFiOSClient = data["client"]
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]

    static_entities: List[SensorEntity] = []
    for subsystem, (label, icon) in SUBSYSTEM_SENSORS.items():
        static_entities.append(
            UniFiGatewaySubsystemSensor(coordinator, client, subsystem, label, icon)
        )
    static_entities.append(UniFiGatewayAlertsSensor(coordinator, client))
    static_entities.append(UniFiGatewayFirmwareSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestDownloadSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestUploadSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestPingSensor(coordinator, client))

    _LOGGER.debug(
        "Adding %s static sensors for entry %s",
        len(static_entities),
        entry.entry_id,
    )
    async_add_entities(static_entities)

    health_entities: Dict[str, HealthSensor] = {}
    vpn_remote_user_entities: Dict[str, VpnRemoteUserSensor] = {}
    vpn_s2s_entities: Dict[str, VpnS2SSensor] = {}
    vpn_diag_entity: Optional[VpnDiagSensor] = None

    def _build_health_entities(
        hass: HomeAssistant,
        entry: ConfigEntry,
        health: Optional[List[Dict[str, Any]]],
    ) -> List[SensorEntity]:
        ent_reg = er.async_get(hass)
        created: List[SensorEntity] = []
        seen: Set[str] = set()
        controller_context = {
            "controller_api": client.get_controller_api_url(),
            "controller_ui": client.get_controller_url(),
            "controller_site": client.get_site(),
        }

        for item in health or []:
            if not isinstance(item, dict):
                continue
            subsystem = str(item.get("subsystem") or "").lower()
            if subsystem not in {"lan", "wan", "wlan", "www"}:
                continue
            uid = f"{entry.entry_id}-health-{subsystem}"
            seen.add(uid)
            entity = health_entities.get(uid)
            if entity is None:
                if ent_reg.async_get_entity_id("sensor", DOMAIN, uid):
                    continue
                entity = HealthSensor(
                    unique_id=uid,
                    name=subsystem.upper(),
                    payload=item,
                    controller_context=controller_context,
                )
                health_entities[uid] = entity
                created.append(entity)
            else:
                entity.set_payload(item, controller_context=controller_context)

        for uid, entity in list(health_entities.items()):
            if uid not in seen:
                entity.mark_stale()

        return created

    def _build_vpn_entities(
        entry: ConfigEntry, data: Dict[str, Any] | UniFiGatewayData | None
    ) -> List[SensorEntity]:
        nonlocal vpn_diag_entity

        ents: List[SensorEntity] = []
        payload: Dict[str, Any]
        controller_site: Optional[str] = None
        if isinstance(data, UniFiGatewayData):
            payload = getattr(data, "vpn", {}) or {}
            controller = getattr(data, "controller", None)
            if isinstance(controller, dict):
                site_candidate = controller.get("site")
                if isinstance(site_candidate, str) and site_candidate:
                    controller_site = site_candidate
        else:
            payload = dict(data or {})
            controller_site = payload.get("site")

        vpn_payload = payload.get("vpn") if isinstance(payload.get("vpn"), dict) else payload
        if not isinstance(vpn_payload, dict):
            vpn_payload = {}
        controller_site = (
            controller_site
            or payload.get("site")
            or vpn_payload.get("site")
            or client.get_site()
            or "default"
        )
        controller_context = {
            "controller_api": client.get_controller_api_url(),
            "controller_ui": client.get_controller_url(),
            "controller_site": controller_site,
        }

        seen_remote: Set[str] = set()
        for user in (vpn_payload.get("remote_users") or []):
            if not isinstance(user, dict):
                continue
            base_key = (
                user.get("id")
                or user.get("_id")
                or user.get("remote_user_id")
                or user.get("uuid")
                or user.get("name")
                or user.get("username")
                or _vpn_peer_id(user)
            )
            fragment = _unique_fragment(base_key)
            if not fragment:
                fragment = hashlib.sha1(
                    repr(sorted(user.items())).encode()
                ).hexdigest()[:12]
            uid = f"{entry.entry_id}-vpn-ru-{fragment}"
            seen_remote.add(uid)
            entity = vpn_remote_user_entities.get(uid)
            display = user.get("name") or user.get("username") or fragment
            if entity is None:
                entity = VpnRemoteUserSensor(
                    unique_id=uid,
                    name=f"VPN User: {display}",
                    site=controller_site,
                    payload=user,
                    controller_context=controller_context,
                )
                vpn_remote_user_entities[uid] = entity
                ents.append(entity)
            else:
                entity.set_payload(
                    user,
                    site=controller_site,
                    controller_context=controller_context,
                )

        for uid, entity in list(vpn_remote_user_entities.items()):
            if uid not in seen_remote:
                entity.mark_stale()

        seen_s2s: Set[str] = set()
        for tun in (vpn_payload.get("site_to_site") or []):
            if not isinstance(tun, dict):
                continue
            base_key = (
                tun.get("peer")
                or tun.get("id")
                or tun.get("_id")
                or tun.get("uuid")
                or tun.get("name")
                or tun.get("remote")
                or _vpn_peer_id(tun)
            )
            fragment = _unique_fragment(base_key)
            if not fragment:
                fragment = hashlib.sha1(
                    repr(sorted(tun.items())).encode()
                ).hexdigest()[:12]
            uid = f"{entry.entry_id}-vpn-s2s-{fragment}"
            seen_s2s.add(uid)
            entity = vpn_s2s_entities.get(uid)
            peer_name = (
                tun.get("peer")
                or tun.get("name")
                or tun.get("remote")
                or tun.get("display_name")
                or fragment
            )
            if entity is None:
                entity = VpnS2SSensor(
                    unique_id=uid,
                    name=f"VPN S2S: {peer_name}",
                    site=controller_site,
                    payload=tun,
                    controller_context=controller_context,
                )
                vpn_s2s_entities[uid] = entity
                ents.append(entity)
            else:
                entity.set_payload(
                    tun,
                    site=controller_site,
                    controller_context=controller_context,
                )

        for uid, entity in list(vpn_s2s_entities.items()):
            if uid not in seen_s2s:
                entity.mark_stale()

        summary = vpn_payload.get("summary") or {}
        diagnostics = vpn_payload.get("diagnostics") or {}
        diag_uid = f"{entry.entry_id}-vpn-summary"
        if vpn_diag_entity is None:
            vpn_diag_entity = VpnDiagSensor(
                unique_id=diag_uid,
                name="VPN diagnostics",
                site=controller_site,
                payload=summary,
                diagnostics=diagnostics,
                vpn_payload=vpn_payload,
                controller_context=controller_context,
            )
            ents.append(vpn_diag_entity)
        else:
            vpn_diag_entity.set_payload(
                summary,
                diagnostics=diagnostics,
                vpn_payload=vpn_payload,
                site=controller_site,
                controller_context=controller_context,
            )

        return ents

    known_wan: set[str] = set()
    known_lan: set[str] = set()
    known_wlan: set[str] = set()
    known_vpn_servers: set[str] = set()
    known_vpn_clients: set[str] = set()
    known_vpn_site_to_site: set[str] = set()

    def _create_dynamic_entity(
        kind: str,
        peer_id: str,
        payload: Dict[str, Any],
        factory: Callable[[], SensorEntity],
    ) -> Optional[SensorEntity]:
        """Safely create a dynamic VPN entity and log failures for debugging."""

        try:
            entity = factory()
        except Exception as err:  # pragma: no cover - defensive guard
            summary_keys = [
                "_id",
                "id",
                "uuid",
                "name",
                "peer_name",
                "description",
                "vpn_name",
                "role",
                "type",
                "vpn_type",
                "interface",
                "server_addr",
                "remote_ip",
            ]
            summary = {
                key: payload.get(key)
                for key in summary_keys
                if key in payload and payload.get(key) not in (None, "", [], {})
            }
            _LOGGER.error(
                "Failed to create %s entity for entry %s (peer_id=%s): %s",
                kind,
                entry.entry_id,
                peer_id or "<missing>",
                err,
            )
            _LOGGER.debug(
                "VPN entity payload for %s (%s): keys=%s summary=%s",
                kind,
                peer_id or "<missing>",
                sorted(payload.keys()),
                summary,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            return None

        return entity

    def _sync_dynamic() -> None:
        _LOGGER.debug(
            "Synchronizing dynamic UniFi Gateway sensors for entry %s",
            entry.entry_id,
        )
        coordinator_data: Optional[UniFiGatewayData] = coordinator.data
        if coordinator_data is None:
            _LOGGER.debug(
                "Coordinator data unavailable during sync for entry %s", entry.entry_id
            )
            return

        new_entities: List[SensorEntity] = []

        controller_site: Optional[str] = None
        controller_info = getattr(coordinator_data, "controller", None)
        if isinstance(controller_info, dict):
            site_candidate = controller_info.get("site")
            if isinstance(site_candidate, str) and site_candidate:
                controller_site = site_candidate

        new_entities.extend(
            _build_health_entities(hass, entry, coordinator_data.health)
        )
        new_entities.extend(_build_vpn_entities(entry, coordinator_data))

        vpn_servers = coordinator_data.vpn_servers
        vpn_clients = coordinator_data.vpn_clients
        vpn_site_to_site = getattr(coordinator_data, "vpn_site_to_site", [])
        vpn_summary = {
            "servers": len(vpn_servers),
            "clients": len(vpn_clients),
            "site_to_site": len(vpn_site_to_site),
        }
        _LOGGER.debug(
            "VPN dataset for entry %s: %s",
            entry.entry_id,
            vpn_summary,
        )
        if not (vpn_servers or vpn_clients or vpn_site_to_site):
            _LOGGER.info(
                "No VPN peers for entry %s; subsystem will show DISABLED. Diagnostics=%s",
                entry.entry_id,
                getattr(coordinator_data, "vpn_diagnostics", None),
            )
        diagnostics = getattr(coordinator_data, "vpn_diagnostics", None)
        if diagnostics:
            _LOGGER.debug(
                "VPN diagnostics for entry %s: %s",
                entry.entry_id,
                diagnostics,
            )

        for link in coordinator_data.wan_links:
            link_id = str(link.get("id"))
            if link_id in known_wan:
                continue
            known_wan.add(link_id)
            new_entities.extend(
                [
                    UniFiGatewayWanStatusSensor(coordinator, client, link),
                    UniFiGatewayWanIpSensor(coordinator, client, link),
                    UniFiGatewayWanIspSensor(coordinator, client, link),
                ]
            )

        for network in coordinator_data.lan_networks:
            net_id = str(network.get("_id") or network.get("id") or network.get("name"))
            if net_id in known_lan:
                continue
            known_lan.add(net_id)
            new_entities.append(
                UniFiGatewayLanClientsSensor(coordinator, client, network)
            )

        for wlan in coordinator_data.wlans:
            ssid = wlan.get("name") or wlan.get("ssid")
            if not ssid:
                continue
            if ssid in known_wlan:
                continue
            known_wlan.add(ssid)
            new_entities.append(UniFiGatewayWlanClientsSensor(coordinator, client, wlan))

        for peer in vpn_servers:
            peer_id = _vpn_peer_id(peer)
            if not peer_id:
                _LOGGER.debug(
                    "Skipping VPN server entity without peer id for entry %s: keys=%s",
                    entry.entry_id,
                    sorted(peer.keys()),
                )
                continue
            if peer_id in known_vpn_servers:
                continue
            entity = _create_dynamic_entity(
                "vpn_server",
                peer_id,
                peer,
                lambda peer=peer: UniFiGatewayVpnServerSensor(
                    coordinator, client, peer
                ),
            )
            if entity:
                known_vpn_servers.add(peer_id)
                _LOGGER.debug(
                    "Discovered VPN server peer %s for entry %s", peer_id, entry.entry_id
                )
                new_entities.append(entity)

        for peer in vpn_clients:
            peer_id = _vpn_peer_id(peer)
            if not peer_id:
                _LOGGER.debug(
                    "Skipping VPN client entity without peer id for entry %s: keys=%s",
                    entry.entry_id,
                    sorted(peer.keys()),
                )
                continue
            if peer_id in known_vpn_clients:
                continue
            entity = _create_dynamic_entity(
                "vpn_client",
                peer_id,
                peer,
                lambda peer=peer: UniFiGatewayVpnClientSensor(
                    coordinator, client, peer
                ),
            )
            if entity:
                known_vpn_clients.add(peer_id)
                _LOGGER.debug(
                    "Discovered VPN client peer %s for entry %s", peer_id, entry.entry_id
                )
                new_entities.append(entity)

        for peer in vpn_site_to_site:
            peer_id = _vpn_peer_id(peer)
            if not peer_id:
                _LOGGER.debug(
                    "Skipping VPN site-to-site entity without peer id for entry %s: keys=%s",
                    entry.entry_id,
                    sorted(peer.keys()),
                )
                continue
            if peer_id in known_vpn_site_to_site:
                continue
            entity = _create_dynamic_entity(
                "vpn_site_to_site",
                peer_id,
                peer,
                lambda peer=peer: UniFiGatewayVpnSiteToSiteSensor(
                    coordinator, client, peer
                ),
            )
            if entity:
                known_vpn_site_to_site.add(peer_id)
                _LOGGER.debug(
                    "Discovered VPN site-to-site peer %s for entry %s",
                    peer_id,
                    entry.entry_id,
                )
                new_entities.append(entity)

        if new_entities:
            names = [
                getattr(entity, "name", entity.__class__.__name__)
                for entity in new_entities
            ]
            _LOGGER.debug(
                "Adding %s dynamic sensors for entry %s: %s",
                len(new_entities),
                entry.entry_id,
                names,
            )
            async_add_entities(new_entities, update_before_add=True)
        else:
            _LOGGER.debug(
                "No new dynamic sensors discovered for entry %s", entry.entry_id
            )

    _sync_dynamic()
    entry.async_on_unload(coordinator.async_add_listener(_sync_dynamic))
    # Ensure the first coordinator refresh runs immediately so peer entities appear
    await coordinator.async_request_refresh()


def _vpn_peer_id(peer: Dict[str, Any]) -> str:
    stored = peer.get("_ha_peer_id")
    if stored not in (None, ""):
        return str(stored)
    return vpn_peer_identity(peer)


def _unique_fragment(value: Any) -> str:
    """Return a sanitized fragment suitable for unique IDs."""

    if value in (None, "", [], {}):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in text)
    cleaned = cleaned.strip("_")
    if cleaned:
        return cleaned.lower()
    return hashlib.sha1(text.encode()).hexdigest()[:12]


def _wan_identifier_candidates(
    link_id: str, link_name: str, link: Dict[str, Any]
) -> set[str]:
    candidates: set[str] = set()

    def _add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, str):
            cleaned = value.strip()
            if not cleaned:
                return
            candidates.add(cleaned.lower())
            candidates.add(cleaned.replace(" ", "").lower())
        else:
            candidates.add(str(value).strip().lower())

    _add(link_id)
    _add(link_name)
    for key in (
        "ifname",
        "interface",
        "wan_port",
        "port",
        "display_name",
        "wan_name",
        "name",
        "id",
    ):
        _add(link.get(key))
    return {value for value in candidates if value}


def _find_wan_health_record(
    data: Optional[UniFiGatewayData], identifiers: set[str]
) -> Optional[Dict[str, Any]]:
    if not data:
        return None
    fallback: Optional[Dict[str, Any]] = None
    for record in data.wan_health:
        if not isinstance(record, dict):
            continue
        if fallback is None:
            fallback = record
        for key in (
            "id",
            "name",
            "ifname",
            "wan_ifname",
            "wan_name",
            "interface",
            "port",
            "link_name",
            "wan_port",
        ):
            value = record.get(key)
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in identifiers or normalized.replace(" ", "") in identifiers:
                    return record
            elif value is not None:
                normalized = str(value).strip().lower()
                if normalized in identifiers:
                    return record
    return fallback


def _value_from_record(record: Optional[Dict[str, Any]], keys: Iterable[str]) -> Optional[Any]:
    if not record:
        return None
    for key in keys:
        if key not in record:
            continue
        value = record.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
        elif value not in (None, [], {}):
            return value
    return None


def _coerce_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return int(float(cleaned))
        except ValueError:
            return None
    return None


def _extract_client_count(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in (
            "connected",
            "active",
            "num_active",
            "num_clients",
            "client_count",
            "connected_clients",
            "value",
            "count",
        ):
            count = _coerce_int(value.get(key))
            if count is not None:
                return count
        return len(value)
    return _coerce_int(value)


def _normalize_vpn_state_token(value: Any) -> Optional[str]:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return "CONNECTED" if value else "DISCONNECTED"
    if isinstance(value, (int, float)):
        return "CONNECTED" if value else "DISCONNECTED"
    if isinstance(value, str):
        token = value.strip().lower()
        if not token:
            return None
        mapping = {
            "connected": "CONNECTED",
            "up": "CONNECTED",
            "online": "CONNECTED",
            "ok": "CONNECTED",
            "ready": "CONNECTED",
            "established": "CONNECTED",
            "active": "CONNECTED",
            "disconnected": "DISCONNECTED",
            "down": "DISCONNECTED",
            "offline": "DISCONNECTED",
            "inactive": "DISCONNECTED",
            "not_connected": "DISCONNECTED",
            "error": "ERROR",
            "failed": "ERROR",
            "fail": "ERROR",
            "critical": "ERROR",
        }
        if token in mapping:
            return mapping[token]
        if any(part in token for part in ("error", "fail", "fault")):
            return "ERROR"
        if any(part in token for part in ("connect", "online", "establish", "up")):
            return "CONNECTED"
        if any(part in token for part in ("discon", "down", "offline", "inactive")):
            return "DISCONNECTED"
        return token.upper()
    return str(value).upper()


def _vpn_peer_client_count(
    record: Dict[str, Any], matches: Iterable[Dict[str, Any]]
) -> Optional[int]:
    count: Optional[int] = None
    for key in (
        "client_count",
        "clients",
        "sessions",
        "active_sessions",
        "connected_clients",
        "users",
        "num_clients",
        "num_users",
    ):
        candidate = _extract_client_count(record.get(key))
        if candidate is not None:
            count = candidate
            break
    match_list = list(matches)
    if match_list:
        count = max(count or 0, len(match_list))
    return count


def _vpn_peer_state(
    record: Dict[str, Any], matches: Iterable[Dict[str, Any]]
) -> Optional[str]:
    for key in (
        "_ha_state",
        "state",
        "status",
        "connection_state",
        "connection_status",
    ):
        state = _normalize_vpn_state_token(record.get(key))
        if state:
            return state

    for key in ("connected", "is_connected", "up", "enabled_state"):
        state = _normalize_vpn_state_token(record.get(key))
        if state:
            return state

    if record.get("error") or record.get("error_code") or record.get("last_error"):
        return "ERROR"

    count = _vpn_peer_client_count(record, matches)
    if count is not None:
        return "CONNECTED" if count > 0 else "DISCONNECTED"

    return None


def _vpn_icon_for_state(state: Optional[str], fallback: Optional[str]) -> Optional[str]:
    normalized = (state or "").upper()
    if normalized == "CONNECTED":
        return "mdi:check-circle"
    if normalized == "ERROR":
        return "mdi:alert-circle-outline"
    if normalized:
        return "mdi:close-circle-outline"
    return fallback


def _normalize_vpn_label(value: Any) -> Optional[str]:
    if value in (None, "", [], {}):
        return None
    cleaned = str(value).strip().lower()
    if not cleaned:
        return None
    if any(ch in cleaned for ch in ".:/"):
        return cleaned
    normalized = "".join(ch for ch in cleaned if ch.isalnum())
    return normalized or None


def _vpn_identifier_candidates(peer: Dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    for key in (
        "_id",
        "id",
        "uuid",
        "peer_uuid",
        "peer_id",
        "peerId",
        "peerID",
        "peerid",
        "server_id",
        "client_id",
        "remote_user_id",
        "remoteuser_id",
        "user_id",
        "userid",
    ):
        value = peer.get(key)
        if value in (None, "", [], {}):
            continue
        identifiers.add(str(value).strip().lower())
    return identifiers


def _vpn_label_candidates(peer: Dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for key in (
        "name",
        "peer_name",
        "description",
        "display_name",
        "vpn_name",
        "remote_user_vpn",
        "profile",
        "profile_name",
        "interface",
        "ifname",
        "gateway",
        "server_addr",
        "server_address",
    ):
        label = _normalize_vpn_label(peer.get(key))
        if label:
            labels.add(label)
    return labels


def _vpn_network_strings(value: Any) -> List[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        raw = value.replace(";", ",").replace("|", ",")
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if len(parts) == 1:
            # also attempt to split on whitespace for strings like "10.0.0.0/24 10.0.1.0/24"
            parts = [part.strip() for part in raw.split() if part.strip()]
        return parts
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            out.extend(_vpn_network_strings(item))
        return out
    if isinstance(value, dict):
        out: List[str] = []
        for item in value.values():
            out.extend(_vpn_network_strings(item))
        return out
    return [str(value)]


def _vpn_networks(
    peer: Dict[str, Any],
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[str] = set()
    for key in (
        "tunnel_network",
        "tunnel_networks",
        "client_subnet",
        "client_networks",
        "subnet",
        "subnets",
        "network",
        "networks",
        "allowed_ips",
    ):
        for candidate in _vpn_network_strings(peer.get(key)):
            if candidate in seen:
                continue
            seen.add(candidate)
            network = _to_ip_network(candidate)
            if network:
                networks.append(network)
    return networks


def _vpn_client_identifier_candidates(client: Dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    for key in (
        "peer_id",
        "peerid",
        "remote_user_id",
        "remoteuser_id",
        "user_id",
        "userid",
        "server_id",
        "client_id",
        "id",
        "_id",
        "uuid",
    ):
        value = client.get(key)
        if value in (None, "", [], {}):
            continue
        identifiers.add(str(value).strip().lower())
    return identifiers


def _vpn_client_labels(client: Dict[str, Any]) -> set[str]:
    labels: set[str] = set()
    for key in (
        "vpn_name",
        "remote_user_vpn",
        "tunnel",
        "gateway",
        "via_vpn",
        "network",
        "profile",
        "profile_name",
        "connection_name",
        "remote_user",
        "remoteuser",
    ):
        label = _normalize_vpn_label(client.get(key))
        if label:
            labels.add(label)
    connection = client.get("connection") or client.get("connectivity") or client.get("type")
    if isinstance(connection, str) and "vpn" in connection.lower():
        label = _normalize_vpn_label(connection)
        if label:
            labels.add(label)
    return labels


def _client_ip_addresses(client: Dict[str, Any]) -> List[str]:
    ips: List[str] = []
    for key in (
        "ip",
        "last_known_ip",
        "wan_ip",
        "remote_ip",
        "vpn_ip",
        "tunnel_ip",
    ):
        value = client.get(key)
        if isinstance(value, str) and value:
            ips.append(value)
    return ips


def _match_clients_for_peer(
    peer: Dict[str, Any],
    base_identifiers: set[str],
    base_labels: set[str],
    base_networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
    clients: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    identifiers = set(base_identifiers)
    identifiers.update(_vpn_identifier_candidates(peer))
    labels = set(base_labels)
    labels.update(_vpn_label_candidates(peer))
    networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = list(
        base_networks
    )
    existing: set[str] = {str(net) for net in networks}
    for network in _vpn_networks(peer):
        key = str(network)
        if key in existing:
            continue
        existing.add(key)
        networks.append(network)

    matches: List[Dict[str, Any]] = []
    for client in clients:
        client_ids = _vpn_client_identifier_candidates(client)
        if identifiers.intersection(client_ids):
            matches.append(client)
            continue
        client_labels = _vpn_client_labels(client)
        if client_labels and labels:
            for candidate in client_labels:
                if any(
                    candidate == label
                    or candidate in label
                    or label in candidate
                    for label in labels
                ):
                    matches.append(client)
                    break
            else:
                pass
            if client in matches:
                continue
        if networks:
            for ip_value in _client_ip_addresses(client):
                try:
                    address = ipaddress.ip_address(ip_value)
                except ValueError:
                    continue
                if any(address in network for network in networks):
                    matches.append(client)
                    break
    return matches


class _GatewayDynamicSensor(SensorEntity):
    """Base helper for dynamically created sensors that manage their payload."""

    _attr_should_poll = False

    def __init__(
        self,
        unique_id: str,
        name: str,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._attr_unique_id = unique_id
        self._attr_name = name
        self._attr_available = False
        self._state: Optional[Any] = None
        self._attrs: Dict[str, Any] = {}
        self._payload: Dict[str, Any] = {}
        self._controller_context: Dict[str, Any] = {}
        if controller_context:
            self.update_context(controller_context)
        self._default_icon = getattr(self, "_attr_icon", None)

    def update_context(self, context: Optional[Dict[str, Any]]) -> None:
        if not context:
            return
        for key, value in context.items():
            if value in (None, "", [], {}):
                continue
            self._controller_context[key] = value

    @property
    def native_value(self) -> Optional[Any]:
        return self._state

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        attrs = dict(self._controller_context)
        attrs.update(self._attrs)
        return attrs

    @property
    def payload(self) -> Dict[str, Any]:
        return self._payload

    def _async_write_state(self) -> None:
        if self.hass:
            self.async_write_ha_state()

    def mark_stale(self) -> None:
        self._payload = {}
        self._state = None
        self._attrs = {}
        self._attr_available = False
        self._async_write_state()


class HealthSensor(_GatewayDynamicSensor):
    """Sensor exposing controller health per subsystem."""

    def __init__(
        self,
        unique_id: str,
        name: str,
        payload: Dict[str, Any],
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(unique_id, name, controller_context)
        self._subsystem = name.lower()
        self.set_payload(payload, controller_context=controller_context)

    def set_payload(
        self,
        payload: Optional[Dict[str, Any]],
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if controller_context:
            self.update_context(controller_context)
        self._payload = dict(payload or {})
        if self._payload.get("subsystem"):
            self._subsystem = str(self._payload.get("subsystem")).lower()
        self._attr_available = bool(payload)
        status = self._payload.get("status") or self._payload.get("state")
        if isinstance(status, str):
            cleaned = status.strip()
            self._state = cleaned.upper() if cleaned else None
        else:
            self._state = status
        attrs = {
            key: value for key, value in self._payload.items() if key != "subsystem"
        }
        attrs["subsystem"] = self._payload.get("subsystem") or self._subsystem
        self._attrs = attrs
        self._async_write_state()

    def mark_stale(self) -> None:  # type: ignore[override]
        self._payload = {}
        self._attr_available = False
        self._state = None
        self._attrs = {"subsystem": self._subsystem}
        self._async_write_state()

    @property
    def icon(self) -> Optional[str]:
        status = str(self._state or "").lower()
        if status in {"ok", "online", "up", "healthy", "connected"}:
            return "mdi:check-circle"
        if status in {"warning", "notice", "degraded", "partial"}:
            return "mdi:alert"
        if status in {"error", "critical", "down", "offline", "disconnected"}:
            return "mdi:alert-circle"
        if status in {"disabled", "not_configured", "notconfigured"}:
            return "mdi:power-plug-off"
        return self._default_icon


class VpnRemoteUserSensor(_GatewayDynamicSensor):
    """Sensor describing VPN remote user sessions."""

    _attr_icon = "mdi:account-lock-outline"

    def __init__(
        self,
        unique_id: str,
        name: str,
        site: str,
        payload: Dict[str, Any],
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(unique_id, name, controller_context)
        self._site = site
        self.set_payload(payload, site=site, controller_context=controller_context)

    def set_payload(
        self,
        payload: Optional[Dict[str, Any]],
        *,
        site: Optional[str] = None,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if site:
            self._site = site
        if controller_context:
            self.update_context(controller_context)
        self._payload = dict(payload or {})
        self._attr_available = bool(payload)
        state = _vpn_peer_state(self._payload, []) if self._payload else None
        if isinstance(state, str):
            self._state = state.upper()
        else:
            self._state = state
        client_count = _vpn_peer_client_count(self._payload, []) if payload else None
        attrs: Dict[str, Any] = {
            "site": self._site,
            "state": self._state,
        }
        for key in (
            "name",
            "username",
            "ip",
            "remote_ip",
            "tunnel_ip",
            "mac",
            "profile",
            "vpn_type",
            "role",
            "server_addr",
            "server",
            "connection_name",
            "connected_at",
            "last_connected",
            "last_state_change",
        ):
            value = self._payload.get(key)
            if value not in (None, "", [], {}):
                attrs[key] = value
        if client_count is not None:
            attrs["client_count"] = client_count
        errors = self._payload.get("errors") or self._payload.get("error")
        if errors not in (None, "", [], {}):
            attrs["errors"] = errors
        if self._payload:
            attrs["raw"] = self._payload
        self._attrs = attrs
        self._async_write_state()

    def mark_stale(self) -> None:  # type: ignore[override]
        self._payload = {}
        self._state = None
        self._attr_available = False
        self._attrs = {"site": self._site}
        self._async_write_state()

    @property
    def icon(self) -> Optional[str]:
        return _vpn_icon_for_state(self._state, self._default_icon)


class VpnS2SSensor(_GatewayDynamicSensor):
    """Sensor describing VPN site-to-site tunnels."""

    _attr_icon = "mdi:lan-lock"

    def __init__(
        self,
        unique_id: str,
        name: str,
        site: str,
        payload: Dict[str, Any],
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(unique_id, name, controller_context)
        self._site = site
        self.set_payload(payload, site=site, controller_context=controller_context)

    def set_payload(
        self,
        payload: Optional[Dict[str, Any]],
        *,
        site: Optional[str] = None,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if site:
            self._site = site
        if controller_context:
            self.update_context(controller_context)
        self._payload = dict(payload or {})
        self._attr_available = bool(payload)
        state = _vpn_peer_state(self._payload, []) if self._payload else None
        if isinstance(state, str):
            self._state = state.upper()
        else:
            self._state = state
        attrs: Dict[str, Any] = {
            "site": self._site,
            "state": self._state,
        }
        for key in (
            "peer",
            "name",
            "remote",
            "description",
            "vpn_type",
            "interface",
            "ifname",
            "remote_ip",
            "remote_host",
            "public_ip",
            "tunnel_ip",
            "tunnel_subnet",
            "client_subnet",
            "gateway",
            "last_state_change",
        ):
            value = self._payload.get(key)
            if value not in (None, "", [], {}):
                attrs[key] = value
        count = _vpn_peer_client_count(self._payload, []) if payload else None
        if count is not None:
            attrs["client_count"] = count
        if self._payload:
            attrs["raw"] = self._payload
        self._attrs = attrs
        self._async_write_state()

    def mark_stale(self) -> None:  # type: ignore[override]
        self._payload = {}
        self._state = None
        self._attr_available = False
        self._attrs = {"site": self._site}
        self._async_write_state()

    @property
    def icon(self) -> Optional[str]:
        return _vpn_icon_for_state(self._state, self._default_icon)


class VpnDiagSensor(_GatewayDynamicSensor):
    """Aggregated VPN diagnostics sensor."""

    _attr_icon = "mdi:shield-search"

    def __init__(
        self,
        unique_id: str,
        name: str,
        site: str,
        payload: Dict[str, Any],
        diagnostics: Optional[Dict[str, Any]] = None,
        vpn_payload: Optional[Dict[str, Any]] = None,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(unique_id, name, controller_context)
        self._site = site
        self.set_payload(
            payload,
            diagnostics=diagnostics,
            vpn_payload=vpn_payload,
            site=site,
            controller_context=controller_context,
        )

    def set_payload(
        self,
        summary: Optional[Dict[str, Any]],
        *,
        diagnostics: Optional[Dict[str, Any]] = None,
        vpn_payload: Optional[Dict[str, Any]] = None,
        site: Optional[str] = None,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if site:
            self._site = site
        if controller_context:
            self.update_context(controller_context)
        summary_payload = dict(summary or {})
        self._payload = summary_payload
        diagnostics_payload = dict(diagnostics or {})
        counts = diagnostics_payload.get("counts")
        if not isinstance(counts, dict):
            counts = {}
        vpn_payload = dict(vpn_payload or {})
        derived_counts = {
            "servers": len(vpn_payload.get("servers") or []),
            "clients": len(vpn_payload.get("clients") or []),
            "remote_users": len(vpn_payload.get("remote_users") or []),
            "site_to_site": len(vpn_payload.get("site_to_site") or []),
        }
        counts.update({k: v for k, v in derived_counts.items() if k not in counts})
        diagnostics_payload["counts"] = counts

        status: Optional[str] = None
        for source in (summary_payload, diagnostics_payload):
            if not isinstance(source, dict):
                continue
            for key in ("status", "state", "result", "outcome", "health"):
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    status = value.strip().upper()
                    break
            if status:
                break
        if not status:
            healthy = summary_payload.get("healthy")
            if isinstance(healthy, bool):
                status = "OK" if healthy else "ERROR"
        self._state = status or "UNKNOWN"
        self._attr_available = bool(summary_payload or diagnostics_payload or vpn_payload)

        attrs: Dict[str, Any] = {
            "site": self._site,
            "summary": summary_payload,
            "diagnostics": diagnostics_payload,
            "counts": counts,
        }
        fetch_errors = diagnostics_payload.get("fetch_errors")
        if fetch_errors not in (None, "", [], {}):
            attrs["fetch_errors"] = fetch_errors
        if vpn_payload:
            attrs["remote_users"] = vpn_payload.get("remote_users")
            attrs["site_to_site"] = vpn_payload.get("site_to_site")
            attrs["servers"] = vpn_payload.get("servers")
            attrs["clients"] = vpn_payload.get("clients")
        self._attrs = attrs
        self._async_write_state()

    def mark_stale(self) -> None:  # type: ignore[override]
        self._payload = {}
        self._state = None
        self._attr_available = False
        self._attrs = {"site": self._site}
        self._async_write_state()

    @property
    def icon(self) -> Optional[str]:
        status = str(self._state or "").upper()
        if status in {"OK", "ONLINE", "CONNECTED", "HEALTHY"}:
            return "mdi:shield-check"
        if status in {"ERROR", "FAILED", "CRITICAL"}:
            return "mdi:shield-alert"
        if status in {"WARNING", "WARN", "NOTICE"}:
            return "mdi:shield-alert-outline"
        return self._default_icon


class UniFiGatewaySensorBase(
    CoordinatorEntity[UniFiGatewayDataUpdateCoordinator], SensorEntity
):
    """Base entity for UniFi Gateway sensors."""

    _attr_should_poll = False

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        unique_id: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self._client = client
        self._attr_unique_id = unique_id
        self._attr_name = name
        self._default_icon = getattr(self, "_attr_icon", None)

    def _controller_attrs(self) -> Dict[str, Any]:
        data = self.coordinator.data
        if not data:
            return {}
        return {
            "controller_ui": data.controller.get("url"),
            "controller_api": data.controller.get("api_url"),
            "controller_site": data.controller.get("site"),
        }


class UniFiGatewayWanSensorBase(UniFiGatewaySensorBase):
    """Common logic for WAN-related sensors."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
        suffix: str,
        name_suffix: str = "",
    ) -> None:
        self._link_id = str(link.get("id"))
        self._link_name = link.get("name") or self._link_id
        self._identifiers = _wan_identifier_candidates(
            self._link_id, self._link_name, link
        )
        canonical = (sorted(self._identifiers) or [self._link_id])[0]
        self._uid_source = canonical
        self._uid_key = hashlib.sha1(canonical.encode()).hexdigest()[:12]
        unique_id = f"unifigw_{client.instance_key()}_wan_{self._uid_key}_{suffix}"
        super().__init__(
            coordinator, client, unique_id, f"WAN {self._link_name}{name_suffix}"
        )

    def _link(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for link in data.wan_links:
            if str(link.get("id")) == self._link_id:
                return link
        return None


class UniFiGatewaySubsystemSensor(UniFiGatewaySensorBase):
    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        subsystem: str,
        label: str,
        icon: str,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_{subsystem}"
        super().__init__(coordinator, client, unique_id, label)
        self._subsystem = subsystem
        self._attr_icon = icon
        self._default_icon = icon

    @property
    def native_value(self) -> Optional[Any]:
        data = self.coordinator.data
        if not data:
            return None
        record = data.health_by_subsystem.get(self._subsystem)
        if not record:
            return None
        status = record.get("status") or record.get("state")
        if isinstance(status, str):
            normalized = status.strip().lower()
            if normalized == "error" and self._subsystem == "vpn":
                if self._vpn_disabled(record, data):
                    return "DISABLED"
            return status.upper()
        return status

    @property
    def icon(self) -> Optional[str]:
        status = str(self.native_value or "").lower()
        if status in {"ok", "online", "up", "healthy", "connected"}:
            return "mdi:check-circle"
        if status in {"warning", "notice", "degraded"}:
            return "mdi:alert"
        if status in {"error", "critical", "down", "offline", "disconnected"}:
            return "mdi:alert-circle"
        if status in {"disabled", "not_configured", "notconfigured"}:
            return "mdi:power-plug-off"
        return self._default_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        record = data.health_by_subsystem.get(self._subsystem) if data else None
        attrs: Dict[str, Any] = {}
        if record:
            attrs.update({k: v for k, v in record.items() if k != "subsystem"})
            total = 0
            total_found = False
            for key in ("num_user", "num_guest", "num_iot", "num_it"):
                count = _coerce_int(record.get(key))
                if count is None:
                    continue
                total += count
                total_found = True
            if total_found:
                attrs["num_user_total"] = total
        if (
            self._subsystem == "vpn"
            and data
            and getattr(data, "vpn_diagnostics", None)
        ):
            attrs["vpn_diagnostics"] = data.vpn_diagnostics
        attrs.update(self._controller_attrs())
        return attrs

    def _vpn_disabled(
        self, record: Dict[str, Any], data: UniFiGatewayData
    ) -> bool:
        """Determine if VPN subsystem is simply disabled/unconfigured."""

        details: list[str] = []
        for key in (
            "status_reason",
            "status_message",
            "status_detail",
            "status_info",
            "reason",
            "msg",
        ):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                details.append(value.strip().lower())

        if details:
            combined = " ".join(details)
            for hint in (
                "not configured",
                "not available",
                "not supported",
                "not provisioned",
                "disabled",
                "no vpn",
                "teleport disabled",
            ):
                if hint in combined:
                    return True

        if record.get("vpn_status") in {"disabled", "off"}:
            return True

        if not (
            data.vpn_servers
            or data.vpn_clients
            or getattr(data, "vpn_site_to_site", [])
        ):
            return True

        return False


class UniFiGatewayAlertsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:information-outline"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_alerts"
        super().__init__(coordinator, client, unique_id, "Alerts")

    @property
    def native_value(self) -> Optional[int]:
        data = self.coordinator.data
        if not data:
            return None
        return len(data.alerts)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        attrs = {"alerts": data.alerts if data else []}
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayFirmwareSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:database-plus"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_firmware"
        super().__init__(coordinator, client, unique_id, "Firmware Upgradable")

    @property
    def native_value(self) -> Optional[int]:
        data = self.coordinator.data
        if not data:
            return None
        return len([dev for dev in data.devices if dev.get("upgradable")])

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        upgradable = [
            {
                "name": dev.get("name") or dev.get("mac"),
                "model": dev.get("model"),
                "version": dev.get("version"),
            }
            for dev in (data.devices if data else [])
            if dev.get("upgradable")
        ]
        attrs = {"devices": upgradable}
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanStatusSensor(UniFiGatewayWanSensorBase):
    _attr_icon = "mdi:shield-outline"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, link, "status")
        self._default_icon = getattr(self, "_attr_icon", None)

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @property
    def native_value(self) -> Optional[Any]:
        link = self._link()
        if not link:
            return None
        status = link.get("status") or link.get("state")
        if isinstance(status, str):
            return status.upper()
        return status

    @property
    def icon(self) -> Optional[str]:
        status = str(self.native_value or "").lower()
        if status in {"up", "ok", "connected", "online"}:
            return "mdi:check-circle"
        if status in {"down", "error", "fail", "disconnected", "offline"}:
            return "mdi:alert-circle"
        return self._default_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link() or {}
        health = self._wan_health_record() or {}
        attrs = {
            "name": self._link_name,
            "type": link.get("type") or link.get("kind"),
            "isp": _value_from_record(
                link,
                ("isp", "provider", "isp_name", "organization"),
            ),
            "ip": _value_from_record(
                link,
                ("ip", "wan_ip", "ipv4", "internet_ip"),
            ),
        }
        if not attrs.get("isp"):
            attrs["isp"] = _value_from_record(
                health,
                (
                    "isp",
                    "provider",
                    "isp_name",
                    "service_provider",
                    "organization",
                ),
            )
        if not attrs.get("ip"):
            attrs["ip"] = _value_from_record(
                health,
                ("wan_ip", "internet_ip", "ip", "public_ip", "external_ip"),
            )
        attrs["gateway_ip"] = _value_from_record(
            health,
            ("gateway_ip", "wan_gateway", "gw_ip", "gateway"),
        )
        attrs["last_update"] = _value_from_record(
            health,
            ("datetime", "time", "last_seen", "last_update", "updated_at"),
        )
        attrs["uptime"] = _value_from_record(
            health,
            ("uptime", "uptime_status", "wan_uptime", "uptime_seconds"),
        )
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIpSensor(UniFiGatewayWanSensorBase):
    _attr_icon = "mdi:ip"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, link, "ip", " IP")
        self._last_ip: Optional[str] = None
        self._last_source: Optional[str] = None

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @property
    def native_value(self) -> Optional[str]:
        ip = None
        source: Optional[str] = None
        link = self._link()
        if link:
            ip = _value_from_record(
                link,
                ("ip", "wan_ip", "ipv4", "internet_ip", "public_ip", "external_ip"),
            )
            if ip:
                source = "link"
        if not ip:
            health = self._wan_health_record()
            ip = _value_from_record(
                health,
                ("wan_ip", "internet_ip", "ip", "public_ip", "external_ip"),
            )
            if ip:
                source = "wan_health"
        if ip:
            self._last_ip = ip
            self._last_source = source or "unknown"
            return ip
        if self._last_ip:
            if not self._last_source:
                self._last_source = "cached"
            return self._last_ip
        return None

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        health = self._wan_health_record() or {}
        attrs = {
            "last_ip": self._last_ip,
            "source": self._last_source or ("cached" if self._last_ip else None),
            "gateway_ip": _value_from_record(
                health, ("gateway_ip", "wan_gateway", "gw_ip", "gateway")
            ),
            "subnet": _value_from_record(
                health,
                (
                    "wan_ip_subnet",
                    "wan_subnet",
                    "subnet",
                    "network",
                    "tunnel_network",
                ),
            ),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIspSensor(UniFiGatewayWanSensorBase):
    _attr_icon = "mdi:domain"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, link, "isp", " ISP")
        self._last_isp: Optional[str] = None
        self._last_source: Optional[str] = None

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @property
    def native_value(self) -> Optional[str]:
        isp = None
        source: Optional[str] = None
        link = self._link()
        if link:
            isp = _value_from_record(
                link,
                ("isp", "provider", "isp_name", "service_provider", "organization"),
            )
            if isp:
                source = "link"
        if not isp:
            health = self._wan_health_record()
            isp = _value_from_record(
                health,
                ("isp", "provider", "isp_name", "service_provider", "organization"),
            )
            if isp:
                source = "wan_health"
        if isp:
            self._last_isp = isp
            self._last_source = source or "unknown"
            return isp
        if self._last_isp:
            if not self._last_source:
                self._last_source = "cached"
            return self._last_isp
        return None

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link() or {}
        health = self._wan_health_record() or {}
        attrs = {
            "last_isp": self._last_isp,
            "source": self._last_source or ("cached" if self._last_isp else None),
            "organization": _value_from_record(
                link,
                (
                    "isp_name",
                    "isp_organization",
                    "organization",
                    "service_provider",
                ),
            )
            or _value_from_record(
                health,
                (
                    "isp_name",
                    "isp_organization",
                    "organization",
                    "service_provider",
                ),
            ),
            "contact": _value_from_record(
                health,
                ("support_contact", "support_phone", "support_email"),
            ),
            "country": _value_from_record(
                health,
                ("country", "country_code", "region"),
            ),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayLanClientsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        network: Dict[str, Any],
    ) -> None:
        self._network = network
        self._network_id = str(network.get("_id") or network.get("id") or network.get("name"))
        self._network_name = network.get("name") or f"VLAN {network.get('vlan')}"
        self._subnet = (
            network.get("subnet")
            or network.get("ip_subnet")
            or network.get("cidr")
        )
        self._ip_network = _to_ip_network(self._subnet)
        unique_id = (
            f"unifigw_{client.instance_key()}_lan_{self._network_id}_clients"
        )
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"LAN {self._network_name}",
        )

    def _matches_client(self, client: Dict[str, Any]) -> bool:
        if str(client.get("network_id")) == self._network_id:
            return True
        if (
            client.get("network")
            and client.get("network").lower() == self._network_name.lower()
        ):
            return True
        if self._ip_network and client.get("ip"):
            try:
                if ipaddress.ip_address(client["ip"]) in self._ip_network:
                    return True
            except ValueError:
                return False
        return False

    def _clients(self) -> Iterable[Dict[str, Any]]:
        data = self.coordinator.data
        return data.clients if data else []

    @property
    def native_value(self) -> Optional[int]:
        return sum(1 for client in self._clients() if self._matches_client(client))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        leases = sum(
            1
            for client in self._clients()
            if self._matches_client(client) and client.get("ip")
        )
        attrs = {
            "network_id": self._network_id,
            "subnet": self._subnet,
            "vlan_id": self._network.get("vlan"),
            "ip_leases": leases,
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWlanClientsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:wifi"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        wlan: Dict[str, Any],
    ) -> None:
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        unique_id = f"unifigw_{client.instance_key()}_wlan_{self._ssid}_clients"
        super().__init__(coordinator, client, unique_id, f"WLAN {self._ssid}")

    def _clients(self) -> Iterable[Dict[str, Any]]:
        data = self.coordinator.data
        return data.clients if data else []

    @property
    def native_value(self) -> Optional[int]:
        count = 0
        for client in self._clients():
            ssid = (
                client.get("essid")
                or client.get("wifi_network")
                or client.get("ap_essid")
            )
            if ssid == self._ssid:
                count += 1
        return count

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        net_id = self._wlan.get("networkconf_id")
        netmap = data.network_map if data else {}
        network = netmap.get(str(net_id)) if net_id else None
        attrs = {
            "network": network.get("name") if network else self._wlan.get("network"),
            "vlan_id": network.get("vlan") if network else None,
            "security": self._wlan.get("security")
            or self._wlan.get("x_security")
            or self._wlan.get("wpa_mode"),
            "enabled": self._wlan.get("enabled", True),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayVpnServerSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:account-lock"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        peer: Dict[str, Any],
    ) -> None:
        self._peer_name = (
            peer.get("name")
            or peer.get("peer_name")
            or peer.get("description")
            or peer.get("display_name")
        )
        self._peer_id = _vpn_peer_id(peer)
        display_name = self._peer_name or str(self._peer_id)
        self._base_identifiers = _vpn_identifier_candidates(peer)
        if self._peer_id:
            self._base_identifiers.add(str(self._peer_id).lower())
        self._base_labels = _vpn_label_candidates(peer)
        self._base_networks = tuple(_vpn_networks(peer))
        unique_id = f"unifigw_{client.instance_key()}_vpn_server_{self._peer_id}"
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"VPN Server {display_name}",
        )

    def _record(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for record in data.vpn_servers:
            if _vpn_peer_id(record) == self._peer_id:
                return record
        return None

    @property
    def native_value(self) -> Optional[str]:
        record = self._record()
        if not record:
            return None
        matches = self._matched_clients(record)
        state = _vpn_peer_state(record, matches)
        if state:
            return state
        return "DISCONNECTED"

    @property
    def icon(self) -> Optional[str]:
        return _vpn_icon_for_state(self.native_value, self._default_icon)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        record = self._record() or {}
        matches = self._matched_clients(record)
        clients = record.get("clients")
        client_count = _vpn_peer_client_count(record, matches) or 0
        state = self.native_value
        attrs = {
            "role": record.get("_ha_role") or "server",
            "category": record.get("_ha_category"),
            "template": record.get("template")
            or record.get("_ha_template")
            or record.get("profile"),
            "vpn_name": record.get("vpn_name")
            or record.get("name")
            or record.get("peer_name"),
            "vpn_type": record.get("vpn_type") or record.get("type"),
            "interface": record.get("interface") or record.get("ifname"),
            "public_ip": record.get("public_ip")
            or record.get("gateway")
            or record.get("wan_ip"),
            "tunnel_subnet": record.get("tunnel_subnet")
            or record.get("tunnel_network")
            or record.get("client_subnet")
            or record.get("subnet"),
            "local_ip": record.get("local_ip") or record.get("server_ip"),
            "gateway_ip": record.get("gateway_ip")
            or record.get("server_addr")
            or record.get("public_ip"),
            "port": record.get("port")
            or record.get("listen_port")
            or record.get("server_port"),
            "client_count": client_count,
            "status": record.get("status") or record.get("state"),
            "state": state,
            "last_state_change": record.get("last_state_change"),
            "rx_bytes": _coerce_int(record.get("rx_bytes")),
            "tx_bytes": _coerce_int(record.get("tx_bytes")),
        }
        if isinstance(clients, (list, dict)):
            attrs["clients"] = clients
        if matches:
            attrs["matched_clients"] = [
                {
                    "name": client.get("name")
                    or client.get("hostname")
                    or client.get("user")
                    or client.get("mac"),
                    "ip": client.get("ip") or client.get("last_known_ip"),
                    "mac": client.get("mac"),
                }
                for client in matches
            ]
            attrs["client_count"] = max(client_count, len(matches))
        attrs.update(self._controller_attrs())
        return attrs

    def _matched_clients(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = self.coordinator.data
        clients = data.clients if data else []
        return _match_clients_for_peer(
            record,
            self._base_identifiers,
            self._base_labels,
            self._base_networks,
            clients,
        )


class UniFiGatewayVpnClientSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:lock"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        peer: Dict[str, Any],
    ) -> None:
        self._peer_id = _vpn_peer_id(peer)
        self._peer_name = (
            peer.get("name")
            or peer.get("peer_name")
            or peer.get("description")
            or peer.get("display_name")
        )
        display_name = self._peer_name or str(self._peer_id)
        self._base_identifiers = _vpn_identifier_candidates(peer)
        if self._peer_id:
            self._base_identifiers.add(str(self._peer_id).lower())
        self._base_labels = _vpn_label_candidates(peer)
        self._base_networks = tuple(_vpn_networks(peer))
        unique_id = f"unifigw_{client.instance_key()}_vpn_client_{self._peer_id}"
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"VPN Client {display_name}",
        )

    def _record(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for record in data.vpn_clients:
            if _vpn_peer_id(record) == self._peer_id:
                return record
        return None

    @property
    def native_value(self) -> Optional[str]:
        record = self._record()
        if not record:
            matches = self._matched_clients({})
            if matches:
                return "CONNECTED"
            return None
        matches = self._matched_clients(record)
        state = _vpn_peer_state(record, matches)
        if state:
            return state
        if matches:
            return "CONNECTED"
        return "DISCONNECTED"

    @property
    def icon(self) -> Optional[str]:
        return _vpn_icon_for_state(self.native_value, self._default_icon)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        record = self._record() or {}
        matches = self._matched_clients(record)
        client_count = _vpn_peer_client_count(record, matches) or 0
        state = self.native_value
        attrs = {
            "role": record.get("_ha_role") or "client",
            "category": record.get("_ha_category"),
            "template": record.get("template")
            or record.get("_ha_template")
            or record.get("profile"),
            "vpn_name": record.get("vpn_name")
            or record.get("name")
            or record.get("peer_name"),
            "vpn_type": record.get("vpn_type") or record.get("type"),
            "interface": record.get("interface") or record.get("ifname"),
            "public_ip": record.get("public_ip")
            or record.get("gateway")
            or record.get("server_addr"),
            "tunnel_subnet": record.get("tunnel_subnet")
            or record.get("tunnel_network")
            or record.get("client_subnet")
            or record.get("subnet"),
            "server_addr": record.get("server_addr")
            or record.get("server_address")
            or record.get("gateway"),
            "server_address": record.get("server_addr")
            or record.get("server_address")
            or record.get("gateway"),
            "remote_ip": record.get("remote_ip"),
            "peer_addr": record.get("peer_addr"),
            "tunnel_ip": record.get("tunnel_ip") or record.get("local_ip"),
            "port": record.get("port")
            or record.get("server_port")
            or record.get("remote_port"),
            "client_count": client_count,
            "status": record.get("status") or record.get("state"),
            "state": state,
            "last_state_change": record.get("last_state_change"),
            "rx_bytes": _coerce_int(record.get("rx_bytes")),
            "tx_bytes": _coerce_int(record.get("tx_bytes")),
        }
        for key in ("subnet", "tunnel_network", "client_subnet"):
            if record.get(key):
                attrs["subnet"] = record.get(key)
                break
        clients = record.get("clients")
        if isinstance(clients, (list, dict)):
            attrs["clients"] = clients
        if matches:
            attrs["matched_clients"] = [
                {
                    "name": client.get("name")
                    or client.get("hostname")
                    or client.get("user")
                    or client.get("mac"),
                    "ip": client.get("ip") or client.get("last_known_ip"),
                    "mac": client.get("mac"),
                }
                for client in matches
            ]
            attrs["client_count"] = max(client_count, len(matches))
        attrs.update(self._controller_attrs())
        return attrs

    def _matched_clients(self, record: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = self.coordinator.data
        clients = data.clients if data else []
        return _match_clients_for_peer(
            record,
            self._base_identifiers,
            self._base_labels,
            self._base_networks,
            clients,
        )


class UniFiGatewayVpnSiteToSiteSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:lan-connect"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        peer: Dict[str, Any],
    ) -> None:
        self._peer_id = _vpn_peer_id(peer)
        self._peer_name = (
            peer.get("name")
            or peer.get("peer_name")
            or peer.get("description")
            or peer.get("display_name")
        )
        display_name = self._peer_name or str(self._peer_id)
        self._base_identifiers = _vpn_identifier_candidates(peer)
        if self._peer_id:
            self._base_identifiers.add(str(self._peer_id).lower())
        self._base_labels = _vpn_label_candidates(peer)
        self._base_networks = tuple(_vpn_networks(peer))
        unique_id = f"unifigw_{client.instance_key()}_vpn_site_to_site_{self._peer_id}"
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"VPN Site-to-Site {display_name}",
        )

    def _record(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for record in getattr(data, "vpn_site_to_site", []):
            if _vpn_peer_id(record) == self._peer_id:
                return record
        return None

    @property
    def native_value(self) -> Optional[str]:
        record = self._record()
        if not record:
            return None
        state = _vpn_peer_state(record, [])
        if state:
            return state
        return "DISCONNECTED"

    @property
    def icon(self) -> Optional[str]:
        return _vpn_icon_for_state(self.native_value, self._default_icon)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        record = self._record() or {}
        state = self.native_value
        client_count = _vpn_peer_client_count(record, []) or 0
        attrs = {
            "role": record.get("_ha_role") or "site_to_site",
            "category": record.get("_ha_category"),
            "template": record.get("template")
            or record.get("_ha_template")
            or record.get("profile"),
            "vpn_type": record.get("vpn_type") or record.get("type"),
            "interface": record.get("interface") or record.get("ifname"),
            "vpn_name": record.get("vpn_name")
            or record.get("name")
            or record.get("peer_name"),
            "public_ip": record.get("public_ip")
            or record.get("gateway")
            or record.get("server_addr"),
            "tunnel_subnet": record.get("tunnel_subnet")
            or record.get("tunnel_network")
            or record.get("client_subnet")
            or record.get("subnet"),
            "local_ip": record.get("local_ip")
            or record.get("server_ip")
            or record.get("gateway"),
            "remote_host": record.get("remote_host")
            or record.get("remote_ip")
            or record.get("peer_addr")
            or record.get("server_addr"),
            "remote_ip": record.get("remote_ip")
            or record.get("peer_addr")
            or record.get("server_addr"),
            "tunnel_ip": record.get("tunnel_ip"),
            "client_count": client_count,
            "status": record.get("status") or record.get("state"),
            "state": state,
            "last_state_change": record.get("last_state_change"),
            "rx_bytes": _coerce_int(record.get("rx_bytes")),
            "tx_bytes": _coerce_int(record.get("tx_bytes")),
            "uptime": record.get("uptime")
            or record.get("uptime_seconds")
            or record.get("uptime_display"),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewaySpeedtestSensor(UniFiGatewaySensorBase):
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        kind: str,
        label: str,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_speedtest_{kind}"
        super().__init__(coordinator, client, unique_id, label)
        self._kind = kind

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        attrs = {
            "source": record.get("source") if record else None,
            "rundate": record.get("rundate") if record else None,
            "server": record.get("server") if record else None,
            "status": record.get("status") if record else None,
        }
        if record:
            for key in (
                "server_cc",
                "server_city",
                "server_country",
                "server_lat",
                "server_long",
                "server_provider",
                "server_provider_url",
            ):
                attrs[key] = record.get(key)
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewaySpeedtestDownloadSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-download"
    _attr_native_unit_of_measurement = "Mbps"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "down", "Speedtest Download")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("download_mbps") is not None:
            return round(float(record["download_mbps"]), 2)
        return None


class UniFiGatewaySpeedtestUploadSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-upload"
    _attr_native_unit_of_measurement = "Mbps"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "up", "Speedtest Upload")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("upload_mbps") is not None:
            return round(float(record["upload_mbps"]), 2)
        return None


class UniFiGatewaySpeedtestPingSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-clock"
    _attr_native_unit_of_measurement = "ms"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "ping", "Speedtest Ping")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("latency_ms") is not None:
            return round(float(record["latency_ms"]), 1)
        return None


def _to_ip_network(value: Optional[str]):
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
