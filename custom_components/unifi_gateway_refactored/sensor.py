from __future__ import annotations

import hashlib
import logging
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Set

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import entity_registry as er

from .const import DEFAULT_SITE, DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiOSClient, VpnState


_LOGGER = logging.getLogger(__name__)


SUBSYSTEM_SENSORS: Dict[str, tuple[str, str]] = {
    "wan": ("WAN", "mdi:shield-outline"),
    "lan": ("LAN", "mdi:lan"),
    "wlan": ("WLAN", "mdi:wifi"),
    "vpn": ("VPN", "mdi:folder-key-network"),
}


def _build_health_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    health: Optional[List[Dict[str, Any]]],
    health_entities: Dict[str, HealthSensor],
    client: UniFiOSClient,
    site_key: str,
    created_unique_ids: Set[str],
) -> List[HealthSensor]:
    ent_reg = er.async_get(hass)
    created: List[HealthSensor] = []
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
        if subsystem in SUBSYSTEM_SENSORS:
            continue
        uid = f"{entry.entry_id}|{site_key}|health::{_sanitize_stable_key(subsystem)}"
        seen.add(uid)
        entity = health_entities.get(uid)
        if entity is None:
            entity_id = ent_reg.async_get_entity_id("sensor", DOMAIN, uid)
            if entity_id:
                entry_record = ent_reg.async_get(entity_id)
                if entry_record is not None:
                    registry_owner = getattr(
                        entry_record, "config_entry_id", entry.entry_id
                    )
                    if registry_owner != entry.entry_id:
                        continue
            entity = HealthSensor(
                unique_id=uid,
                name=subsystem.upper(),
                payload=item,
                controller_context=controller_context,
            )
            health_entities[uid] = entity
            created_unique_ids.add(uid)
            created.append(entity)
        else:
            entity.set_payload(item, controller_context=controller_context)

    for uid, entity in list(health_entities.items()):
        if uid not in seen:
            entity.mark_stale()

    return created


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    _LOGGER.debug(
        "Setting up UniFi Gateway sensors for config entry %s", entry.entry_id
    )
    data = hass.data[DOMAIN][entry.entry_id]
    client: UniFiOSClient = data["client"]
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]

    await coordinator.async_config_entry_first_refresh()
    site_key = resolve_site_key(client, coordinator.data)
    created_unique_ids: Set[str] = set()

    static_entities: List[SensorEntity] = []
    for subsystem, (label, icon) in SUBSYSTEM_SENSORS.items():
        entity = UniFiGatewaySubsystemSensor(
            coordinator, client, entry.entry_id, site_key, subsystem, label, icon
        )
        static_entities.append(entity)
        if entity.unique_id:
            created_unique_ids.add(entity.unique_id)

    alerts_sensor = UniFiGatewayAlertsSensor(
        coordinator, client, entry.entry_id, site_key
    )
    static_entities.append(alerts_sensor)
    if alerts_sensor.unique_id:
        created_unique_ids.add(alerts_sensor.unique_id)

    firmware_sensor = UniFiGatewayFirmwareSensor(
        coordinator, client, entry.entry_id, site_key
    )
    static_entities.append(firmware_sensor)
    if firmware_sensor.unique_id:
        created_unique_ids.add(firmware_sensor.unique_id)

    speedtest_download = UniFiGatewaySpeedtestDownloadSensor(
        coordinator, client, entry.entry_id, site_key
    )
    speedtest_upload = UniFiGatewaySpeedtestUploadSensor(
        coordinator, client, entry.entry_id, site_key
    )
    speedtest_ping = UniFiGatewaySpeedtestPingSensor(
        coordinator, client, entry.entry_id, site_key
    )
    for sensor in (speedtest_download, speedtest_upload, speedtest_ping):
        static_entities.append(sensor)
        if sensor.unique_id:
            created_unique_ids.add(sensor.unique_id)

    _LOGGER.debug(
        "Adding %s static sensors for entry %s",
        len(static_entities),
        entry.entry_id,
    )
    async_add_entities(static_entities, update_before_add=True)

    health_entities: Dict[str, HealthSensor] = {}
    vpn_diag_entity: Optional[VpnDiagSensor] = None

    def _build_vpn_entities(
        entry: ConfigEntry, data: Dict[str, Any] | UniFiGatewayData | None
    ) -> List[SensorEntity]:
        nonlocal vpn_diag_entity

        ents: List[SensorEntity] = []
        controller_site = client.get_site() or DEFAULT_SITE
        controller_context = {
            "controller_api": client.get_controller_api_url(),
            "controller_ui": client.get_controller_url(),
            "controller_site": controller_site,
        }
        vpn_state: VpnState = VpnState()

        if isinstance(data, UniFiGatewayData):
            controller_info = getattr(data, "controller", {}) or {}
            if isinstance(controller_info, dict):
                site_candidate = controller_info.get("site")
                if isinstance(site_candidate, str) and site_candidate:
                    controller_site = site_candidate
                    controller_context["controller_site"] = controller_site
                api_candidate = controller_info.get("api_url")
                if isinstance(api_candidate, str) and api_candidate:
                    controller_context["controller_api"] = api_candidate
                ui_candidate = controller_info.get("url")
                if isinstance(ui_candidate, str) and ui_candidate:
                    controller_context["controller_ui"] = ui_candidate
            if isinstance(data.vpn_state, VpnState):
                vpn_state = data.vpn_state
        elif isinstance(data, dict):
            potential = data.get("vpn_state")
            if isinstance(potential, VpnState):
                vpn_state = potential

        remote_users = list(vpn_state.remote_users)
        s2s_peers = list(vpn_state.site_to_site_peers)
        teleport_servers = list(vpn_state.teleport_servers)
        teleport_clients = list(vpn_state.teleport_clients)

        counts = {
            "remote_users": len(remote_users),
            "s2s_peers": len(s2s_peers),
            "teleport_servers": len(teleport_servers),
            "teleport_clients": len(teleport_clients),
        }
        total_connections = sum(counts.values())

        diag_errors = vpn_state.errors
        if isinstance(diag_errors, dict) and diag_errors:
            state_token = "error"
        elif total_connections > 0:
            state_token = "ok"
        else:
            state_token = "unknown"

        diag_uid = f"{entry.entry_id}|{site_key}|vpn::diagnostics"
        if vpn_diag_entity is None:
            vpn_diag_entity = VpnDiagSensor(
                unique_id=diag_uid,
                name="VPN diagnostics",
                site=controller_site,
                state=state_token,
                vpn_state=vpn_state,
                controller_context=controller_context,
            )
            ents.append(vpn_diag_entity)
            created_unique_ids.add(diag_uid)
        else:
            vpn_diag_entity.set_state(
                state_token,
                vpn_state=vpn_state,
                site=controller_site,
                controller_context=controller_context,
            )
        return ents

    known_wan: set[str] = set()
    known_lan: set[str] = set()
    known_wlan: set[str] = set()

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

        new_entities.extend(
            _build_health_entities(
                hass,
                entry,
                coordinator_data.health,
                health_entities,
                client,
                site_key,
                created_unique_ids,
            )
        )
        new_entities.extend(_build_vpn_entities(entry, coordinator_data))

        entity_registry = er.async_get(hass)

        def _should_skip(unique_id: str) -> bool:
            if unique_id in created_unique_ids:
                return True
            entity_id = entity_registry.async_get_entity_id("sensor", DOMAIN, unique_id)
            if not entity_id:
                return False
            entry_entry = entity_registry.async_get(entity_id)
            if entry_entry and entry_entry.config_entry_id != entry.entry_id:
                _LOGGER.warning(
                    "Skipping entity with unique_id %s for entry %s; already owned by %s",
                    unique_id,
                    entry.entry_id,
                    entity_id,
                )
                return True
            return False

        for link in coordinator_data.wan_links:
            link_key = wan_interface_key(link)
            if link_key in known_wan:
                continue
            known_wan.add(link_key)
            for cls, suffix in (
                (UniFiGatewayWanStatusSensor, "status"),
                (UniFiGatewayWanIpSensor, "ip"),
                (UniFiGatewayWanIspSensor, "isp"),
            ):
                unique_id = build_wan_unique_id(entry.entry_id, site_key, link, suffix)
                if _should_skip(unique_id):
                    continue
                new_entities.append(
                    cls(coordinator, client, entry.entry_id, site_key, link)
                )
                created_unique_ids.add(unique_id)

        for network in coordinator_data.lan_networks:
            key = lan_interface_key(network)
            if key in known_lan:
                continue
            known_lan.add(key)
            unique_id = build_lan_unique_id(entry.entry_id, site_key, network)
            if _should_skip(unique_id):
                continue
            new_entities.append(
                UniFiGatewayLanClientsSensor(
                    coordinator, client, entry.entry_id, site_key, network
                )
            )
            created_unique_ids.add(unique_id)

        for wlan in coordinator_data.wlans:
            ssid_key = wlan_interface_key(wlan)
            if ssid_key in known_wlan:
                continue
            known_wlan.add(ssid_key)
            unique_id = build_wlan_unique_id(entry.entry_id, site_key, wlan)
            if _should_skip(unique_id):
                continue
            new_entities.append(
                UniFiGatewayWlanClientsSensor(
                    coordinator, client, entry.entry_id, site_key, wlan
                )
            )
            created_unique_ids.add(unique_id)

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


def _sanitize_stable_key(value: str) -> str:
    cleaned = value.strip().lower()
    sanitized = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in cleaned
    )
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")
    digest = hashlib.sha256(cleaned.encode()).hexdigest()
    return sanitized.strip("_") or digest[:12]


def wan_interface_key(link: Dict[str, Any]) -> str:
    link_id = str(link.get("id") or link.get("_id") or link.get("ifname") or "wan")
    link_name = link.get("name") or link_id
    identifiers = _wan_identifier_candidates(link_id, link_name, link)
    canonical = (sorted(identifiers) or [link_id])[0]
    return _sanitize_stable_key(canonical or link_id)


def lan_interface_key(network: Dict[str, Any]) -> str:
    token = (
        network.get("_id")
        or network.get("id")
        or network.get("name")
        or network.get("network_id")
        or network.get("vlan")
        or "lan"
    )
    return _sanitize_stable_key(str(token))


def wlan_interface_key(wlan: Dict[str, Any]) -> str:
    ssid = (
        wlan.get("name")
        or wlan.get("ssid")
        or wlan.get("_id")
        or wlan.get("id")
        or "wlan"
    )
    return _sanitize_stable_key(str(ssid))


def resolve_site_key(client: UniFiOSClient, data: UniFiGatewayData | None) -> str:
    """Return a normalized site identifier for unique_id construction."""

    site_identifier: Optional[str] = None
    try:
        site_identifier = client.site_id()
    except Exception:  # pragma: no cover - defensive
        site_identifier = None
    if (
        not site_identifier
        and data
        and isinstance(getattr(data, "controller", None), dict)
    ):
        controller_info = data.controller
        candidate = controller_info.get("site_id") or controller_info.get("site")
        if isinstance(candidate, str) and candidate:
            site_identifier = candidate
    if not site_identifier:
        site_identifier = client.get_site() or DEFAULT_SITE
    return _sanitize_stable_key(str(site_identifier))


def build_wan_unique_id(
    entry_id: str, site_key: str, link: Dict[str, Any], suffix: str
) -> str:
    return f"{entry_id}|{site_key}|wan::{wan_interface_key(link)}::{suffix}"


def build_lan_unique_id(entry_id: str, site_key: str, network: Dict[str, Any]) -> str:
    return f"{entry_id}|{site_key}|lan::{lan_interface_key(network)}::clients"


def build_wlan_unique_id(entry_id: str, site_key: str, wlan: Dict[str, Any]) -> str:
    return f"{entry_id}|{site_key}|wlan::{wlan_interface_key(wlan)}::clients"


def _first_non_empty(record: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = record.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
            continue
        if isinstance(value, list):
            flattened = [
                str(item).strip() for item in value if item not in (None, "", [], {})
            ]
            if flattened:
                return ", ".join(flattened)
            continue
        return str(value)
    return None


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
                if (
                    normalized in identifiers
                    or normalized.replace(" ", "") in identifiers
                ):
                    return record
            elif value is not None:
                normalized = str(value).strip().lower()
                if normalized in identifiers:
                    return record
    return fallback


def _value_from_record(
    record: Optional[Dict[str, Any]], keys: Iterable[str]
) -> Optional[Any]:
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


class VpnDiagSensor(_GatewayDynamicSensor):
    """Aggregated VPN diagnostics sensor."""

    _attr_icon = "mdi:shield-search"

    def __init__(
        self,
        unique_id: str,
        name: str,
        site: str,
        state: str,
        vpn_state: VpnState,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(unique_id, name, controller_context)
        self._site = site
        self._vpn_state = VpnState()
        self._counts: Dict[str, int] = {}
        self._attrs = {}
        self.set_state(
            state, vpn_state=vpn_state, site=site, controller_context=controller_context
        )

    def set_state(
        self,
        state: str,
        *,
        vpn_state: VpnState,
        site: Optional[str] = None,
        controller_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        if site:
            self._site = site
        if controller_context:
            self.update_context(controller_context)
        self._vpn_state = vpn_state
        counts = {
            "remote_users": len(vpn_state.remote_users),
            "s2s_peers": len(vpn_state.site_to_site_peers),
            "teleport_servers": len(vpn_state.teleport_servers),
            "teleport_clients": len(vpn_state.teleport_clients),
        }
        self._counts = counts

        normalized = str(state or "").strip().lower()
        if not normalized:
            normalized = "error" if vpn_state.errors else "unknown"
        self._state = normalized
        self._attr_available = True

        attrs: Dict[str, Any] = {
            "site": self._site,
            "counts": counts,
            "remote_users": list(vpn_state.remote_users),
            "site_to_site_peers": list(vpn_state.site_to_site_peers),
            "teleport_servers": list(vpn_state.teleport_servers),
            "teleport_clients": list(vpn_state.teleport_clients),
        }
        attempts_attr = [
            {
                "path": attempt.path,
                "status": attempt.status,
                "ok": attempt.ok,
                "snippet": attempt.snippet,
            }
            for attempt in vpn_state.attempts
        ]
        if attempts_attr:
            attrs["attempts"] = attempts_attr
        if vpn_state.errors:
            attrs["errors"] = vpn_state.errors
        self._attrs = attrs
        self._async_write_state()

    def mark_stale(self) -> None:  # type: ignore[override]
        self._state = None
        self._attr_available = False
        self._counts = {}
        self._attrs = {
            "site": self._site,
            "counts": {},
            "remote_users": [],
            "site_to_site_peers": [],
            "teleport_servers": [],
            "teleport_clients": [],
            "attempts": [],
        }
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
        entry_id: str,
        site_key: str,
        link: Dict[str, Any],
        suffix: str,
        name_suffix: str = "",
    ) -> None:
        self._entry_id = entry_id
        self._link_id = str(
            link.get("id") or link.get("_id") or link.get("ifname") or "wan"
        )
        self._link_name = link.get("name") or self._link_id
        self._identifiers = _wan_identifier_candidates(
            self._link_id, self._link_name, link
        )
        canonical = (sorted(self._identifiers) or [self._link_id])[0]
        self._uid_source = canonical
        unique_id = build_wan_unique_id(entry_id, site_key, link, suffix)
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
        entry_id: str,
        site_key: str,
        subsystem: str,
        label: str,
        icon: str,
    ) -> None:
        unique_id = (
            f"{entry_id}|{site_key}|subsystem::{_sanitize_stable_key(subsystem)}"
        )
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
        if self._subsystem == "vpn" and data:
            vpn_state = data.vpn_state or VpnState()
            counts = {
                "remote_users": len(vpn_state.remote_users),
                "site_to_site_peers": len(vpn_state.site_to_site_peers),
                "teleport_servers": len(vpn_state.teleport_servers),
                "teleport_clients": len(vpn_state.teleport_clients),
            }
            attrs["vpn_counts"] = counts
            if vpn_state.attempts:
                attrs["vpn_attempts"] = [
                    {
                        "path": attempt.path,
                        "status": attempt.status,
                        "ok": attempt.ok,
                        "snippet": attempt.snippet,
                    }
                    for attempt in vpn_state.attempts
                ]
            if vpn_state.errors:
                attrs["vpn_errors"] = vpn_state.errors
        attrs.update(self._controller_attrs())
        return attrs

    def _vpn_disabled(self, record: Dict[str, Any], data: UniFiGatewayData) -> bool:
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

        vpn_state = getattr(data, "vpn_state", None)
        if isinstance(vpn_state, VpnState):
            if (
                not (
                    vpn_state.remote_users
                    or vpn_state.site_to_site_peers
                    or vpn_state.teleport_servers
                    or vpn_state.teleport_clients
                )
                and not vpn_state.errors
            ):
                return True

        return False


class UniFiGatewayAlertsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:information-outline"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
    ) -> None:
        unique_id = f"{entry_id}|{site_key}|alerts"
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
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
    ) -> None:
        unique_id = f"{entry_id}|{site_key}|firmware_upgradable"
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
        entry_id: str,
        site_key: str,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, entry_id, site_key, link, "status")
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
        entry_id: str,
        site_key: str,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, entry_id, site_key, link, "ip", " IP")
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
        entry_id: str,
        site_key: str,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, entry_id, site_key, link, "isp", " ISP")
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
        entry_id: str,
        site_key: str,
        network: Dict[str, Any],
    ) -> None:
        self._network = network
        self._network_id = str(
            network.get("_id") or network.get("id") or network.get("name")
        )
        self._network_name = network.get("name") or f"VLAN {network.get('vlan')}"
        self._subnet = (
            network.get("subnet") or network.get("ip_subnet") or network.get("cidr")
        )
        self._ip_network = _to_ip_network(self._subnet)
        unique_id = build_lan_unique_id(entry_id, site_key, network)
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"LAN {self._network_name}",
        )

    def _matches_client(self, client: Dict[str, Any]) -> bool:
        if str(client.get("network_id")) == self._network_id:
            return True
        network_name = client.get("network")
        if (
            isinstance(network_name, str)
            and network_name.lower() == self._network_name.lower()
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
        entry_id: str,
        site_key: str,
        wlan: Dict[str, Any],
    ) -> None:
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        unique_id = build_wlan_unique_id(entry_id, site_key, wlan)
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


class UniFiGatewaySpeedtestSensor(UniFiGatewaySensorBase):
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
        kind: str,
        label: str,
    ) -> None:
        unique_id = f"{entry_id}|{site_key}|speedtest::{kind}"
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
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
    ) -> None:
        super().__init__(
            coordinator, client, entry_id, site_key, "down", "Speedtest Download"
        )

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
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
    ) -> None:
        super().__init__(
            coordinator, client, entry_id, site_key, "up", "Speedtest Upload"
        )

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
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        site_key: str,
    ) -> None:
        super().__init__(
            coordinator, client, entry_id, site_key, "ping", "Speedtest Ping"
        )

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
