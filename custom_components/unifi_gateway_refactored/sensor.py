from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache, partial
import html
import hashlib
import logging
import time
import ipaddress
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
    TYPE_CHECKING,
    Type,
    Protocol,
    cast,
)

if TYPE_CHECKING:  # pragma: no cover - type checking helpers only
    from requests import Response as RequestsResponse
    from requests.exceptions import RequestException as RequestsRequestException
else:  # pragma: no cover - runtime fallback when requests missing
    RequestsResponse = Any
    RequestsRequestException = Exception

try:  # pragma: no cover - optional dependency in test environment
    import requests
except ImportError:  # pragma: no cover - gracefully handle missing dependency
    requests = cast(Any, None)

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
try:  # pragma: no cover - compatibility shim for older Home Assistant versions
    from homeassistant.const import UnitOfTime
except ImportError:  # pragma: no cover - Home Assistant <=2023.11
    from homeassistant.const import TIME_MILLISECONDS as UNIT_MILLISECONDS
else:  # pragma: no cover - modern Home Assistant releases
    UNIT_MILLISECONDS = UnitOfTime.MILLISECONDS
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from homeassistant.util import Throttle
from .const import CONF_HOST, DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, ConnectivityError, UniFiOSClient

class _IPWhoisProtocol(Protocol):
    def __init__(self, address: str) -> None:
        ...

    def lookup_whois(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        ...


_IPWhoisClass: Type[_IPWhoisProtocol] | None

try:  # pragma: no cover - optional dependency for WHOIS lookups
    from ipwhois import IPWhois as _IPWhoisClass
except ImportError:  # pragma: no cover - dependency is optional at runtime
    _IPWhoisClass = None

IPWhois: Type[_IPWhoisProtocol] | None = cast(Type[_IPWhoisProtocol] | None, _IPWhoisClass)


_LOGGER = logging.getLogger(__name__)


VPN_MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=10)


def _freeze_state(value: Any) -> Any:
    """Create a hashable representation of an arbitrary value."""

    if isinstance(value, Mapping):
        return tuple(sorted((key, _freeze_state(val)) for key, val in value.items()))
    if isinstance(value, (list, tuple, set)):
        return tuple(_freeze_state(item) for item in value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    return value


SUBSYSTEM_SENSORS: Dict[str, tuple[str, str]] = {
    "wan": ("WAN", "mdi:shield-outline"),
    "lan": ("LAN", "mdi:lan"),
    "wlan": ("WLAN", "mdi:wifi"),
    "www": ("WWW", "mdi:web"),
}


@dataclass
class RunnerState:
    last_ok: bool | None = None
    last_error: str | None = None
    last_duration_ms: int | None = None
    last_run: datetime | None = None


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    _LOGGER.debug(
        "Setting up UniFi Gateway sensors for config entry %s", entry.entry_id
    )
    data = hass.data[DOMAIN][entry.entry_id]
    client: UniFiOSClient = data["client"]
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]

    base_name = entry.title or entry.data.get(CONF_HOST) or "UniFi Gateway"
    device_name = base_name

    static_entities: List[SensorEntity] = []
    for subsystem, (label, icon) in SUBSYSTEM_SENSORS.items():
        static_entities.append(
            UniFiGatewaySubsystemSensor(
                coordinator,
                client,
                subsystem,
                label,
                icon,
                device_name=device_name,
                wifi_overrides=data.get("wifi_overrides"),
            )
        )
    static_entities.append(
        UniFiGatewayAlertsSensor(coordinator, client, device_name=device_name)
    )
    static_entities.append(
        UniFiGatewayFirmwareSensor(coordinator, client, device_name=device_name)
    )
    static_entities.append(
        UniFiGatewaySpeedtestDownloadSensor(
            coordinator, client, device_name=device_name
        )
    )
    static_entities.append(
        UniFiGatewaySpeedtestUploadSensor(
            coordinator, client, device_name=device_name
        )
    )
    static_entities.append(
        UniFiGatewaySpeedtestPingSensor(
            coordinator, client, device_name=device_name
        )
    )

    runner_state = RunnerState()
    device_identifier = (DOMAIN, client.instance_key())
    controller_url = client.get_controller_url()
    monitor_entities = [
        SpeedtestStatusSensor(
            entry.entry_id,
            runner_state,
            device_identifier,
            device_name,
            controller_url,
        ),
        SpeedtestLastErrorSensor(
            entry.entry_id,
            runner_state,
            device_identifier,
            device_name,
            controller_url,
        ),
        SpeedtestDurationSensor(
            entry.entry_id,
            runner_state,
            device_identifier,
            device_name,
            controller_url,
        ),
        SpeedtestLastRunSensor(
            entry.entry_id,
            runner_state,
            device_identifier,
            device_name,
            controller_url,
        ),
    ]
    static_entities.extend(monitor_entities)

    _LOGGER.debug(
        "Adding %s static sensors for entry %s",
        len(static_entities),
        entry.entry_id,
    )
    async_add_entities(static_entities)

    async def _on_result(
        *, success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        runner_state.last_ok = success
        runner_state.last_error = error
        runner_state.last_duration_ms = duration_ms
        runner_state.last_run = datetime.now(timezone.utc)
        for entity in monitor_entities:
            entity.async_write_ha_state_if_changed()

    entry_store = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if entry_store is not None:
        entry_store["on_result_cb"] = _on_result
    else:
        _LOGGER.debug(
            "Speedtest monitor callback setup skipped; entry store missing for %s",
            entry.entry_id,
        )

    known_wan: set[str] = set()
    known_lan: set[str] = set()
    known_wlan: set[str] = set()
    known_vpn: set[str] = set()
    discovery_lock = asyncio.Lock()

    async def _async_sync_dynamic() -> None:
        async with discovery_lock:
            _LOGGER.debug(
                "Synchronizing dynamic UniFi Gateway sensors for entry %s",
                entry.entry_id,
            )
            coordinator_data: Optional[UniFiGatewayData] = coordinator.data
            if coordinator_data is None:
                _LOGGER.debug(
                    "Coordinator data unavailable during sync for entry %s",
                    entry.entry_id,
                )
                return

            new_entities: List[SensorEntity] = []

            entity_registry = er.async_get(hass)
            pending_unique_ids: set[str] = set()

            def _should_skip(unique_id: str) -> bool:
                entity_id = entity_registry.async_get_entity_id(
                    "sensor", DOMAIN, unique_id
                )
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

            vpn_server_cache: Dict[str, List[Dict[str, Any]]] = {}

            async def _async_lookup_vpn_servers(net_identifier: str) -> List[Dict[str, Any]]:
                if net_identifier in vpn_server_cache:
                    return vpn_server_cache[net_identifier]
                try:
                    candidates = await hass.async_add_executor_job(
                        partial(client.get_vpn_servers, net_id=net_identifier)
                    )
                except (APIError, ConnectivityError) as err:
                    _LOGGER.debug(
                        "VPN lookup for network %s failed: %s", net_identifier, err
                    )
                    candidates = []
                if not isinstance(candidates, list):
                    candidates = []
                vpn_server_cache[net_identifier] = candidates
                return candidates

            for link in coordinator_data.wan_links:
                link_key = wan_interface_key(link)
                if link_key in known_wan:
                    continue
                known_wan.add(link_key)
                for cls, suffix in (
                    (UniFiGatewayWanStatusSensor, "status"),
                    (UniFiGatewayWanIpSensor, "ip"),
                    (UniFiGatewayWanIpv6Sensor, "ipv6"),
                    (UniFiGatewayWanIspSensor, "isp"),
                ):
                    unique_id = build_wan_unique_id(entry.entry_id, link, suffix)
                    if unique_id in pending_unique_ids or _should_skip(unique_id):
                        continue
                    new_entities.append(
                        cls(
                            coordinator,
                            client,
                            entry.entry_id,
                            link,
                            device_name=device_name,
                        )
                    )
                    pending_unique_ids.add(unique_id)

            for network in coordinator_data.lan_networks:
                key = lan_interface_key(network)
                if key in known_lan:
                    continue
                known_lan.add(key)
                unique_id = build_lan_unique_id(entry.entry_id, network)
                if unique_id in pending_unique_ids or _should_skip(unique_id):
                    continue
                new_entities.append(
                    UniFiGatewayLanClientsSensor(
                        coordinator,
                        client,
                        entry.entry_id,
                        network,
                        device_name=device_name,
                    )
                )
                pending_unique_ids.add(unique_id)

            for wlan in coordinator_data.wlans:
                ssid_key = wlan_interface_key(wlan)
                if ssid_key in known_wlan:
                    continue
                known_wlan.add(ssid_key)
                unique_id = build_wlan_unique_id(entry.entry_id, wlan)
                if unique_id in pending_unique_ids or _should_skip(unique_id):
                    continue
                new_entities.append(
                    UniFiGatewayWlanClientsSensor(
                        coordinator,
                        client,
                        entry.entry_id,
                        wlan,
                        device_name=device_name,
                    )
                )
                pending_unique_ids.add(unique_id)

            # VPN usage sensors derived from network/VPN server associations
            for network in coordinator_data.networks:
                purpose = str(
                    network.get("purpose") or network.get("role") or ""
                ).strip().lower()
                if purpose == "wan":
                    continue

                vlan = network.get("vlan")
                if isinstance(vlan, int) or (
                    isinstance(vlan, str) and vlan.isdigit()
                ):
                    continue

                net_id = network.get("_id") or network.get("id")
                server: Optional[Dict[str, Any]] = None

                if net_id:
                    candidates = await _async_lookup_vpn_servers(str(net_id))
                    if candidates:
                        server = candidates[0]

                if server is None:
                    server = {
                        "id": net_id,
                        "name": network.get("name") or "VPN",
                        "vpn_type": network.get("vpn_type") or "Unknown",
                        "linked_network_id": net_id,
                        "_raw": {"source": "network_only"},
                    }

                vpn_type_raw = (
                    server.get("vpn_type") or network.get("vpn_type") or ""
                )
                protocol_type, mode = _parse_protocol_and_mode(vpn_type_raw)
                if (
                    vpn_type_raw.strip().lower() in {"", "unknown"}
                    and protocol_type == "unknown"
                    and mode == "unknown"
                ):
                    continue

                entity_key = build_vpn_server_unique_id(entry.entry_id, server, network)
                key = vpn_instance_key({"id": entity_key})
                if key in known_vpn:
                    continue
                known_vpn.add(key)

                if entity_key in pending_unique_ids or _should_skip(entity_key):
                    continue

                new_entities.append(
                    UniFiGatewayVpnUsageSensor(
                        coordinator,
                        client,
                        entry.entry_id,
                        base_name,
                        server,
                        network,
                        unique_id=entity_key,
                    )
                )
                pending_unique_ids.add(entity_key)

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
                    "No new dynamic sensors discovered for entry %s",
                    entry.entry_id,
                )

    def _handle_coordinator_update() -> None:
        hass.async_create_task(_async_sync_dynamic())

    await _async_sync_dynamic()
    entry.async_on_unload(coordinator.async_add_listener(_handle_coordinator_update))
    await coordinator.async_request_refresh()


class SpeedtestMonitorEntity(SensorEntity):
    """Base class providing device binding for speedtest monitor sensors."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        entry_id: str,
        state: RunnerState,
        device_identifier: tuple[str, str],
        device_name: str,
        controller_url: Optional[str],
    ) -> None:
        self._state = state
        self._device_identifier = device_identifier
        self._device_name = device_name
        self._controller_url = controller_url
        self._entry_id = entry_id
        self._last_signature: Any | None = None

    @property
    def device_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "identifiers": {self._device_identifier},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
        }
        if self._controller_url:
            info["configuration_url"] = self._controller_url
        return info

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_write_ha_state_if_changed()

    def _state_signature(self) -> Any:
        native = self.native_value
        attrs = self.extra_state_attributes
        icon = getattr(self, "icon", None)
        available = self.available
        return (
            _freeze_state(native),
            _freeze_state(attrs) if attrs is not None else None,
            icon,
            available,
        )

    def async_write_ha_state_if_changed(self) -> None:
        signature = self._state_signature()
        if signature == self._last_signature and self._last_signature is not None:
            return
        self._last_signature = signature
        super().async_write_ha_state()


class SpeedtestLastRunSensor(SpeedtestMonitorEntity):
    _attr_name = "Speedtest Last Run"
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(
        self,
        entry_id: str,
        state: RunnerState,
        device_identifier: tuple[str, str],
        device_name: str,
        controller_url: Optional[str],
    ) -> None:
        super().__init__(entry_id, state, device_identifier, device_name, controller_url)
        self._attr_unique_id = f"{entry_id}_speedtest_last_run"

    @property
    def native_value(self):
        return self._state.last_run


class SpeedtestDurationSensor(SpeedtestMonitorEntity):
    _attr_name = "Speedtest Last Duration"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UNIT_MILLISECONDS

    def __init__(
        self,
        entry_id: str,
        state: RunnerState,
        device_identifier: tuple[str, str],
        device_name: str,
        controller_url: Optional[str],
    ) -> None:
        super().__init__(entry_id, state, device_identifier, device_name, controller_url)
        self._attr_unique_id = f"{entry_id}_speedtest_last_duration"

    @property
    def native_value(self):
        return self._state.last_duration_ms


class SpeedtestLastErrorSensor(SpeedtestMonitorEntity):
    _attr_name = "Speedtest Last Error"
    _attr_icon = "mdi:alert-circle-outline"

    def __init__(
        self,
        entry_id: str,
        state: RunnerState,
        device_identifier: tuple[str, str],
        device_name: str,
        controller_url: Optional[str],
    ) -> None:
        super().__init__(entry_id, state, device_identifier, device_name, controller_url)
        self._attr_unique_id = f"{entry_id}_speedtest_last_error"

    @property
    def native_value(self):
        return self._state.last_error or ""


class SpeedtestStatusSensor(SpeedtestMonitorEntity):
    _attr_name = "Speedtest Last Run OK"
    _attr_icon = "mdi:check-network"

    def __init__(
        self,
        entry_id: str,
        state: RunnerState,
        device_identifier: tuple[str, str],
        device_name: str,
        controller_url: Optional[str],
    ) -> None:
        super().__init__(entry_id, state, device_identifier, device_name, controller_url)
        self._attr_unique_id = f"{entry_id}_speedtest_last_run_ok"

    @property
    def native_value(self):
        if self._state.last_ok is None:
            return "unknown"
        return "ok" if self._state.last_ok else "error"


def _sanitize_stable_key(value: str) -> str:
    cleaned = value.strip().lower()
    sanitized = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in cleaned)
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
    ssid = wlan.get("name") or wlan.get("ssid") or wlan.get("_id") or wlan.get("id") or "wlan"
    return _sanitize_stable_key(str(ssid))


def _normalize_wifi_name(value: Optional[Any]) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


@dataclass(slots=True)
class _WlanClientSummary:
    counts: Dict[str, int]
    names: Dict[str, str]
    total: int


def _summarize_wlan_clients(data: Optional[UniFiGatewayData]) -> _WlanClientSummary:
    counts: Dict[str, int] = {}
    names: Dict[str, str] = {}
    if not data:
        return _WlanClientSummary(counts, names, 0)

    for wlan in data.wlans:
        if not isinstance(wlan, Mapping):
            continue
        key = wlan_interface_key(wlan)
        name = (
            wlan.get("name")
            or wlan.get("ssid")
            or wlan.get("_id")
            or wlan.get("id")
            or key
        )
        names[key] = str(name)

    for client in data.clients:
        if not isinstance(client, Mapping):
            continue
        ssid = (
            client.get("essid")
            or client.get("wifi_network")
            or client.get("ap_essid")
            or client.get("ssid")
        )
        if not ssid:
            continue
        key = _sanitize_stable_key(str(ssid))
        counts[key] = counts.get(key, 0) + 1
        if key not in names:
            names[key] = str(ssid)

    total = sum(counts.values())
    return _WlanClientSummary(counts, names, total)


def _resolve_wlan_user_count(
    summary: _WlanClientSummary, target: Optional[str]
) -> Tuple[int, Optional[str]]:
    if target is None:
        return 0, None

    candidate = target.strip()
    if not candidate:
        return 0, None

    sanitized_target = _sanitize_stable_key(candidate)
    if sanitized_target in summary.counts:
        return summary.counts[sanitized_target], sanitized_target

    lowered = candidate.lower()
    for key, name in summary.names.items():
        if name.lower() == lowered:
            return summary.counts.get(key, 0), key

    sanitized_matches = [
        key for key in summary.counts if key.startswith(sanitized_target)
    ]
    if len(sanitized_matches) == 1:
        key = sanitized_matches[0]
        return summary.counts.get(key, 0), key

    prefix_matches = [
        key for key, name in summary.names.items() if name.lower().startswith(lowered)
    ]
    if len(prefix_matches) == 1:
        key = prefix_matches[0]
        return summary.counts.get(key, 0), key

    return 0, None


def vpn_instance_key(tunnel: Dict[str, Any]) -> str:
    token = (
        tunnel.get("id")
        or tunnel.get("_id")
        or tunnel.get("uuid")
        or tunnel.get("name")
        or tunnel.get("peer")
        or tunnel.get("remote")
        or "vpn"
    )
    return _sanitize_stable_key(str(token))


def _parse_protocol_and_mode(vpn_type_value: Optional[str]) -> Tuple[str, str]:
    """Parse ``vpn_type`` textual description into protocol/mode pair."""

    text = (vpn_type_value or "").strip().lower()
    normalized = text.replace("_", " ").replace("-", " ")

    if "wireguard" in normalized or normalized.startswith("wg "):
        protocol = "wireguard"
    elif "openvpn" in normalized or "ovpn" in normalized:
        protocol = "openvpn"
    elif "l2tp" in normalized and ("ipsec" in normalized or "ikev2" in normalized):
        protocol = "l2tp-ipsec"
    elif "ikev2" in normalized:
        protocol = "ikev2"
    elif "ipsec" in normalized:
        protocol = "ipsec"
    elif "l2tp" in normalized:
        protocol = "l2tp"
    elif "pptp" in normalized:
        protocol = "pptp"
    elif "sstp" in normalized:
        protocol = "sstp"
    elif "gre" in normalized:
        protocol = "gre"
    else:
        protocol = "unknown"

    if "server" in normalized:
        mode = "server"
    elif "client" in normalized:
        mode = "client"
    elif any(
        term in normalized
        for term in ("site to site", "site-to-site", "s2s", "gateway to gateway", "peer", "peering", "tunnel")
    ):
        mode = "site-to-site"
    elif "remote user" in normalized or "road warrior" in normalized or "roadwarrior" in normalized:
        mode = "server"
    else:
        mode = "unknown"

    return protocol, mode


def build_wan_unique_id(entry_id: str, link: Dict[str, Any], suffix: str) -> str:
    return f"{entry_id}::wan::{wan_interface_key(link)}::{suffix}"


def build_lan_unique_id(entry_id: str, network: Dict[str, Any]) -> str:
    return f"{entry_id}::lan::{lan_interface_key(network)}::clients"


def build_wlan_unique_id(entry_id: str, wlan: Dict[str, Any]) -> str:
    return f"{entry_id}::wlan::{wlan_interface_key(wlan)}::clients"

def build_vpn_unique_id(entry_id: str, tunnel: Dict[str, Any], suffix: str) -> str:
    return f"{entry_id}::vpn::{vpn_instance_key(tunnel)}::{suffix}"


def build_vpn_server_unique_id(
    entry_id: str, server: Dict[str, Any], network: Dict[str, Any]
) -> str:
    pseudo = dict(server)
    if not pseudo.get("id"):
        pseudo["id"] = (
            network.get("_id")
            or network.get("id")
            or network.get("uuid")
            or network.get("name")
            or "vpn"
        )
    if not pseudo.get("name"):
        pseudo["name"] = network.get("name") or "VPN"
    return build_vpn_unique_id(entry_id, pseudo, "clients")


def _is_connected(record: Any) -> bool:
    if isinstance(record, dict):
        for key in ("connected", "active", "up"):
            if key in record:
                value = record[key]
                if isinstance(value, bool):
                    return value
                if isinstance(value, (int, float)):
                    return bool(value)
        status = record.get("status")
        if isinstance(status, str):
            lowered = status.strip().lower()
            if lowered in ("up", "connected", "online", "active"):
                return True
            if lowered in ("down", "disconnected", "offline", "inactive"):
                return False
        return True
    if isinstance(record, (int, float)):
        return bool(record)
    return record is True
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


_PLACEHOLDER_STRINGS: tuple[str, ...] = (
    "unknown",
    "none",
    "null",
    "n/a",
    "na",
    "not available",
)


def _value_from_record(
    record: Optional[Mapping[str, Any]], keys: Iterable[str]
) -> Optional[Any]:
    if not record:
        return None
    for key in keys:
        if key not in record:
            continue
        value = record.get(key)
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned and cleaned.lower() not in _PLACEHOLDER_STRINGS:
                return cleaned
        elif value not in (None, [], {}):
            return value
    return None


_WAN_IPV4_KEYS: tuple[str, ...] = (
    "ip",
    "wan_ip",
    "ipv4",
    "internet_ip",
    "public_ip",
    "external_ip",
)


_WAN_IPV6_KEYS: tuple[str, ...] = (
    "ipv6",
    "wan_ipv6",
    "internet_ipv6",
    "public_ipv6",
    "external_ipv6",
    "ip6",
    "ip_v6",
    "wan_ip6",
    "wan_ipv6_address",
    "wan_ipv6_ip",
    "ipv6_address",
    "global_ipv6",
    "public_ip6",
)


_WAN_GATEWAY_IPV6_KEYS: tuple[str, ...] = (
    "gateway_ipv6",
    "wan_gateway_ipv6",
    "gw_ipv6",
    "gateway_v6",
    "wan_gateway_ip6",
    "wan_ipv6_gateway",
)


_WAN_IPV6_PREFIX_KEYS: tuple[str, ...] = (
    "wan_ipv6_prefix",
    "ipv6_prefix",
    "prefix_ipv6",
    "wan_ipv6_subnet",
    "subnet_ipv6",
    "wan_prefix_ipv6",
    "ipv6_network",
    "ipv6_cidr",
    "wan_ipv6_cidr",
    "wan_ipv6_network",
)


def _extract_wan_value_with_source(
    link: Optional[Dict[str, Any]],
    health: Optional[Dict[str, Any]],
    keys: Iterable[str],
) -> Tuple[Optional[str], Optional[str]]:
    if link:
        value = _value_from_record(link, keys)
        if value:
            return value, "wan_link"
    if health:
        value = _value_from_record(health, keys)
        if value:
            return value, "wan_health"
    return None, None


def _extract_wan_value(
    link: Optional[Dict[str, Any]],
    health: Optional[Dict[str, Any]],
    keys: Iterable[str],
) -> Optional[str]:
    value, _ = _extract_wan_value_with_source(link, health, keys)
    return value


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


def _resolve_client_count_from_record(
    record: Optional[Mapping[str, Any]], keys: Iterable[str]
) -> Optional[int]:
    if not record:
        return None
    for key in keys:
        if key not in record:
            continue
        count = _extract_client_count(record.get(key))
        if count is not None:
            return count
    return None


def _normalize_client_field(value: Optional[Any]) -> str:
    if value in (None, ""):
        return "Unknown"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or "Unknown"
    return str(value)


def _lookup_remote_ip_geolocation(remote_ip: str) -> Dict[str, str]:
    normalized_ip = remote_ip.strip()
    if not normalized_ip:
        return {}

    try:
        ip_obj = ipaddress.ip_address(normalized_ip)
    except ValueError:
        return {}

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return {}

    return _cached_geolocation_lookup(normalized_ip)


@lru_cache(maxsize=512)
def _cached_geolocation_lookup(remote_ip: str) -> Dict[str, str]:
    if requests is None:
        return {}

    extracted: Dict[str, str] = {}

    try:
        response: RequestsResponse = requests.get(
            f"https://ipapi.co/{remote_ip}/json/", timeout=5
        )
    except RequestsRequestException as err:  # pragma: no cover - defensive logging
        _LOGGER.debug("Geolocation lookup failed for %s: %s", remote_ip, err)
        return {}

    if response.status_code != 200:
        _LOGGER.debug(
            "Geolocation lookup for %s returned status %s",
            remote_ip,
            response.status_code,
        )
        return {}

    try:
        payload = response.json()
    except ValueError:
        return {}

    if not isinstance(payload, Mapping):
        return {}

    if payload.get("error"):
        return {}

    def _store(key: str, value: Any) -> None:
        if value is None:
            return
        text = str(value).strip()
        if text:
            extracted[key] = text

    _store("city", payload.get("city"))
    _store("region", payload.get("region"))
    _store("state", payload.get("region"))
    _store("country", payload.get("country_name") or payload.get("country"))
    isp_value = (
        payload.get("org")
        or payload.get("asn_org")
        or payload.get("company")
        or payload.get("as")
        or payload.get("isp")
    )
    _store("isp", isp_value)

    return extracted


def _lookup_remote_ip_whois(remote_ip: str) -> Dict[str, str]:
    if IPWhois is None:
        return {}

    normalized_ip = remote_ip.strip()
    if not normalized_ip:
        return {}

    try:
        ip_obj = ipaddress.ip_address(normalized_ip)
    except ValueError:
        return {}

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return {}

    return _cached_whois_lookup(normalized_ip)


@lru_cache(maxsize=256)
def _cached_whois_lookup(remote_ip: str) -> Dict[str, str]:
    if IPWhois is None:
        return {}

    try:
        lookup = IPWhois(remote_ip)
        result = lookup.lookup_whois(get_referral=True)
    except Exception as err:  # pragma: no cover - defensive logging
        _LOGGER.debug("WHOIS lookup failed for %s: %s", remote_ip, err)
        return {}

    nets = result.get("nets") if isinstance(result, Mapping) else None
    extracted: Dict[str, str] = {}

    if isinstance(nets, list):
        for net in nets:
            if not isinstance(net, Mapping):
                continue

            city = net.get("city")
            if city and "city" not in extracted:
                extracted["city"] = str(city).strip()

            state = net.get("state") or net.get("region") or net.get("province")
            if state and "state" not in extracted:
                extracted["state"] = str(state).strip()

            country = net.get("country")
            if country and "country" not in extracted:
                extracted["country"] = str(country).strip()

            for key in ("description", "name", "org", "organization"):
                value = net.get(key)
                if value and "isp" not in extracted:
                    extracted["isp"] = str(value).strip()
                    break

            if {"city", "country", "isp"}.issubset(extracted.keys()):
                break

    if "isp" not in extracted:
        for key in ("asn_description", "asn", "nir"):
            value = result.get(key) if isinstance(result, Mapping) else None
            if value:
                extracted["isp"] = str(value).strip()
                break

    if "country" not in extracted and isinstance(result, Mapping):
        cc = result.get("asn_country_code")
        if cc:
            extracted["country"] = str(cc).strip()

    return {key: value for key, value in extracted.items() if value}


def _enrich_remote_ip_details(
    remote_ip: str, city: str, country: str, isp: str
) -> Tuple[str, str, str]:
    if not remote_ip or remote_ip == "Unknown":
        return city, country, isp

    detail_sources = (
        _lookup_remote_ip_geolocation(remote_ip),
        _lookup_remote_ip_whois(remote_ip),
    )

    for details in detail_sources:
        if not details:
            continue

        candidate_city = details.get("city")
        if candidate_city:
            city = _normalize_client_field(candidate_city)
        elif not city or city == "Unknown":
            for fallback_key in ("state", "region"):
                candidate_city = details.get(fallback_key)
                if candidate_city:
                    city = _normalize_client_field(candidate_city)
                    break

        candidate_country = details.get("country")
        if candidate_country:
            country = _normalize_client_field(candidate_country)
        elif not country or country == "Unknown":
            for fallback_key in ("state", "region"):
                candidate_country = details.get(fallback_key)
                if candidate_country:
                    country = _normalize_client_field(candidate_country)
                    break

        candidate_isp = details.get("isp")
        if candidate_isp:
            isp = _normalize_client_field(candidate_isp)
        elif not isp or isp == "Unknown":
            for key in ("organization", "org", "asn_description", "asn"):
                candidate = details.get(key)
                if candidate:
                    isp = _normalize_client_field(candidate)
                    break

    return city, country, isp


def _extract_nested_value(
    record: Mapping[str, Any], keys: Iterable[str]
) -> Optional[Any]:
    value = _value_from_record(record, keys)
    if value is not None:
        return value

    nested_sections = (
        "geoip",
        "geo",
        "ip_geo",
        "location",
        "client",
        "user",
        "details",
        "info",
        "metadata",
        "isp_info",
        "source",
        "session",
        "remote",
        "origin",
        "attributes",
    )
    for section in nested_sections:
        nested = record.get(section)
        if isinstance(nested, Mapping):
            value = _value_from_record(nested, keys)
            if value is not None:
                return value
    return None


def _iter_connected_client_records(raw: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    if not isinstance(raw, Mapping):
        return []

    candidates: List[Any] = []
    for key in (
        "connected_clients",
        "clients",
        "users",
        "peers",
        "remote_users",
        "active_clients",
        "sessions",
    ):
        value = raw.get(key)
        if value in (None, ""):
            continue
        candidates.append(value)

    stats = raw.get("stats") or raw.get("statistics")
    if isinstance(stats, Mapping):
        for key in ("clients", "connected_clients", "users"):
            value = stats.get(key)
            if value not in (None, ""):
                candidates.append(value)

    for value in candidates:
        if isinstance(value, list):
            for item in value:
                if isinstance(item, Mapping):
                    yield item
        elif isinstance(value, Mapping):
            for nested_key in ("items", "clients", "connected", "users", "data", "list"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    for item in nested:
                        if isinstance(item, Mapping):
                            yield item
            for item in value.values():
                if isinstance(item, Mapping):
                    yield item


def _collect_vpn_connected_clients_details(
    raw: Mapping[str, Any]
) -> List[Dict[str, str]]:
    details: List[Dict[str, str]] = []
    for client in _iter_connected_client_records(raw):
        name = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "name",
                    "display_name",
                    "user-name",
                    "user_name",
                    "username",
                    "user",
                    "identity",
                    "client_name",
                    "description",
                    "peer",
                ),
            )
        )
        source_ip = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "source_ip",
                    "remote_ip",
                    "remoteIP",
                    "remote_addr",
                    "remoteAddr",
                    "public_ip",
                    "wan_ip",
                    "peer_ip",
                    "peer_addr",
                    "ip_address",
                    "internet_ip",
                    "src_ip",
                ),
            )
        )
        source_ipv6 = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "source_ipv6",
                    "sourceIPV6",
                    "source_ip6",
                    "remote_ipv6",
                    "remoteIPV6",
                    "remote_ipv6_address",
                    "remoteIPv6Address",
                    "remote_addr_ipv6",
                    "remote_addr6",
                    "public_ipv6",
                    "publicIPV6",
                    "wan_ipv6",
                    "peer_ipv6",
                    "peerIPv6",
                    "ip_address_v6",
                    "internet_ipv6",
                    "src_ipv6",
                    "ipv6",
                    "ip6",
                    "ip_v6",
                ),
            )
        )
        internal_ip = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "internal_ip",
                    "client_ip",
                    "assigned_ip",
                    "ip",
                    "local_ip",
                    "tunnel_ip",
                    "network_ip",
                    "lan_ip",
                ),
            )
        )
        internal_ipv6 = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "internal_ipv6",
                    "internalIPV6",
                    "internal_ip6",
                    "client_ipv6",
                    "clientIPV6",
                    "assigned_ipv6",
                    "assignedIPV6",
                    "ip_v6",
                    "ipv6",
                    "ip6",
                    "local_ipv6",
                    "localIPV6",
                    "local_ip6",
                    "tunnel_ipv6",
                    "vpn_ipv6",
                    "lan_ipv6",
                ),
            )
        )
        country = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "country",
                    "country_name",
                    "geoip_country",
                    "countryCode",
                    "country_code",
                ),
            )
        )
        city = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "city",
                    "geoip_city",
                    "town",
                    "region",
                ),
            )
        )
        isp = _normalize_client_field(
            _extract_nested_value(
                client,
                (
                    "isp",
                    "isp_name",
                    "organization",
                    "org",
                    "ispOrg",
                    "isp_org",
                    "isp_provider",
                ),
            )
        )

        lookup_candidates: List[str] = []
        if source_ip and source_ip != "Unknown":
            lookup_candidates.append(source_ip)
        if source_ipv6 and source_ipv6 != "Unknown":
            lookup_candidates.append(source_ipv6)

        for lookup_ip in lookup_candidates:
            city, country, isp = _enrich_remote_ip_details(
                lookup_ip, city, country, isp
            )
            if (
                city not in (None, "Unknown")
                and country not in (None, "Unknown")
                and isp not in (None, "Unknown")
            ):
                break

        details.append(
            {
                "name": name,
                "source_ip": source_ip,
                "source_ipv6": source_ipv6,
                "internal_ip": internal_ip,
                "internal_ipv6": internal_ipv6,
                "country": country,
                "city": city,
                "isp": isp,
            }
        )

    return details


def _render_connected_clients_html(clients: Iterable[Mapping[str, str]]) -> str:
    table_open = (
        '<table width="100%" border="1" '
        'style="border: 1px black solid; border-collapse: collapse;">'
    )
    rows: List[str] = []
    for client in clients:
        remote_ipv6 = client.get("source_ipv6", "")
        remote_ip_parts: List[str] = []
        remote_ip_value = client.get("source_ip", "")
        escaped_remote_ip = html.escape(remote_ip_value)
        if escaped_remote_ip:
            remote_ip_parts.append(escaped_remote_ip)
        if remote_ipv6 and remote_ipv6 != "Unknown":
            remote_ip_parts.append(
                f"<span style=\"font-size: 0.9em; color: #555;\">{html.escape(remote_ipv6)}" "</span>"
            )
        remote_ip_cell = "<br>".join(remote_ip_parts)

        internal_ip_parts: List[str] = []
        internal_ip_value = client.get("internal_ip", "")
        escaped_internal_ip = html.escape(internal_ip_value)
        if escaped_internal_ip:
            internal_ip_parts.append(escaped_internal_ip)

        internal_ipv6_value = client.get("internal_ipv6", "")
        if internal_ipv6_value and internal_ipv6_value != "Unknown":
            internal_ip_parts.append(
                f"<span style=\"font-size: 0.9em; color: #555;\">{html.escape(internal_ipv6_value)}" "</span>"
            )
        internal_ip_cell = "<br>".join(internal_ip_parts)

        rows.append(
            "<tr>"
            f"<td style=\"padding: 4px; text-align: left;\">{html.escape(client.get('name', ''))}</td>"
            f"<td style=\"padding: 4px; text-align: right;\">{remote_ip_cell}</td>"
            f"<td style=\"padding: 4px; text-align: right;\">{internal_ip_cell}</td>"
            f"<td style=\"padding: 4px; text-align: left;\">{html.escape(client.get('country', ''))}</td>"
            f"<td style=\"padding: 4px; text-align: left;\">{html.escape(client.get('city', ''))}</td>"
            f"<td style=\"padding: 4px; text-align: left;\">{html.escape(client.get('isp', ''))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            "<tr><td style=\"padding: 4px; text-align: center;\" colspan=\"6\">"
            "No connected clients"
            "</td></tr>"
        )

    header = (
        "<tr>"
        "<th style=\"padding: 4px; text-align: left;\">Client</th>"
        "<th style=\"padding: 4px; text-align: right;\">Remote IP</th>"
        "<th style=\"padding: 4px; text-align: right;\">Internal Addresses</th>"
        "<th style=\"padding: 4px; text-align: left;\">Country</th>"
        "<th style=\"padding: 4px; text-align: left;\">City</th>"
        "<th style=\"padding: 4px; text-align: left;\">ISP</th>"
        "</tr>"
    )

    return f"{table_open}{header}{''.join(rows)}</table>"


def _prepare_connected_clients_output(raw: Mapping[str, Any]) -> Tuple[List[str], str]:
    details = _collect_vpn_connected_clients_details(raw)
    formatted: List[str] = []
    for client in details:
        formatted.append(
            "{} ~ {} | {} | {} | {} | {} | {} | {}".format(
                client["name"],
                client["source_ip"],
                client["source_ipv6"],
                client["internal_ip"],
                client["internal_ipv6"],
                client["country"],
                client["city"],
                client["isp"],
            )
        )
    return formatted, _render_connected_clients_html(details)


def _format_vpn_connected_clients(raw: Mapping[str, Any]) -> List[str]:
    formatted, _ = _prepare_connected_clients_output(raw)
    return formatted


def _parse_datetime_24h(value: Any) -> Optional[str]:
    """Parse datetime and return in 24h format."""
    if value in (None, ""):
        return None

    dt_value: Optional[datetime] = None
    try:
        if isinstance(value, datetime):
            dt_value = value
        elif isinstance(value, (int, float)):
            number = float(value)
            if number > 1e11:  # Convert from milliseconds if needed
                number /= 1000.0
            dt_value = datetime.fromtimestamp(number, tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                number = float(text)
                if number > 1e11:
                    number /= 1000.0
                dt_value = datetime.fromtimestamp(number, tz=timezone.utc)
            except ValueError:
                dt_value = dt_util.parse_datetime(text)
    except (OverflowError, OSError, ValueError):
        return None

    if dt_value is None:
        return None

    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=timezone.utc)
    local_dt = dt_util.as_local(dt_value)
    return local_dt.strftime("%Y-%m-%d %H:%M:%S")


class UniFiGatewaySensorBase(
    CoordinatorEntity[UniFiGatewayData], SensorEntity
):
    """Base entity for UniFi Gateway sensors."""

    _attr_should_poll = False

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        unique_id: str,
        name: str,
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(coordinator)
        self._client = client
        self._attr_unique_id = unique_id
        self._attr_name = name
        self._default_icon = getattr(self, "_attr_icon", None)
        self._device_name = device_name or self._derive_device_name()
        self._last_signature: Any | None = None

    def _derive_device_name(self) -> str:
        site = self._client.get_site()
        if site:
            return f"UniFi Gateway ({site})"
        return "UniFi Gateway"

    def _controller_attrs(self) -> Dict[str, Any]:
        data = self.coordinator.data
        if not data:
            return {}
        return {
            "controller_ui": data.controller.get("url"),
            "controller_api": data.controller.get("api_url"),
            "controller_site": data.controller.get("site"),
        }

    @property
    def device_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
        }
        try:
            info["configuration_url"] = self._client.get_controller_url()
        except Exception:  # pragma: no cover - guard against unexpected client errors
            pass
        return info

    def _state_signature(self) -> Any:
        native = self.native_value
        attrs = self.extra_state_attributes
        icon = getattr(self, "icon", None)
        available = self.available
        return (
            _freeze_state(native),
            _freeze_state(attrs) if attrs is not None else None,
            icon,
            available,
        )

    def _handle_coordinator_update(self) -> None:
        signature = self._state_signature()
        if signature == self._last_signature and self._last_signature is not None:
            return
        self._last_signature = signature
        self.async_write_ha_state()


class UniFiGatewayWanSensorBase(UniFiGatewaySensorBase):
    """Common logic for WAN-related sensors."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        link: Dict[str, Any],
        suffix: str,
        name_suffix: str = "",
        *,
        device_name: Optional[str] = None,
    ) -> None:
        self._entry_id = entry_id
        self._link_id = str(link.get("id") or link.get("_id") or link.get("ifname") or "wan")
        self._link_name = link.get("name") or self._link_id
        self._identifiers = _wan_identifier_candidates(
            self._link_id, self._link_name, link
        )
        canonical = (sorted(self._identifiers) or [self._link_id])[0]
        self._uid_source = canonical
        unique_id = build_wan_unique_id(entry_id, link, suffix)
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"WAN {self._link_name}{name_suffix}",
            device_name=device_name,
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
        *,
        device_name: Optional[str] = None,
        wifi_overrides: Optional[Mapping[str, Optional[str]]] = None,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_{subsystem}"
        super().__init__(
            coordinator,
            client,
            unique_id,
            label,
            device_name=device_name,
        )
        self._subsystem = subsystem
        self._attr_icon = icon
        self._default_icon = icon
        overrides = wifi_overrides or {}
        self._wifi_guest_name = _normalize_wifi_name(overrides.get("guest"))
        self._wifi_iot_name = _normalize_wifi_name(overrides.get("iot"))

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
            count_sources: Dict[str, Iterable[str]] = {
                "num_user": (
                    "num_user",
                    "user",
                    "users",
                    "num_sta",
                    "sta",
                    "clients",
                ),
                "num_guest": ("num_guest", "guest", "guests", "user_guest"),
                "num_iot": ("num_iot", "user_iot", "iot", "users_iot"),
            }
            normalized_counts: Dict[str, int] = {
                key: 0 for key in count_sources
            }
            for target, keys in count_sources.items():
                count = _resolve_client_count_from_record(record, keys)
                if count is None:
                    continue
                normalized_counts[target] = count
            for target, value in normalized_counts.items():
                attrs[target] = value
            attrs["user"] = normalized_counts["num_user"]
            attrs["user_guest"] = normalized_counts["num_guest"]
            attrs["user_iot"] = normalized_counts["num_iot"]
            total = sum(normalized_counts.values())
            attrs["num_user_total"] = total
            attrs["user_total"] = total
        override_counts = None
        if self._subsystem == "wlan":
            override_counts = self._compute_wlan_user_counts()
        if override_counts is not None:
            attrs["num_user"] = override_counts["num_user"]
            attrs["user"] = override_counts["num_user"]
            attrs["num_guest"] = override_counts["guest"]
            attrs["user_guest"] = override_counts["guest"]
            attrs["num_iot"] = override_counts["iot"]
            attrs["user_iot"] = override_counts["iot"]
            attrs["num_user_total"] = override_counts["total"]
            attrs["user_total"] = override_counts["total"]
        if self._subsystem == "wan":
            data = self.coordinator.data
            ipv6_value: Optional[str] = None
            if record:
                ipv6_value = _value_from_record(record, _WAN_IPV6_KEYS)
            if not ipv6_value and data:
                for link in data.wan_links:
                    ipv6_value = _value_from_record(link, _WAN_IPV6_KEYS)
                    if ipv6_value:
                        break
                if not ipv6_value:
                    for health_record in data.wan_health:
                        ipv6_value = _value_from_record(health_record, _WAN_IPV6_KEYS)
                        if ipv6_value:
                            break
            attrs["ipv6"] = ipv6_value
        attrs.update(self._controller_attrs())
        return attrs

    def _compute_wlan_user_counts(self) -> Optional[Dict[str, int]]:
        if not (self._wifi_guest_name or self._wifi_iot_name):
            return None

        data = self.coordinator.data
        if not data:
            return None

        summary = _summarize_wlan_clients(data)
        guest_count, _guest_key = _resolve_wlan_user_count(
            summary, self._wifi_guest_name
        )
        iot_count, _iot_key = _resolve_wlan_user_count(summary, self._wifi_iot_name)
        num_user = summary.total - guest_count - iot_count
        total = guest_count + iot_count + num_user
        return {
            "num_user": num_user,
            "guest": guest_count,
            "iot": iot_count,
            "total": total,
        }



class UniFiGatewayAlertsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:information-outline"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        *,
        device_name: Optional[str] = None,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_alerts"
        super().__init__(
            coordinator,
            client,
            unique_id,
            "Alerts",
            device_name=device_name,
        )

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


class UniFiGatewayVpnUsageSensor(SensorEntity):
    """Sensor providing VPN client counts with enhanced detection."""

    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_should_poll = True

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        base_name: str,
        server: Dict[str, Any],
        linked_network: Dict[str, Any],
        *,
        unique_id: str,
    ) -> None:
        self._coordinator = coordinator
        self._client = client
        self._base_name = base_name
        self._server = server
        self._linked_network = linked_network or {}
        self._attr_unique_id = unique_id

        self._srv_id = server.get("id")
        self._srv_name = server.get("name") or "VPN"
        self._linked_net_id = (
            server.get("linked_network_id")
            or self._linked_network.get("_id")
            or self._linked_network.get("id")
        )
        self._subnet = (
            self._linked_network.get("subnet")
            or self._linked_network.get("ip_subnet")
            or self._linked_network.get("cidr")
            or self._server.get("_raw", {}).get("tunnel_network")
            or self._server.get("_raw", {}).get("subnet")
        )
        self._ip_network = None
        if self._subnet:
            try:
                self._ip_network = ipaddress.ip_network(self._subnet, strict=False)
            except ValueError:
                self._ip_network = None

        vpn_type_raw = (
            self._server.get("vpn_type")
            or self._linked_network.get("vpn_type")
            or "Unknown"
        )
        protocol_type, mode = _parse_protocol_and_mode(vpn_type_raw)

        self._attr_name = f"VPN {vpn_type_raw} {self._srv_name}"
        self._state: Optional[int] = None
        self._attrs: Dict[str, Any] = {
            "family": "VPN",
            "type": "VPN",
            "vpn_type": vpn_type_raw,
            "protocol_type": protocol_type,
            "mode": mode,
            "vpn_name": self._srv_name,
            "linked_network_id": self._linked_net_id,
            "debug_v2_filter": {
                "network_id": self._linked_net_id,
                "status": "online",
            },
            "instance": base_name,
        }
        self._apply_network_overrides()
        self._connected_clients: List[str] = []
        self._connected_clients_html: Optional[str] = None
        self._connected_clients_signature: Any | None = None

    def _apply_network_overrides(self) -> None:
        raw = self._linked_network if isinstance(self._linked_network, dict) else {}
        if not raw:
            return

        if raw.get("vpn_type"):
            proto, mode = _parse_protocol_and_mode(raw.get("vpn_type"))
            self._attrs["vpn_type"] = raw["vpn_type"]
            self._attrs["protocol_type"] = proto
            self._attrs["mode"] = mode
            self._attr_name = f"VPN {raw['vpn_type']} {self._srv_name}"

        if "purpose" in raw or "role" in raw:
            self._attrs["purpose"] = raw.get("purpose") or raw.get("role")

        for key in ("local_port", "listen_port", "port", "openvpn_port"):
            if raw.get(key) is not None:
                self._attrs["local_port"] = raw.get(key)
                break

        wan_ip = raw.get("wan_ip") or raw.get("local_wan_ip")
        if not wan_ip:
            for key, value in raw.items():
                if isinstance(key, str) and key.endswith("_local_wan_ip") and value:
                    wan_ip = value
                    break
        if wan_ip:
            self._attrs["wan_ip"] = wan_ip

        if "enabled" in raw:
            self._attrs["enabled"] = raw.get("enabled")

    def _resolve_network_subnet(self) -> Optional[str]:
        if self._subnet:
            return self._subnet

        data = self._coordinator.data if self._coordinator else None
        if not data:
            return None

        net_id = str(self._linked_net_id) if self._linked_net_id else None
        if net_id:
            candidate = data.network_map.get(net_id)
            if candidate and candidate.get("subnet"):
                self._subnet = candidate["subnet"]
                if not self._ip_network:
                    self._ip_network = _to_ip_network(self._subnet)
                return self._subnet

        if net_id:
            for network in data.networks:
                candidate_id = network.get("_id") or network.get("id")
                if candidate_id and str(candidate_id) == net_id:
                    for key in ("subnet", "ip_subnet", "cidr"):
                        value = network.get(key)
                        if value:
                            self._subnet = value
                            if not self._ip_network:
                                self._ip_network = _to_ip_network(value)
                            return value
                    break

        return None

    def _controller_attrs(self) -> Dict[str, Any]:
        data = self._coordinator.data if self._coordinator else None
        if data and isinstance(data.controller, dict):
            return {
                "controller_ui": data.controller.get("url"),
                "controller_api": data.controller.get("api_url"),
                "controller_site": data.controller.get("site"),
            }
        return {
            "controller_ui": self._client.get_controller_url(),
            "controller_api": self._client.get_controller_api_url(),
            "controller_site": self._client.get_site(),
        }

    @property
    def name(self) -> Optional[str]:
        return self._attr_name

    @property
    def icon(self) -> str:
        proto = str(self._attrs.get("protocol_type") or "").lower()
        mapping = {
            "openvpn": "selfhst:openvpn",
            "wireguard": "selfhst:wireguard",
            "ipsec": "selfhst:ipsec",
            "ikev2": "selfhst:ipsec",
            "l2tp": "selfhst:ipsec",
            "l2tp-ipsec": "selfhst:ipsec",
            "pptp": "selfhst:pptp",
            "sstp": "selfhst:sstp",
            "gre": "mdi:lock",
        }
        return mapping.get(proto, "mdi:lock")

    @property
    def native_value(self) -> Optional[int]:
        return self._state

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        attrs = dict(self._attrs)
        attrs.update(self._controller_attrs())
        subnet_value = self._resolve_network_subnet()
        if subnet_value:
            attrs["subnet"] = subnet_value
        attrs["connected_clients"] = list(self._connected_clients)
        if self._connected_clients_html is not None:
            attrs["connected_clients_html"] = self._connected_clients_html
        return attrs

    @property
    def extra_state_attribute_names(self) -> Dict[str, str]:
        return {
            "connected_clients": "Connected Clients",
            "connected_clients_html": "Connected Clients HTML",
        }

    @property
    def device_info(self) -> Dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._base_name,
        }

    @Throttle(VPN_MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        now_ts = time.time()
        count = 0
        v2_total = 0
        v2_for_net = 0
        connected_records: List[Dict[str, Any]] = []

        try:
            clients_v2 = self._client.get_active_clients_v2()
            v2_total = len(clients_v2)
            target = str(self._linked_net_id) if self._linked_net_id else None
            filtered_clients: List[Dict[str, Any]] = []
            for client in clients_v2:
                if not isinstance(client, Mapping):
                    continue
                if target and str(client.get("network_id")) != target:
                    continue
                status = str(client.get("status", "")).lower()
                if status == "online" or client.get("is_online") is True or client.get("online") is True:
                    filtered_clients.append(dict(client))
            v2_for_net = len(filtered_clients)
            connected_records = filtered_clients
            count = v2_for_net
        except (APIError, ConnectivityError) as err:
            _LOGGER.debug("Active clients v2 fetch failed for VPN %s: %s", self._srv_name, err)

        if count == 0:
            try:
                leases = self._client.get_dhcp_leases()
            except (APIError, ConnectivityError) as err:
                leases = []
                _LOGGER.debug("DHCP leases fetch failed for VPN %s: %s", self._srv_name, err)
            lease_matches: List[Dict[str, Any]] = []
            for lease in leases or []:
                if not isinstance(lease, Mapping):
                    continue
                try:
                    if not self._client._lease_is_active(lease, now_ts):
                        continue
                except Exception:
                    continue
                lease_ip = lease.get("ip") or lease.get("lease_ip") or lease.get("assigned_ip")
                lease_network = (
                    lease.get("network_id")
                    or lease.get("networkconf_id")
                    or lease.get("network")
                )
                matched = False
                if self._linked_net_id and str(lease_network) == str(self._linked_net_id):
                    matched = True
                if self._ip_network and lease_ip:
                    try:
                        if ipaddress.ip_address(lease_ip) in self._ip_network:
                            matched = True
                    except ValueError:
                        continue
                if matched:
                    normalized = dict(lease)
                    if lease_ip and not normalized.get("assigned_ip"):
                        normalized.setdefault("assigned_ip", lease_ip)
                    lease_matches.append(normalized)
            if lease_matches:
                connected_records = lease_matches
                count = len(lease_matches)

        if count == 0:
            try:
                session_map = self._client.get_vpn_active_sessions_map()
            except (APIError, ConnectivityError) as err:
                session_map = {"by_server": {}, "by_net": {}}
                _LOGGER.debug("VPN session fetch failed for %s: %s", self._srv_name, err)
            by_server = session_map.get("by_server", {})
            by_net = session_map.get("by_net", {})
            if self._srv_id and str(self._srv_id) in by_server:
                count = by_server[str(self._srv_id)]
            elif self._linked_net_id and str(self._linked_net_id) in by_net:
                count = by_net[str(self._linked_net_id)]

        if count == 0:
            try:
                legacy_clients = self._client.get_clients()
            except (APIError, ConnectivityError) as err:
                legacy_clients = []
                _LOGGER.debug("Legacy clients fetch failed for VPN %s: %s", self._srv_name, err)
            legacy_matches: List[Dict[str, Any]] = []
            for client in legacy_clients or []:
                if not isinstance(client, Mapping):
                    continue
                if not self._client.is_client_active(client, now_ts):
                    continue
                matched = False
                if self._linked_net_id and str(client.get("network_id")) == str(self._linked_net_id):
                    matched = True
                if self._ip_network and client.get("ip"):
                    try:
                        if ipaddress.ip_address(client["ip"]) in self._ip_network:
                            matched = True
                    except ValueError:
                        continue
                if matched:
                    legacy_matches.append(dict(client))
            if legacy_matches:
                connected_records = legacy_matches
                count = len(legacy_matches)

        self._state = count
        self._attrs["debug_v2_seen_total"] = v2_total
        self._attrs["Online users"] = v2_for_net
        self._update_connected_clients(connected_records)

    async def async_update(self) -> None:
        if self.hass is None:
            return
        await self.hass.async_add_executor_job(self.update)

    def _update_connected_clients(
        self, primary_records: Optional[Iterable[Mapping[str, Any]]] = None
    ) -> None:
        raw_payload: Optional[Mapping[str, Any]] = None

        if primary_records:
            prepared: List[Mapping[str, Any]] = []
            for record in primary_records:
                if isinstance(record, Mapping):
                    prepared.append(record)
            if prepared:
                raw_payload = {"connected_clients": prepared}

        if raw_payload is not None:
            signature = _freeze_state(raw_payload)
            if (
                signature == self._connected_clients_signature
                and self._connected_clients_html is not None
            ):
                return
            formatted, html_value = _prepare_connected_clients_output(raw_payload)
            self._connected_clients = formatted
            self._connected_clients_html = html_value
            self._connected_clients_signature = signature
            return

        try:
            servers = self._client.get_vpn_servers()
        except (APIError, ConnectivityError) as err:
            _LOGGER.debug(
                "Fetching VPN server clients failed for %s: %s", self._srv_name, err
            )
            if (
                self._connected_clients_signature is None
                or self._connected_clients_html is None
            ):
                self._connected_clients = []
                self._connected_clients_html = _render_connected_clients_html([])
                self._connected_clients_signature = ("empty",)
            return

        target_id = str(self._srv_id) if self._srv_id is not None else None
        target_link = str(self._linked_net_id) if self._linked_net_id is not None else None

        fallback_raw: Optional[Mapping[str, Any]] = None
        for server in servers:
            raw = server.get("_raw") if isinstance(server, Mapping) else None
            if not isinstance(raw, Mapping):
                continue

            server_id = server.get("id") if isinstance(server, Mapping) else None
            linked_id = server.get("linked_network_id") if isinstance(server, Mapping) else None

            if target_id is not None and server_id is not None and str(server_id) == target_id:
                signature = _freeze_state(raw)
                if (
                    signature == self._connected_clients_signature
                    and self._connected_clients_html is not None
                ):
                    return
                formatted, html_value = _prepare_connected_clients_output(raw)
                self._connected_clients = formatted
                self._connected_clients_html = html_value
                self._connected_clients_signature = signature
                return

            if (
                target_link is not None
                and linked_id is not None
                and str(linked_id) == target_link
            ):
                fallback_raw = raw
                continue

            if fallback_raw is None and target_link is None and target_id is None:
                fallback_raw = raw

        if fallback_raw is not None:
            signature = _freeze_state(fallback_raw)
            if (
                signature == self._connected_clients_signature
                and self._connected_clients_html is not None
            ):
                return
            formatted, html_value = _prepare_connected_clients_output(fallback_raw)
            self._connected_clients = formatted
            self._connected_clients_html = html_value
            self._connected_clients_signature = signature
            return

        signature = ("empty",)
        if (
            signature == self._connected_clients_signature
            and self._connected_clients_html is not None
        ):
            return
        self._connected_clients = []
        self._connected_clients_html = _render_connected_clients_html([])
        self._connected_clients_signature = signature



class UniFiGatewayFirmwareSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:database-plus"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        *,
        device_name: Optional[str] = None,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_firmware"
        super().__init__(
            coordinator,
            client,
            unique_id,
            "Firmware Upgradable",
            device_name=device_name,
        )

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
        link: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            entry_id,
            link,
            "status",
            device_name=device_name,
        )
        self._default_icon = getattr(self, "_attr_icon", None)
        self._last_status: Optional[str] = None
        self._last_status_source: Optional[str] = None

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @staticmethod
    def _normalize_status(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            return "UP" if float(value) > 0 else "DOWN"
        text = str(value).strip()
        if not text:
            return None
        lowered = text.lower()
        mapping: Dict[str, str] = {
            "ok": "OK",
            "normal": "OK",
            "good": "OK",
            "up": "UP",
            "online": "UP",
            "connected": "UP",
            "active": "UP",
            "running": "UP",
            "ready": "UP",
            "down": "DOWN",
            "offline": "DOWN",
            "disconnected": "DOWN",
            "error": "DOWN",
            "fail": "DOWN",
            "failed": "DOWN",
            "inactive": "DOWN",
            "standby": "STANDBY",
            "backup": "STANDBY",
            "secondary": "STANDBY",
        }
        if lowered in mapping:
            return mapping[lowered]
        if lowered.startswith("wan_"):
            return lowered.split("_", 1)[1].upper()
        return text.upper()

    def _determine_status(self) -> Tuple[Optional[str], Optional[str]]:
        link = self._link()
        status = _value_from_record(
            link,
            (
                "status",
                "state",
                "link_state",
                "value",
                "status_text",
                "wan_status",
            ),
        )
        normalized = self._normalize_status(status)
        if normalized:
            return normalized, "wan_link"

        health = self._wan_health_record()
        status = _value_from_record(
            health,
            (
                "status",
                "state",
                "status_text",
                "wan_status",
                "availability",
            ),
        )
        normalized = self._normalize_status(status)
        if normalized:
            return normalized, "wan_health"
        return None, None

    @property
    def native_value(self) -> Optional[Any]:
        status, source = self._determine_status()
        if status:
            self._last_status = status
            self._last_status_source = source
            return status
        return self._last_status

    @property
    def icon(self) -> Optional[str]:
        status = str((self._last_status or self.native_value or "")).lower()
        if status in {"up", "ok", "connected", "online"}:
            return "mdi:check-circle"
        if status in {"down", "error", "fail", "disconnected", "offline"}:
            return "mdi:alert-circle"
        return self._default_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link()
        health = self._wan_health_record()
        link_dict = link or {}
        health_dict = health or {}
        ip, ip_source = _extract_wan_value_with_source(link, health, _WAN_IPV4_KEYS)
        ipv6, ipv6_source = _extract_wan_value_with_source(
            link, health, _WAN_IPV6_KEYS
        )
        attrs = {
            "name": self._link_name,
            "type": link_dict.get("type") or link_dict.get("kind"),
            "isp": _value_from_record(
                link_dict,
                ("isp", "provider", "isp_name", "organization"),
            ),
            "ip": ip,
            "ip_source": ip_source,
        }
        attrs["ipv6"] = ipv6
        attrs["ipv6_source"] = ipv6_source
        if not attrs.get("isp"):
            attrs["isp"] = _value_from_record(
                health_dict,
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
                health_dict,
                ("wan_ip", "internet_ip", "ip", "public_ip", "external_ip"),
            )
        attrs["gateway_ip"] = _value_from_record(
            health_dict,
            ("gateway_ip", "wan_gateway", "gw_ip", "gateway"),
        )
        last_update_raw = _value_from_record(
            health_dict,
            ("datetime", "time", "last_seen", "last_update", "updated_at"),
        )
        attrs["last_update"] = _parse_datetime_24h(last_update_raw)
        attrs["last_update_raw"] = last_update_raw
        attrs["uptime"] = _value_from_record(
            health_dict,
            ("uptime", "uptime_status", "wan_uptime", "uptime_seconds"),
        )
        attrs["status_source"] = self._last_status_source
        attrs["status_normalized"] = self._last_status
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIpSensor(UniFiGatewayWanSensorBase):
    _attr_icon = "mdi:ip"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        link: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            entry_id,
            link,
            "ip",
            " IP",
            device_name=device_name,
        )
        self._last_ip: Optional[str] = None
        self._last_source: Optional[str] = None

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @property
    def native_value(self) -> Optional[str]:
        link = self._link()
        health = self._wan_health_record()
        ip, source = _extract_wan_value_with_source(link, health, _WAN_IPV4_KEYS)
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
        link = self._link()
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
            "ipv6": _extract_wan_value(link, health, _WAN_IPV6_KEYS),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIpv6Sensor(UniFiGatewayWanSensorBase):
    _attr_icon = "mdi:ip-network"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        entry_id: str,
        link: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            entry_id,
            link,
            "ipv6",
            " IPv6",
            device_name=device_name,
        )
        self._last_ipv6: Optional[str] = None
        self._last_source: Optional[str] = None

    def _wan_health_record(self) -> Optional[Dict[str, Any]]:
        return _find_wan_health_record(self.coordinator.data, self._identifiers)

    @property
    def native_value(self) -> Optional[str]:
        link = self._link()
        health = self._wan_health_record()
        ipv6, source = _extract_wan_value_with_source(link, health, _WAN_IPV6_KEYS)
        if ipv6:
            if source == "wan_link":
                normalized_source = "link"
            elif source == "wan_health":
                normalized_source = "health"
            else:
                normalized_source = source or "unknown"
            self._last_ipv6 = ipv6
            self._last_source = normalized_source
            return ipv6
        if self._last_ipv6:
            self._last_source = "cached"
            return self._last_ipv6
        return None

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link()
        health = self._wan_health_record() or {}
        attrs = {
            "last_ipv6": self._last_ipv6,
            "source": self._last_source or ("cached" if self._last_ipv6 else None),
            "gateway_ipv6": _extract_wan_value(link, health, _WAN_GATEWAY_IPV6_KEYS),
            "prefix": _extract_wan_value(link, health, _WAN_IPV6_PREFIX_KEYS),
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
        link: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            entry_id,
            link,
            "isp",
            " ISP",
            device_name=device_name,
        )
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
        network: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        self._network = network
        self._lan_key = lan_interface_key(network)
        self._network_id = str(network.get("_id") or network.get("id") or network.get("name"))
        self._network_name = network.get("name") or f"VLAN {network.get('vlan')}"
        self._subnet = (
            network.get("subnet")
            or network.get("ip_subnet")
            or network.get("cidr")
        )
        self._ip_network = _to_ip_network(self._subnet)
        self._last_client_count: Optional[int] = None
        self._last_ip_leases: Optional[int] = None
        unique_id = build_lan_unique_id(entry_id, network)
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"LAN {self._network_name}",
            device_name=device_name,
        )

    def _current_network(self) -> Dict[str, Any]:
        data = self.coordinator.data
        if data:
            for candidate in data.lan_networks:
                if lan_interface_key(candidate) == self._lan_key:
                    self._network = candidate
                    break
        return self._network

    def _matches_client(self, client: Dict[str, Any]) -> bool:
        if str(client.get("network_id")) == self._network_id:
            return True
        network_name = client.get("network")
        if (
            isinstance(network_name, str)
            and isinstance(self._network_name, str)
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

    def _refresh_client_stats(self) -> tuple[int, int]:
        total = 0
        leases = 0
        for client in self._clients():
            if not self._matches_client(client):
                continue
            total += 1
            if client.get("ip"):
                leases += 1
        self._last_client_count = total
        self._last_ip_leases = leases
        return total, leases

    @property
    def native_value(self) -> Optional[int]:
        total, _ = self._refresh_client_stats()
        return total

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        if self._last_client_count is None or self._last_ip_leases is None:
            self._refresh_client_stats()

        leases = self._last_ip_leases or 0
        network = self._current_network() or {}
        subnet = (
            network.get("subnet")
            or network.get("ip_subnet")
            or network.get("cidr")
            or self._subnet
        )
        vlan_id = network.get("vlan") if network else None
        ip_address = _extract_network_ip_address(network, version=4)
        if not ip_address:
            ip_address = _extract_network_ip_address(network)
        if not ip_address:
            ip_address = _extract_ip_from_value(subnet, version=4)
        if not ip_address:
            ip_address = _extract_ip_from_value(subnet)
        ipv6_address = _extract_network_ip_address(network, version=6)
        if not ipv6_address:
            ipv6_address = _extract_ip_from_value(subnet, version=6)
        if vlan_id is None:
            vlan_id = self._network.get("vlan")
        attrs = {
            "network_id": self._network_id,
            "subnet": subnet,
            "vlan_id": vlan_id,
            "ip_address": ip_address,
            "ipv6_address": ipv6_address,
            "client_count": self._last_client_count,
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
        wlan: Dict[str, Any],
        *,
        device_name: Optional[str] = None,
    ) -> None:
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        unique_id = build_wlan_unique_id(entry_id, wlan)
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"WLAN {self._ssid}",
            device_name=device_name,
        )

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
        ipv6_address = None
        if network:
            ipv6_address = _extract_network_ip_address(network, version=6)
        if not ipv6_address:
            for key in (
                "ipv6_address",
                "ipv6_interface",
                "ipv6",
                "ip6",
                "inet6",
                "wan_ipv6",
            ):
                ipv6_address = _extract_ip_from_value(
                    self._wlan.get(key), version=6
                )
                if ipv6_address:
                    break
        attrs["ipv6_address"] = ipv6_address
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewaySpeedtestSensor(UniFiGatewaySensorBase):
    """Base speedtest sensor with improved status handling."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        suffix: str,
        name: str,
        *,
        device_name: Optional[str] = None,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_speedtest_{suffix}"
        super().__init__(
            coordinator,
            client,
            unique_id,
            name,
            device_name=device_name,
        )

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        """Return enhanced speedtest attributes."""
        data = self.coordinator.data
        record = data.speedtest if data else None
        
        attrs = {
            "source": record.get("source") if record else None,
            "last_run": _parse_datetime_24h(record.get("rundate") if record else None),
            "server": record.get("server_name") if record else None,
            "status": self._get_speedtest_status(record),
        }

        if record:
            server_details: Dict[str, Any] = {}

            raw_server = record.get("server")
            if raw_server not in (None, "", {}):
                server_details["server_raw"] = raw_server

            for key, value in record.items():
                if not key.startswith("server_"):
                    continue
                if value in (None, "", [], {}):
                    continue
                server_details[key] = value

            if "server_location" not in server_details:
                for fallback_key in ("server_city", "server_region"):
                    if fallback_key in server_details:
                        server_details["server_location"] = server_details[fallback_key]
                        break

            if "server_sponsor" not in server_details and "server_provider" in server_details:
                server_details["server_sponsor"] = server_details["server_provider"]

            attrs.update(server_details)

        attrs.update(self._controller_attrs())
        return attrs

    def _get_speedtest_status(self, record: Optional[Dict[str, Any]]) -> str:
        """Get normalized speedtest status."""
        if not record:
            return "unknown"
        
        status = record.get("status", "")
        if not status:
            return "unknown"
            
        status = str(status).lower()
        if "error" in status or "fail" in status:
            return "error"
        if "progress" in status or "running" in status:
            return "running"
        if "success" in status or "complete" in status:
            return "success"
            
        return status


class UniFiGatewaySpeedtestDownloadSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-download"
    _attr_native_unit_of_measurement = "Mbps"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            "down",
            "Speedtest Download",
            device_name=device_name,
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
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            "up",
            "Speedtest Upload",
            device_name=device_name,
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
        *,
        device_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            coordinator,
            client,
            "ping",
            "Speedtest Ping",
            device_name=device_name,
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


def _extract_ip_from_value(value: Any, *, version: Optional[int] = None) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        if "/" in candidate:
            try:
                interface = ipaddress.ip_interface(candidate)
                if version and interface.ip.version != version:
                    return None
                return str(interface.ip)
            except ValueError:
                pass
            prefix, _, _ = candidate.partition("/")
            try:
                parsed = ipaddress.ip_address(prefix.strip())
                if version and parsed.version != version:
                    return None
                return str(parsed)
            except ValueError:
                return None
        try:
            parsed = ipaddress.ip_address(candidate)
            if version and parsed.version != version:
                return None
            return str(parsed)
        except ValueError:
            return None
    if isinstance(value, (list, tuple)):
        for item in value:
            result = _extract_ip_from_value(item, version=version)
            if result:
                return result
        return None
    if isinstance(value, dict):
        for key in ("ip", "address", "gateway", "value"):
            result = _extract_ip_from_value(value.get(key), version=version)
            if result:
                return result
        return None
    return None


def _extract_network_ip_address(
    network: Dict[str, Any], *, version: Optional[int] = None
) -> Optional[str]:
    if not isinstance(network, dict):
        return None
    for key in (
        "gateway",
        "gateway_ip",
        "router_ip",
        "dhcpd_gateway",
        "ip",
        "ip_address",
        "wan_ip",
        "wan_gateway",
    ):
        result = _extract_ip_from_value(network.get(key), version=version)
        if result:
            return result
    for key in ("subnet", "ip_subnet", "cidr"):
        result = _extract_ip_from_value(network.get(key), version=version)
        if result:
            return result
    return None
