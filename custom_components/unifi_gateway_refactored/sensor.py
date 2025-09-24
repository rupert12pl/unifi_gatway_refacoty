from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
from .const import CONF_HOST, DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, UniFiOSClient


_LOGGER = logging.getLogger(__name__)


MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=30)


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

    runner_state = RunnerState()
    monitor_entities = [
        SpeedtestStatusSensor(entry.entry_id, runner_state),
        SpeedtestLastErrorSensor(entry.entry_id, runner_state),
        SpeedtestDurationSensor(entry.entry_id, runner_state),
        SpeedtestLastRunSensor(entry.entry_id, runner_state),
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
            entity.async_write_ha_state()

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

        entity_registry = er.async_get(hass)
        pending_unique_ids: set[str] = set()

        def _should_skip(unique_id: str) -> bool:
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
                unique_id = build_wan_unique_id(entry.entry_id, link, suffix)
                if unique_id in pending_unique_ids or _should_skip(unique_id):
                    continue
                new_entities.append(
                    cls(coordinator, client, entry.entry_id, link)
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
                UniFiGatewayLanClientsSensor(coordinator, client, entry.entry_id, network)
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
                UniFiGatewayWlanClientsSensor(coordinator, client, entry.entry_id, wlan)
            )
            pending_unique_ids.add(unique_id)

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
    await coordinator.async_request_refresh()


class SpeedtestLastRunSensor(SensorEntity):
    _attr_name = "Speedtest Last Run"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry_id: str, state: RunnerState) -> None:
        self._state = state
        self._attr_unique_id = f"{entry_id}_speedtest_last_run"

    @property
    def native_value(self):
        return self._state.last_run


class SpeedtestDurationSensor(SensorEntity):
    _attr_name = "Speedtest Last Duration"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UNIT_MILLISECONDS
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry_id: str, state: RunnerState) -> None:
        self._state = state
        self._attr_unique_id = f"{entry_id}_speedtest_last_duration"

    @property
    def native_value(self):
        return self._state.last_duration_ms


class SpeedtestLastErrorSensor(SensorEntity):
    _attr_name = "Speedtest Last Error"
    _attr_icon = "mdi:alert-circle-outline"
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry_id: str, state: RunnerState) -> None:
        self._state = state
        self._attr_unique_id = f"{entry_id}_speedtest_last_error"

    @property
    def native_value(self):
        return self._state.last_error or ""


class SpeedtestStatusSensor(SensorEntity):
    _attr_name = "Speedtest Last Run OK"
    _attr_icon = "mdi:check-network"
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry_id: str, state: RunnerState) -> None:
        self._state = state
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


def build_wan_unique_id(entry_id: str, link: Dict[str, Any], suffix: str) -> str:
    return f"{entry_id}::wan::{wan_interface_key(link)}::{suffix}"


def build_lan_unique_id(entry_id: str, network: Dict[str, Any]) -> str:
    return f"{entry_id}::lan::{lan_interface_key(network)}::clients"


def build_wlan_unique_id(entry_id: str, wlan: Dict[str, Any]) -> str:
    return f"{entry_id}::wlan::{wlan_interface_key(wlan)}::clients"


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
                str(item).strip()
                for item in value
                if item not in (None, "", [], {})
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


def _parse_datetime_24h(value: Any) -> Optional[str]:
    """Return a datetime string formatted as YYYY-MM-DD HH:MM:SS in local time."""

    if value in (None, ""):
        return None

    dt_value: Optional[datetime] = None

    if isinstance(value, datetime):
        dt_value = value
    elif isinstance(value, (int, float)):
        number = float(value)
        if number > 1e11:
            number /= 1000.0
        try:
            dt_value = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        parsed = dt_util.parse_datetime(text)
        if parsed is not None:
            dt_value = parsed
        else:
            try:
                number = float(text)
            except (TypeError, ValueError):
                return None
            if number > 1e11:
                number /= 1000.0
            try:
                dt_value = datetime.fromtimestamp(number, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
    else:
        return None

    if dt_value is None:
        return None

    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=timezone.utc)
    local_dt = dt_util.as_local(dt_value)
    return local_dt.strftime("%Y-%m-%d %H:%M:%S")


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
        link: Dict[str, Any],
        suffix: str,
        name_suffix: str = "",
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
                attrs["user_total"] = total
        attrs.update(self._controller_attrs())
        return attrs



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
        entry_id: str,
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, entry_id, link, "status")
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
            "primary": "UP",
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
        last_update_raw = _value_from_record(
            health,
            ("datetime", "time", "last_seen", "last_update", "updated_at"),
        )
        attrs["last_update"] = _parse_datetime_24h(last_update_raw)
        attrs["last_update_raw"] = last_update_raw
        attrs["uptime"] = _value_from_record(
            health,
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
    ) -> None:
        super().__init__(coordinator, client, entry_id, link, "ip", " IP")
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
        link: Dict[str, Any],
    ) -> None:
        super().__init__(coordinator, client, entry_id, link, "isp", " ISP")
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
        ip_address = _extract_network_ip_address(network)
        if not ip_address:
            ip_address = _extract_ip_from_value(subnet)
        if vlan_id is None:
            vlan_id = self._network.get("vlan")
        attrs = {
            "network_id": self._network_id,
            "subnet": subnet,
            "vlan_id": vlan_id,
            "ip_address": ip_address,
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
    ) -> None:
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        unique_id = build_wlan_unique_id(entry_id, wlan)
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
        rundate_raw = record.get("rundate") if record else None
        attrs = {
            "source": record.get("source") if record else None,
            "rundate": _parse_datetime_24h(rundate_raw),
            "rundate_raw": rundate_raw,
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
                "server_name",
                "server_host",
                "server_id",
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


def _extract_ip_from_value(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return None
        if "/" in candidate:
            try:
                interface = ipaddress.ip_interface(candidate)
                return str(interface.ip)
            except ValueError:
                pass
            prefix, _, _ = candidate.partition("/")
            try:
                return str(ipaddress.ip_address(prefix.strip()))
            except ValueError:
                return None
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return None
    if isinstance(value, (list, tuple)):
        for item in value:
            result = _extract_ip_from_value(item)
            if result:
                return result
        return None
    if isinstance(value, dict):
        for key in ("ip", "address", "gateway", "value"):
            result = _extract_ip_from_value(value.get(key))
            if result:
                return result
        return None
    return None


def _extract_network_ip_address(network: Dict[str, Any]) -> Optional[str]:
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
        result = _extract_ip_from_value(network.get(key))
        if result:
            return result
    for key in ("subnet", "ip_subnet", "cidr"):
        result = _extract_ip_from_value(network.get(key))
        if result:
            return result
    return None
