"""Sensor entities for UniFi Gateway Refactory."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfDataRate, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IntegrationRuntime
from .const import DOMAIN
from .coordinator import UniFiGatewayCoordinator, UniFiGatewayData, as_float


@dataclass(frozen=True, slots=True, kw_only=True)
class UniFiGatewaySensorEntityDescription(SensorEntityDescription):
    """Describes UniFi Gateway sensor entity."""

    value_fn: Callable[[UniFiGatewayData], Any]
    attr_fn: Callable[[UniFiGatewayData], Mapping[str, Any]] | None = None


def _get_subsystem(data: UniFiGatewayData, subsystem: str) -> Mapping[str, Any]:
    for item in data.health:
        if isinstance(item, Mapping) and item.get("subsystem") == subsystem:
            return item
    return {}


def _wan_status(data: UniFiGatewayData) -> str:
    subsystem = _get_subsystem(data, "wan")
    return str(subsystem.get("status_translated") or subsystem.get("status") or "unknown")


def _wan_latency(data: UniFiGatewayData) -> float | None:
    subsystem = _get_subsystem(data, "wan")
    return as_float(subsystem.get("latency"))


def _wan_uptime(data: UniFiGatewayData) -> float | None:
    subsystem = _get_subsystem(data, "wan")
    return as_float(subsystem.get("uptime"))


def _wan_tx_mbps(data: UniFiGatewayData) -> float | None:
    subsystem = _get_subsystem(data, "wan")
    bps = as_float(subsystem.get("uplink_tx_bps"))
    if bps is None:
        return None
    return round(bps / 1_000_000, 3)


def _wan_rx_mbps(data: UniFiGatewayData) -> float | None:
    subsystem = _get_subsystem(data, "wan")
    bps = as_float(subsystem.get("uplink_rx_bps"))
    if bps is None:
        return None
    return round(bps / 1_000_000, 3)


def _clients_total(data: UniFiGatewayData) -> int:
    total = 0
    for subsystem_name in ("lan", "wlan"):
        count = as_float(_get_subsystem(data, subsystem_name).get("num_user"))
        if count:
            total += int(count)
    return total


def _vpn_clients(data: UniFiGatewayData) -> int:
    subsystem = _get_subsystem(data, "vpn")
    clients = subsystem.get("connected_clients")
    if isinstance(clients, list):
        return len(clients)
    count = as_float(subsystem.get("num_user"))
    return int(count) if count else 0


def _vpn_attrs(data: UniFiGatewayData) -> Mapping[str, Any]:
    subsystem = _get_subsystem(data, "vpn")
    clients = subsystem.get("connected_clients")
    if not isinstance(clients, list):
        return {}
    formatted = []
    for raw in clients:
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name") or "Unknown")
        remote = raw.get("remote_ip") or raw.get("remoteIP") or "?"
        assigned = raw.get("assigned_ip") or raw.get("internal_ip")
        formatted.append(
            {
                "name": name,
                "remote_ip": remote,
                "assigned_ip": assigned,
            }
        )
    return {"connected_clients": formatted}


SENSOR_DESCRIPTIONS: tuple[UniFiGatewaySensorEntityDescription, ...] = (
    UniFiGatewaySensorEntityDescription(
        key="wan_status",
        translation_key="wan_status",
        value_fn=_wan_status,
    ),
    UniFiGatewaySensorEntityDescription(
        key="wan_latency_ms",
        translation_key="wan_latency",
        native_unit_of_measurement="ms",
        value_fn=_wan_latency,
    ),
    UniFiGatewaySensorEntityDescription(
        key="wan_uptime_s",
        translation_key="wan_uptime",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        suggested_display_precision=0,
        value_fn=_wan_uptime,
    ),
    UniFiGatewaySensorEntityDescription(
        key="wan_tx_mbps",
        translation_key="wan_tx",
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_display_precision=3,
        value_fn=_wan_tx_mbps,
    ),
    UniFiGatewaySensorEntityDescription(
        key="wan_rx_mbps",
        translation_key="wan_rx",
        native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_display_precision=3,
        value_fn=_wan_rx_mbps,
    ),
    UniFiGatewaySensorEntityDescription(
        key="clients_total",
        translation_key="clients_total",
        value_fn=_clients_total,
    ),
    UniFiGatewaySensorEntityDescription(
        key="vpn_clients",
        translation_key="vpn_clients",
        value_fn=_vpn_clients,
        attr_fn=_vpn_attrs,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Gateway sensors based on a config entry."""
    runtime = cast(IntegrationRuntime, hass.data[DOMAIN][entry.entry_id])
    coordinator: UniFiGatewayCoordinator = runtime.coordinator
    entities: list[UniFiGatewaySensor] = [
        UniFiGatewaySensor(coordinator, description, entry.entry_id)
        for description in SENSOR_DESCRIPTIONS
    ]
    async_add_entities(entities)


class UniFiGatewaySensor(CoordinatorEntity[UniFiGatewayData], SensorEntity):
    """Representation of a UniFi Gateway sensor."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: UniFiGatewayCoordinator,
        description: UniFiGatewaySensorEntityDescription,
        entry_id: str,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry_id}_{description.key}"

    @property
    def native_value(self) -> Any:
        if not self.coordinator.data:
            return None
        description = self.entity_description
        if not isinstance(description, UniFiGatewaySensorEntityDescription):
            return None
        return description.value_fn(self.coordinator.data)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if not self.coordinator.data:
            return None
        description = self.entity_description
        if not isinstance(description, UniFiGatewaySensorEntityDescription):
            return None
        if description.attr_fn is None:
            return None
        attrs = description.attr_fn(self.coordinator.data)
        return dict(attrs)
