"""Sensor entities for UniFi Gateway Refactory."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, GatewaySensorDescription
from .coordinator import UniFiGatewayDataUpdateCoordinator, UniFiGatewayMetrics

SENSOR_DESCRIPTIONS: tuple[GatewaySensorDescription, ...] = (
    GatewaySensorDescription(
        key="wan_latency",
        name="UniFi WAN Latency",
        icon="mdi:speedometer",
        native_unit_of_measurement="ms",
        device_class=None,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["wan"].get("latency_ms"),
    ),
    GatewaySensorDescription(
        key="wan_packet_loss",
        name="UniFi WAN Packet Loss",
        icon="mdi:chart-line",
        native_unit_of_measurement="%",
        device_class=None,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["wan"].get("packet_loss_pct"),
    ),
    GatewaySensorDescription(
        key="wan_throughput",
        name="UniFi WAN Throughput",
        icon="mdi:transmission-tower",
        native_unit_of_measurement="Mbps",
        device_class=None,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["wan"].get("throughput_mbps"),
    ),
    GatewaySensorDescription(
        key="vpn_tunnels",
        name="UniFi VPN Tunnels",
        icon="mdi:vpn",
        native_unit_of_measurement=None,
        device_class=None,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["vpn"].get("active_tunnels"),
        attributes_fn=lambda data: {"clients": data["vpn"].get("clients", [])},
    ),
    GatewaySensorDescription(
        key="connected_clients",
        name="UniFi Connected Clients",
        icon="mdi:lan-connect",
        native_unit_of_measurement=None,
        device_class=None,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data["clients"].get("total"),
        attributes_fn=lambda data: {
            "wired": data["clients"].get("wired"),
            "wireless": data["clients"].get("wireless"),
        },
    ),
    GatewaySensorDescription(
        key="wan_ipv6",
        name="UniFi WAN IPv6",
        icon="mdi:ip-network-outline",
        native_unit_of_measurement=None,
        device_class=None,
        state_class=None,
        value_fn=lambda data: (
            data["wan"].get("ipv6", {}).get("display_value")
            if data.get("wan")
            else None
        ),
        attributes_fn=lambda data: {
            "wan_ipv6_global": data["wan"].get("ipv6", {}).get("wan_ipv6_global"),
            "wan_ipv6_link_local": data["wan"].get("ipv6", {}).get("wan_ipv6_link_local"),
            "delegated_prefix": data["wan"].get("ipv6", {}).get("delegated_prefix"),
            "ipv6_source": data["wan"].get("ipv6", {}).get("ipv6_source"),
            "has_ipv6_connectivity": data["wan"].get("ipv6", {}).get(
                "has_ipv6_connectivity"
            ),
        },
    ),
)


class UniFiGatewaySensor(CoordinatorEntity[UniFiGatewayMetrics], SensorEntity):
    """Representation of a UniFi Gateway metric sensor."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        description: GatewaySensorDescription,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_icon = description.icon
        self._attr_native_unit_of_measurement = description.native_unit_of_measurement
        self._attr_device_class = description.device_class
        self._attr_state_class = description.state_class

    @property
    def native_value(self) -> Any:
        metrics = self.coordinator.data
        if not metrics:
            return None
        try:
            return self.entity_description.value_fn(self._metrics_to_dict(metrics))
        except Exception:  # pragma: no cover - safety net
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        metrics = self.coordinator.data
        if not metrics:
            return {}
        try:
            return self.entity_description.attributes_fn(self._metrics_to_dict(metrics))
        except Exception:  # pragma: no cover - safety net
            return {}

    @property
    def available(self) -> bool:
        if not self.coordinator.data:
            return False
        return True

    @staticmethod
    def _metrics_to_dict(metrics: UniFiGatewayMetrics) -> dict[str, Any]:
        return {
            "wan": metrics.wan,
            "vpn": metrics.vpn,
            "clients": metrics.clients,
            "last_fetch": metrics.last_fetch,
            "raw_health": metrics.raw_health,
            "raw_wlans": metrics.raw_wlans,
        }


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:  # type: ignore[override]
    """Set up sensors from a config entry."""

    data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if not data:
        return
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]
    entities = [
        UniFiGatewaySensor(coordinator, description, entry)
        for description in SENSOR_DESCRIPTIONS
    ]
    async_add_entities(entities)
