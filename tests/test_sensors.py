"""Sensor tests for UniFi Gateway Refactory."""
from __future__ import annotations

from datetime import datetime

import pytest
from custom_components.unifi_gateway_refactory.binary_sensor import (
    UniFiGatewayWanOnlineSensor,
)
from custom_components.unifi_gateway_refactory.coordinator import UniFiGatewayMetrics
from custom_components.unifi_gateway_refactory.sensor import (
    SENSOR_DESCRIPTIONS,
    UniFiGatewaySensor,
    async_setup_entry,
)
from homeassistant.config_entries import ConfigEntry


class DummyCoordinator:
    """Coordinator stub providing metric data."""

    def __init__(self, metrics: UniFiGatewayMetrics | None) -> None:
        self.data = metrics


@pytest.fixture
def metrics() -> UniFiGatewayMetrics:
    return UniFiGatewayMetrics(
        last_fetch=datetime(2024, 1, 1, 12, 0, 0),
        wan={
            "status": "ok",
            "latency_ms": 10.5,
            "packet_loss_pct": 0.1,
            "throughput_mbps": 50.0,
            "ipv6": {
                "display_value": "2401:db00::1",
                "wan_ipv6_global": "2401:db00::1",
                "wan_ipv6_link_local": "fe80::1",
                "delegated_prefix": "2a01:1111:abcd::/56",
                "ipv6_source": "global",
                "has_ipv6_connectivity": True,
            },
        },
        vpn={"active_tunnels": 1, "clients": ["alice"]},
        clients={"total": 5, "wired": 2, "wireless": 3},
        raw_health=[],
        raw_wlans=[],
    )


def test_sensor_values(metrics: UniFiGatewayMetrics) -> None:
    coordinator = DummyCoordinator(metrics)
    entry = ConfigEntry(entry_id="entry", data={}, title="UniFi", options={})

    sensor = UniFiGatewaySensor(coordinator, SENSOR_DESCRIPTIONS[0], entry)
    assert sensor.native_value == 10.5
    assert sensor.extra_state_attributes == {}

    vpn_sensor = UniFiGatewaySensor(coordinator, SENSOR_DESCRIPTIONS[3], entry)
    assert vpn_sensor.native_value == 1
    assert vpn_sensor.extra_state_attributes["clients"] == ["alice"]


def test_wan_ipv6_sensor(metrics: UniFiGatewayMetrics) -> None:
    coordinator = DummyCoordinator(metrics)
    entry = ConfigEntry(entry_id="entry", data={}, title="UniFi", options={})

    ipv6_sensor = UniFiGatewaySensor(coordinator, SENSOR_DESCRIPTIONS[-1], entry)
    assert ipv6_sensor.native_value == "2401:db00::1"
    attrs = ipv6_sensor.extra_state_attributes
    assert attrs["wan_ipv6_global"] == "2401:db00::1"
    assert attrs["delegated_prefix"] == "2a01:1111:abcd::/56"
    assert attrs["ipv6_source"] == "global"
    assert attrs["has_ipv6_connectivity"] is True


def test_binary_sensor(metrics: UniFiGatewayMetrics) -> None:
    coordinator = DummyCoordinator(metrics)
    entry = ConfigEntry(entry_id="entry", data={}, title="UniFi", options={})

    binary_sensor = UniFiGatewayWanOnlineSensor(coordinator, entry)
    assert binary_sensor.is_on is True
    assert binary_sensor.extra_state_attributes["latency_ms"] == 10.5


def test_async_setup_entry(hass, metrics: UniFiGatewayMetrics, event_loop) -> None:
    added: list = []

    def _async_add_entities(entities):
        added.extend(entities)

    entry = ConfigEntry(entry_id="entry", data={}, title="UniFi", options={})
    hass.data.setdefault("unifi_gateway_refactory", {})[entry.entry_id] = {
        "coordinator": DummyCoordinator(metrics)
    }

    event_loop.run_until_complete(async_setup_entry(hass, entry, _async_add_entities))
    assert len(added) == len(SENSOR_DESCRIPTIONS)
