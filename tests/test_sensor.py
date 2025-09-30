"""Tests for UniFi Gateway sensors."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import cast

from custom_components.unifi_gateway_refactory.coordinator import (
    UniFiGatewayCoordinator,
    UniFiGatewayData,
)
from custom_components.unifi_gateway_refactory.sensor import (
    SENSOR_DESCRIPTIONS,
    UniFiGatewaySensor,
)


class DummyCoordinator:
    """Minimal coordinator stand-in for sensor tests."""

    def __init__(self, data: UniFiGatewayData) -> None:
        self.data = data
        self.last_update_success = True

    def async_add_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        return lambda: None


def _build_data() -> UniFiGatewayData:
    return UniFiGatewayData(
        health=[
            {
                "subsystem": "wan",
                "status": "ok",
                "status_translated": "Connected",
                "latency": 12.5,
                "uptime": 1200,
                "uplink_tx_bps": 5_000_000,
                "uplink_rx_bps": 10_000_000,
            },
            {
                "subsystem": "lan",
                "num_user": 3,
            },
            {
                "subsystem": "wlan",
                "num_user": 2,
            },
            {
                "subsystem": "vpn",
                "connected_clients": [
                    {"name": "Alice", "remoteIP": "1.2.3.4", "assigned_ip": "10.0.0.2"},
                    {"name": "Bob", "remote_ip": "5.6.7.8"},
                ],
            },
        ],
        wlans=[{"name": "Home"}],
        last_fetch=datetime.now(timezone.utc),
    )


def test_sensor_values() -> None:
    data = _build_data()
    coordinator = cast(UniFiGatewayCoordinator, DummyCoordinator(data))
    sensors = [
        UniFiGatewaySensor(coordinator, description, "entry")
        for description in SENSOR_DESCRIPTIONS
    ]
    values = {sensor.entity_description.key: sensor.native_value for sensor in sensors}

    assert values["wan_status"] == "Connected"
    assert values["wan_latency_ms"] == 12.5
    assert values["wan_uptime_s"] == 1200
    assert values["wan_tx_mbps"] == 5.0
    assert values["wan_rx_mbps"] == 10.0
    assert values["clients_total"] == 5
    assert values["vpn_clients"] == 2

    vpn_sensor = next(
        sensor
        for sensor in sensors
        if sensor.entity_description.key == "vpn_clients"
    )
    attrs = vpn_sensor.extra_state_attributes
    assert attrs is not None
    connected = attrs.get("connected_clients")
    assert isinstance(connected, list)
    assert len(connected) == 2
    first_client = connected[0]
    assert isinstance(first_client, dict)
    assert first_client["remote_ip"] == "1.2.3.4"
