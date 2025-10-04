"""Tests for merging WAN IPv6 data from the UI Cloud API."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, cast

from custom_components.unifi_gateway_refactored.cloud_client import UiCloudError, UiCloudRateLimitError
from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayData,
    UniFiGatewayDataUpdateCoordinator,
)


class DummyClient:
    def instance_key(self) -> str:
        return "dummy"


class DummyCloudClient:
    def __init__(self, payload: Dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error
        self.calls = 0

    async def fetch_hosts(self) -> Dict[str, Any]:
        self.calls += 1
        if self._error:
            raise self._error
        return self._payload or {}


class DummyCoordinator(UniFiGatewayDataUpdateCoordinator):
    def __init__(
        self,
        hass,
        data: UniFiGatewayData,
        cloud_client: DummyCloudClient,
    ) -> None:
        self._test_data = data
        super().__init__(
            hass,
            cast(Any, DummyClient()),
            ui_cloud_client=cast(Any, cloud_client),
        )

    def _fetch_data(self) -> UniFiGatewayData:
        return self._test_data


def _build_data(mac: str) -> UniFiGatewayData:
    return UniFiGatewayData(
        controller={},
        wan_links=[{"id": "wan1", "name": "WAN", "mac": mac}],
        wan_health=[{"id": "wan1"}],
    )


def test_coordinator_applies_cloud_ipv6(hass) -> None:
    mac = "78:45:58:D0:95:75"
    payload = {
        "data": [
            {
                "reportedState": {
                    "wans": [
                        {
                            "mac": mac,
                            "ipv6": "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe",
                            "enabled": True,
                            "type": "WAN",
                        }
                    ]
                }
            }
        ]
    }
    cloud_client = DummyCloudClient(payload)
    data = _build_data(mac)
    coordinator = DummyCoordinator(hass, data, cloud_client)

    result = asyncio.run(coordinator._async_update_data())

    link = result.wan_links[0]
    assert link["last_ipv6"] == "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe"
    assert coordinator._wan_ipv6_cache["78:45:58:d0:95:75"][1] == "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe"
    health = result.wan_health[0]
    assert health["wan_ipv6"] == "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe"


def test_coordinator_uses_cache_on_error(hass, caplog) -> None:
    mac = "78:45:58:D0:95:75"
    error = UiCloudError("boom")
    cloud_client = DummyCloudClient(error=error)
    data = _build_data(mac)
    coordinator = DummyCoordinator(hass, data, cloud_client)
    normalized_mac = "78:45:58:d0:95:75"
    coordinator._wan_ipv6_cache[normalized_mac] = (time.monotonic() - 10, "2001:db8::1")

    result = asyncio.run(coordinator._async_update_data())

    link = result.wan_links[0]
    assert link["last_ipv6"] == "2001:db8::1"
    assert "Failed to fetch WAN IPv6 from UI Cloud API" in caplog.text


def test_coordinator_ignores_expired_cache(hass) -> None:
    mac = "78:45:58:D0:95:75"
    cloud_client = DummyCloudClient(error=UiCloudError("down"))
    data = _build_data(mac)
    coordinator = DummyCoordinator(hass, data, cloud_client)
    normalized_mac = "78:45:58:d0:95:75"
    coordinator._wan_ipv6_cache[normalized_mac] = (time.monotonic() - 600, "2001:db8::2")

    result = asyncio.run(coordinator._async_update_data())

    link = result.wan_links[0]
    assert link.get("last_ipv6") is None


def test_coordinator_logs_rate_limit_warning(hass, caplog) -> None:
    mac = "78:45:58:D0:95:75"
    error = UiCloudRateLimitError(3.0)
    cloud_client = DummyCloudClient(error=error)
    data = _build_data(mac)
    coordinator = DummyCoordinator(hass, data, cloud_client)
    normalized_mac = "78:45:58:d0:95:75"
    coordinator._wan_ipv6_cache[normalized_mac] = (time.monotonic() - 5, "2001:db8::3")

    result = asyncio.run(coordinator._async_update_data())

    assert "retry_in=3.0s" in caplog.text
    assert result.wan_links[0]["last_ipv6"] == "2001:db8::3"
