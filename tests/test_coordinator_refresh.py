from __future__ import annotations

import asyncio
from typing import Any, cast

from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayData,
    UniFiGatewayDataUpdateCoordinator,
)
from custom_components.unifi_gateway_refactored.const import (
    NETWORK_STATUS_UPDATE_INTERVAL,
)
from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


class _DummyClient:
    """Minimal UniFi client stub for coordinator tests."""

    def instance_key(self) -> str:
        return "dummy"


class _TestCoordinator(UniFiGatewayDataUpdateCoordinator):
    def __init__(self, hass, client: UniFiOSClient, data: UniFiGatewayData) -> None:
        self._data_to_return = data
        self.fetch_calls = 0
        super().__init__(hass, client)

    def _fetch_data(self) -> UniFiGatewayData:
        self.fetch_calls += 1
        return self._data_to_return


def _make_data() -> UniFiGatewayData:
    return UniFiGatewayData(
        controller={},
        health=[],
        health_by_subsystem={},
        wan_health=[],
        alerts=[],
        devices=[],
        wan_links=[],
        networks=[],
        lan_networks=[],
        network_map={},
        wlans=[],
        clients=[],
    )


def test_coordinator_uses_15_second_interval(hass) -> None:
    data = _make_data()
    coordinator = _TestCoordinator(hass, cast(UniFiOSClient, _DummyClient()), data)
    assert coordinator.update_interval == NETWORK_STATUS_UPDATE_INTERVAL


def test_coordinator_refresh_runs_in_executor(hass) -> None:
    data = _make_data()
    coordinator = _TestCoordinator(hass, cast(UniFiOSClient, _DummyClient()), data)

    calls: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    async def fake_async_add_executor_job(
        func, *args: Any, **kwargs: Any
    ) -> Any:
        calls.append((func, args, kwargs))
        return func(*args, **kwargs)

    original_executor = hass.async_add_executor_job
    hass.async_add_executor_job = fake_async_add_executor_job  # type: ignore[assignment]
    try:
        asyncio.run(coordinator.async_request_refresh())
    finally:
        hass.async_add_executor_job = original_executor  # type: ignore[assignment]

    assert calls, "Coordinator refresh should offload work to executor"
    assert calls[0][0] == coordinator._fetch_data
    assert coordinator.fetch_calls == 1
    assert coordinator.data == data
