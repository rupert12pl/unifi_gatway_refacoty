from __future__ import annotations

import asyncio
from typing import cast

from custom_components.unifi_gateway_refactored.const import (
    ERROR_CODE_TIMEOUT,
    UPDATE_INTERVAL_BACKOFF,
    UPDATE_INTERVAL_OK,
)
from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayDataUpdateCoordinator,
)
from custom_components.unifi_gateway_refactored.unifi_client import (
    UniFiApiClient,
    UniFiRequestError,
)


class FakeClient:
    def __init__(self, fail_count: int) -> None:
        self._fail_count = fail_count
        self.health_calls = 0

    async def async_request_health(self, *, trace_id: str):
        self.health_calls += 1
        if self.health_calls <= self._fail_count:
            raise UniFiRequestError("timeout", code=ERROR_CODE_TIMEOUT)
        return [{"status": "ok"}]

    async def async_request_alerts(self, *, trace_id: str):
        return []

    async def async_request_devices(self, *, trace_id: str):
        return []

    def get_controller_url(self) -> str:
        return "https://controller"

    def get_controller_api_url(self) -> str:
        return "https://controller/api"

    def get_site(self) -> str:
        return "default"


def test_coordinator_circuit_breaker(hass) -> None:
    errors: list[dict[str, str]] = []
    client = FakeClient(fail_count=3)
    coordinator = UniFiGatewayDataUpdateCoordinator(
        hass=hass,
        client=cast(UniFiApiClient, client),
        error_buffer=errors,
    )

    async def _run() -> None:
        await coordinator.async_refresh()
        assert coordinator.available is True
        await coordinator.async_refresh()
        assert coordinator.available is True
        await coordinator.async_refresh()
        assert coordinator.available is False
        assert coordinator.update_interval == UPDATE_INTERVAL_BACKOFF
        assert len(errors) == 3

        await coordinator.async_refresh()
        assert coordinator.available is True
        assert coordinator.update_interval == UPDATE_INTERVAL_OK

    asyncio.run(_run())
