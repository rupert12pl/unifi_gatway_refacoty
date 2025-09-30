"""Tests for UniFi Gateway data coordinator."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from custom_components.unifi_gateway_refactory.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SITE,
    CONF_USERNAME,
)
from custom_components.unifi_gateway_refactory.coordinator import (
    AuthFailedError,
    InvalidResponseError,
    UniFiGatewayApiClient,
    UniFiGatewayDataUpdateCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed


@pytest.fixture
def config_entry() -> ConfigEntry:
    return ConfigEntry(
        entry_id="test-entry",
        data={
            CONF_HOST: "https://gateway",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_SITE: "default",
        },
        title="UniFi",
        options={},
    )


def test_coordinator_success(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Coordinator aggregates WAN, VPN and client metrics."""

    class StaticSession:
        async def request(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
            raise AssertionError("request should not be called in this test")

        def close(self) -> None:  # pragma: no cover
            return None

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        lambda *args, **kwargs: StaticSession(),
    )

    async def _fetch_metrics(
        self: UniFiGatewayApiClient,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        health = [
            {
                "subsystem": "wan",
                "status": "ok",
                "latency": 12,
                "packet_loss": "0.3",
                "wan_down": 80,
                "wan_up": 40,
            },
            {
                "subsystem": "vpn",
                "num_active": 2,
                "clients": ["alice", "bob"],
            },
            {"num_clients": 5, "num_sta": 3},
        ]
        wlan = [
            {"name": "Main", "num_sta": 4},
        ]
        return health, wlan

    monkeypatch.setattr(UniFiGatewayApiClient, "fetch_metrics", _fetch_metrics)

    coordinator = UniFiGatewayDataUpdateCoordinator(hass, config_entry)
    event_loop.run_until_complete(coordinator.async_config_entry_first_refresh())

    assert coordinator.data.wan["latency_ms"] == 12
    assert coordinator.data.vpn["active_tunnels"] == 2
    assert coordinator.data.clients["total"] == 7


def test_coordinator_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Authentication failures are surfaced as ConfigEntryAuthFailed."""

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        lambda *args, **kwargs: object(),
    )

    async def _raise_auth(
        self: UniFiGatewayApiClient,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        raise AuthFailedError

    monkeypatch.setattr(UniFiGatewayApiClient, "fetch_metrics", _raise_auth)

    coordinator = UniFiGatewayDataUpdateCoordinator(hass, config_entry)
    with pytest.raises(ConfigEntryAuthFailed):
        event_loop.run_until_complete(coordinator.async_config_entry_first_refresh())


def test_coordinator_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Invalid payloads raise UpdateFailed."""

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        lambda *args, **kwargs: object(),
    )

    async def _raise_invalid(
        self: UniFiGatewayApiClient,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        raise InvalidResponseError("bad json")

    monkeypatch.setattr(UniFiGatewayApiClient, "fetch_metrics", _raise_invalid)

    coordinator = UniFiGatewayDataUpdateCoordinator(hass, config_entry)
    with pytest.raises(UpdateFailed):
        event_loop.run_until_complete(coordinator.async_config_entry_first_refresh())


class DummyResponse:
    """Minimal aiohttp-like response for testing retries."""

    def __init__(self, status: int, payload: Any) -> None:
        self._status = status
        self._payload = payload

    async def __aenter__(self) -> "DummyResponse":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    @property
    def status(self) -> int:
        return self._status

    async def json(self) -> Any:
        return self._payload

    async def text(self) -> str:
        return "temporary error"


class DummySession:
    """Fake session implementing request for retry tests."""

    def __init__(self, responses: list[int], payloads: list[Any]) -> None:
        self._responses = responses
        self._payloads = payloads
        self.calls = 0

    async def request(self, *args: Any, **kwargs: Any) -> DummyResponse:
        index = min(self.calls, len(self._responses) - 1)
        status = self._responses[index]
        payload = self._payloads[index]
        self.calls += 1
        return DummyResponse(status, payload)


def test_api_retries_on_server_error(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """API client retries on 5xx responses before succeeding."""

    responses = [502, 200]
    payloads = [{}, {"data": []}]
    session = DummySession(responses, payloads)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        result = event_loop.run_until_complete(client._request_json("GET", "/test"))

    assert session.calls == 2
    assert result == {"data": []}


def _setup_coordinator(
    monkeypatch: pytest.MonkeyPatch, hass, config_entry: ConfigEntry
) -> UniFiGatewayDataUpdateCoordinator:
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        lambda *args, **kwargs: object(),
    )
    return UniFiGatewayDataUpdateCoordinator(hass, config_entry)


def test_ipv6_global_address(
    monkeypatch: pytest.MonkeyPatch, hass, config_entry: ConfigEntry
) -> None:
    coordinator = _setup_coordinator(monkeypatch, hass, config_entry)
    health = [
        {
            "subsystem": "wan",
            "status": "ok",
            "ipv6": "2401:db00::1",
            "ipv6_link_local": "fe80::1",
            "pd_prefix": "2a01:1111:abcd::",
            "pd_prefixlen": 56,
        }
    ]
    metrics = coordinator._build_metrics(health, [])

    ipv6 = metrics.wan["ipv6"]
    assert ipv6["display_value"] == "2401:db00::1"
    assert ipv6["ipv6_source"] == "global"
    assert ipv6["wan_ipv6_link_local"] == "fe80::1"
    assert ipv6["has_ipv6_connectivity"] is True


def test_ipv6_prefix_delegation(
    monkeypatch: pytest.MonkeyPatch, hass, config_entry: ConfigEntry
) -> None:
    coordinator = _setup_coordinator(monkeypatch, hass, config_entry)
    health = [
        {
            "subsystem": "wan",
            "status": "ok",
            "ipv6_link_local": "fe80::1",
            "pd_prefix": "2a10:abcd::",
            "pd_prefixlen": "56",
        }
    ]
    metrics = coordinator._build_metrics(health, [])

    ipv6 = metrics.wan["ipv6"]
    assert ipv6["display_value"] == "2a10:abcd::/56"
    assert ipv6["ipv6_source"] == "pd"
    assert ipv6["wan_ipv6_global"] is None


def test_ipv6_link_local_only(
    monkeypatch: pytest.MonkeyPatch, hass, config_entry: ConfigEntry
) -> None:
    coordinator = _setup_coordinator(monkeypatch, hass, config_entry)
    health = [
        {
            "subsystem": "wan",
            "status": "ok",
            "ipv6_link_local": "fe80::abcd",
        }
    ]
    metrics = coordinator._build_metrics(health, [])

    ipv6 = metrics.wan["ipv6"]
    assert ipv6["display_value"] == "unknown"
    assert ipv6["ipv6_source"] == "unknown"
    assert ipv6["wan_ipv6_link_local"] == "fe80::abcd"
    assert ipv6["has_ipv6_connectivity"] is False


def test_ipv6_malformed_payload(
    monkeypatch: pytest.MonkeyPatch, hass, config_entry: ConfigEntry
) -> None:
    coordinator = _setup_coordinator(monkeypatch, hass, config_entry)
    health = [
        {
            "subsystem": "wan",
            "status": "ok",
            "ipv6": "not-an-ip",
            "pd_prefix": "bad-prefix",
            "pd_prefixlen": "not-a-number",
        }
    ]
    metrics = coordinator._build_metrics(health, [])

    ipv6 = metrics.wan["ipv6"]
    assert ipv6["display_value"] == "unknown"
    assert ipv6["wan_ipv6_global"] is None
    assert ipv6["delegated_prefix"] is None
    assert ipv6["has_ipv6_connectivity"] is False
