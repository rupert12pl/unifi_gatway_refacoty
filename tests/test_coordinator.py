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


def test_client_base_url_with_port(
    monkeypatch: pytest.MonkeyPatch,
    hass,
) -> None:
    """Explicit ports in the host are not appended twice."""

    class StaticSession:
        async def request(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover
            raise AssertionError("request should not be called in this test")

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        lambda *args, **kwargs: StaticSession(),
    )

    entry = ConfigEntry(
        entry_id="with-port",
        data={
            CONF_HOST: "https://gateway.local:8443",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_SITE: "default",
        },
        title="UniFi",
        options={},
    )

    client = UniFiGatewayApiClient(hass, entry)

    assert client.base_url == "https://gateway.local:8443"


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

    def __init__(self, status: int, payload: Any, text: str = "temporary error") -> None:
        self._status = status
        self._payload = payload
        self._text = text

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
        return self._text


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


class DummyCookie:
    def __init__(self, value: str) -> None:
        self.value = value


class DummyCookieJar:
    def __init__(self, cookies: dict[str, DummyCookie]) -> None:
        self._cookies = cookies

    def filter_cookies(self, url: str) -> dict[str, DummyCookie]:  # pragma: no cover - simple
        return self._cookies


class DummyLoginResponse:
    def __init__(
        self,
        status: int = 200,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self.status = status
        self.headers = headers or {}
        self._text = text

    async def __aenter__(self) -> "DummyLoginResponse":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def text(self) -> str:
        return self._text


class AuthRetrySession:
    """Session that first uses basic auth then retries with session cookies."""

    def __init__(self, responses: list[DummyResponse], login_response: DummyLoginResponse) -> None:
        self._responses = responses
        self._login_response = login_response
        self.request_calls: list[dict[str, Any]] = []
        self.cookie_jar = DummyCookieJar({})
        self._request_index = 0
        self.login_calls = 0

    async def request(self, *args: Any, **kwargs: Any) -> DummyResponse:
        self.request_calls.append(kwargs)
        index = min(self._request_index, len(self._responses) - 1)
        self._request_index += 1
        return self._responses[index]

    async def post(self, *args: Any, **kwargs: Any) -> DummyLoginResponse:
        self.login_calls += 1
        return self._login_response


class DummyLoginSession:
    def __init__(
        self,
        responses: DummyLoginResponse | list[DummyLoginResponse],
        cookies: dict[str, DummyCookie] | None = None,
    ) -> None:
        if isinstance(responses, list):
            self._responses = responses
        else:
            self._responses = [responses]
        self.post_calls = 0
        self.cookie_jar = DummyCookieJar(cookies or {})
        self.calls: list[dict[str, Any]] = []

    async def post(self, *args: Any, **kwargs: Any) -> DummyLoginResponse:
        self.post_calls += 1
        url = args[0] if args else kwargs.get("url", "")
        payload = kwargs.get("json")
        self.calls.append({"url": url, "payload": payload})
        index = min(self.post_calls - 1, len(self._responses) - 1)
        return self._responses[index]


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
        client._logged_in = True
        result = event_loop.run_until_complete(client._request_json("GET", "/test"))

    assert session.calls == 2
    assert result == {"data": []}


def test_login_uses_csrf_header(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Login flow stores CSRF token from response headers."""

    response = DummyLoginResponse(headers={"x-csrf-token": "abc123"})
    session = DummyLoginSession(response)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        event_loop.run_until_complete(client._ensure_authenticated())

    assert client._csrf_token == "abc123"
    assert session.post_calls == 1
    assert session.calls[0]["payload"]["rememberMe"] is True
    assert "/api/auth/login" in session.calls[0]["url"]


def test_login_falls_back_to_cookie(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Login fallback extracts CSRF token from cookies when header missing."""

    response = DummyLoginResponse()
    cookies = {"csrf_token": DummyCookie("cookie-token")}
    session = DummyLoginSession(response, cookies)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        event_loop.run_until_complete(client._ensure_authenticated())

    assert client._csrf_token == "cookie-token"
    assert session.post_calls == 1
    assert session.calls[0]["payload"]["rememberMe"] is True
    assert "/api/auth/login" in session.calls[0]["url"]


def test_login_retries_with_unifi_os_payload(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Login retries include UniFi OS rememberMe flag for local users."""

    responses = [
        DummyLoginResponse(status=401, text="invalid"),
        DummyLoginResponse(headers={"x-csrf-token": "csrf456"}),
    ]
    session = DummyLoginSession(responses)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        event_loop.run_until_complete(client._ensure_authenticated())

    assert session.post_calls == 2
    assert "/api/auth/login" in session.calls[0]["url"]
    assert session.calls[0]["payload"]["rememberMe"] is True
    assert "/api/login" in session.calls[1]["url"]
    assert session.calls[1]["payload"]["remember"] is True
    assert client._csrf_token == "csrf456"


def test_login_retries_when_csrf_missing(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Login ignores 200 responses that do not include a CSRF token."""

    responses = [
        DummyLoginResponse(),
        DummyLoginResponse(headers={"x-csrf-token": "csrf789"}),
    ]
    session = DummyLoginSession(responses)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        event_loop.run_until_complete(client._ensure_authenticated())

    assert session.post_calls == 2
    assert "/api/auth/login" in session.calls[0]["url"]
    assert session.calls[0]["payload"]["rememberMe"] is True
    assert "/api/login" in session.calls[1]["url"]
    assert session.calls[1]["payload"]["remember"] is True
    assert client._csrf_token == "csrf789"


def test_request_reauth_on_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
    hass,
    config_entry: ConfigEntry,
    event_loop,
) -> None:
    """Client retries without basic auth after UniFi OS login."""

    responses = [
        DummyResponse(401, {}, text="unauthorized"),
        DummyResponse(200, {"data": []}, text="ok"),
    ]
    login_response = DummyLoginResponse(headers={"x-csrf-token": "csrf123"})
    session = AuthRetrySession(responses, login_response)

    with patch(
        "custom_components.unifi_gateway_refactory.coordinator.aiohttp_client.async_get_clientsession",
        return_value=session,
    ):
        client = UniFiGatewayApiClient(hass, config_entry)
        result = event_loop.run_until_complete(client._request_json("GET", "/test"))

    assert session.login_calls == 1
    assert len(session.request_calls) == 2
    assert session.request_calls[0].get("auth") is not None
    assert session.request_calls[1].get("auth") is None
    assert session.request_calls[1]["headers"].get("x-csrf-token") == "csrf123"
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
