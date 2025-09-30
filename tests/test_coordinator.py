"""Tests for the UniFi Gateway coordinator."""
from __future__ import annotations

import asyncio
from collections.abc import Iterable, Iterator
from types import TracebackType
from typing import Any, cast

import pytest
from aiohttp import ClientSession
from homeassistant.core import HomeAssistant

from custom_components.unifi_gateway_refactory.coordinator import (
    UniFiGatewayApi,
    UniFiGatewayApiError,
    UniFiGatewayAuthError,
    UniFiGatewayInvalidResponse,
)


class DummyResponse:
    """Simple response object mimicking aiohttp's API."""

    def __init__(self, status: int, payload: Any) -> None:
        self.status = status
        self._payload = payload

    async def json(self, content_type: str | None = None) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    async def text(self) -> str:
        if isinstance(self._payload, Exception):
            return "error"
        return ""

    async def __aenter__(self) -> DummyResponse:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        return False


class DummySession:
    """Minimal async session returning queued responses."""

    def __init__(self, responses: Iterable[DummyResponse | Exception]) -> None:
        self._responses = list(responses)

    def request(self, method: str, url: str, **kwargs: Any) -> DummyResponse:
        if not self._responses:
            raise AssertionError("No responses queued")
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    async def _sleep(_duration: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    yield


async def test_api_success(hass: HomeAssistant) -> None:
    session = cast(
        ClientSession,
        DummySession(
            [
                DummyResponse(200, [{"subsystem": "wan", "status": "ok"}]),
                DummyResponse(200, [{"name": "Main"}]),
            ]
        ),
    )
    api = UniFiGatewayApi(
        session=session,
        host="https://gateway.local",
        username="user",
        password="pass",
        site="default",
        verify_ssl=True,
    )

    data = await api.async_fetch_data()

    assert data.health[0]["subsystem"] == "wan"
    assert data.wlans[0]["name"] == "Main"
    assert data.last_fetch is not None


async def test_api_auth_failure(hass: HomeAssistant) -> None:
    session = cast(ClientSession, DummySession([DummyResponse(401, [])]))
    api = UniFiGatewayApi(
        session=session,
        host="https://gateway.local",
        username="user",
        password="pass",
        site="default",
        verify_ssl=True,
    )

    with pytest.raises(UniFiGatewayAuthError):
        await api.async_fetch_data()


async def test_api_retry_on_502(hass: HomeAssistant) -> None:
    session = cast(
        ClientSession,
        DummySession(
            [
                DummyResponse(502, []),
                DummyResponse(200, []),
                DummyResponse(200, []),
            ]
        ),
    )
    api = UniFiGatewayApi(
        session=session,
        host="https://gateway.local",
        username="user",
        password="pass",
        site="default",
        verify_ssl=True,
    )

    data = await api.async_fetch_data()
    assert data.health == []


async def test_api_invalid_json(hass: HomeAssistant) -> None:
    session = cast(
        ClientSession,
        DummySession(
            [
                DummyResponse(200, ValueError("bad")),
            ]
        ),
    )
    api = UniFiGatewayApi(
        session=session,
        host="https://gateway.local",
        username="user",
        password="pass",
        site="default",
        verify_ssl=True,
    )

    with pytest.raises(UniFiGatewayInvalidResponse):
        await api.async_fetch_data()


async def test_api_timeout_is_wrapped(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactory.coordinator.MAX_RETRIES", 1
    )
    session = cast(
        ClientSession,
        DummySession(
            [
                asyncio.TimeoutError(),
            ]
        ),
    )
    api = UniFiGatewayApi(
        session=session,
        host="https://gateway.local",
        username="user",
        password="pass",
        site="default",
        verify_ssl=True,
    )

    with pytest.raises(UniFiGatewayApiError):
        await api.async_fetch_data()
