"""Tests for the UniFi Gateway coordinator."""
from __future__ import annotations

import asyncio

import pytest

from custom_components.unifi_gateway_refactory.coordinator import (
    UniFiGatewayApi,
    UniFiGatewayAuthError,
    UniFiGatewayInvalidResponse,
)


class DummyResponse:
    def __init__(self, status: int, payload) -> None:  # type: ignore[no-untyped-def]
        self.status = status
        self._payload = payload

    async def json(self, content_type=None):  # type: ignore[no-untyped-def]
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    async def text(self) -> str:
        if isinstance(self._payload, Exception):
            return "error"
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummySession:
    def __init__(self, responses):  # type: ignore[no-untyped-def]
        self._responses = list(responses)

    def request(self, method, url, **kwargs):  # type: ignore[no-untyped-def]
        if not self._responses:
            raise AssertionError("No responses queued")
        response = self._responses.pop(0)
        return response


@pytest.fixture(autouse=True)
async def fast_sleep(monkeypatch):
    async def _sleep(_duration):
        return None

    monkeypatch.setattr(asyncio, "sleep", _sleep)
    yield


async def test_api_success(hass):
    session = DummySession(
        [
            DummyResponse(200, [{"subsystem": "wan", "status": "ok"}]),
            DummyResponse(200, [{"name": "Main"}]),
        ]
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


async def test_api_auth_failure(hass):
    session = DummySession([DummyResponse(401, [])])
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


async def test_api_retry_on_502(hass):
    session = DummySession(
        [
            DummyResponse(502, []),
            DummyResponse(200, []),
            DummyResponse(200, []),
        ]
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


async def test_api_invalid_json(hass):
    session = DummySession(
        [
            DummyResponse(200, ValueError("bad")),
        ]
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
