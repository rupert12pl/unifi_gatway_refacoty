"""Tests for the UniFi UI Cloud client helper."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, cast

import pytest

from aiohttp import ClientError, ClientSession
from custom_components.unifi_gateway_refactored.cloud_client import (
    UiCloudAuthError,
    UiCloudClient,
    UiCloudError,
    UiCloudRateLimitError,
    UiCloudRequestError,
)


class DummyResponse:
    def __init__(self, status: int, payload: Any = None, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self._payload = payload
        self.headers = headers or {}

    async def __aenter__(self) -> "DummyResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def json(self) -> Any:
        return self._payload


class DummySession:
    def __init__(self, responses: List[DummyResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[str] = []

        # capture keyword arguments for assertions (e.g. SSL enforcement)
        self.kwargs: list[Dict[str, Any]] = []

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout=None,
        ssl=None,
    ) -> DummyResponse:
        self.requests.append(url)
        self.kwargs.append({"headers": headers, "timeout": timeout, "ssl": ssl})
        if not self._responses:
            raise RuntimeError("No more responses queued")
        return self._responses.pop(0)


class FailingSession:
    def __init__(self, error: Exception) -> None:
        self._error = error
        self.calls = 0

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout=None,
        ssl=None,
    ) -> DummyResponse:
        self.calls += 1
        raise self._error


async def _no_sleep(_seconds: float) -> None:
    return None


def test_fetch_ipv6_for_mac_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload = {
        "data": [
            {
                "reportedState": {
                    "wans": [
                        {
                            "mac": "78:45:58:D0:95:75",
                            "ipv6": "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe",
                            "enabled": True,
                            "type": "WAN",
                        }
                    ]
                }
            }
        ]
    }
    session = DummySession([DummyResponse(200, payload)])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    ipv6 = asyncio.run(client.fetch_ipv6_for_mac("78:45:58:D0:95:75"))

    assert ipv6 == "2a00:c020:40fe:37f1:4402:b7a2:4cd3:e8fe"
    assert session.requests == ["https://api.ui.com/v1/hosts"]
    assert session.kwargs[0]["ssl"] is True


def test_fetch_ipv6_for_mac_returns_none_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload = {
        "data": [
            {
                "reportedState": {
                    "wans": [
                        {
                            "mac": "78:45:58:d0:95:75",
                            "ipv6": "",
                            "enabled": True,
                            "type": "WAN",
                        }
                    ]
                }
            }
        ]
    }
    session = DummySession([DummyResponse(200, payload)])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    ipv6 = asyncio.run(client.fetch_ipv6_for_mac("00:00:00:00:00:00"))

    assert ipv6 is None
    assert session.requests == ["https://api.ui.com/v1/hosts"]
    assert session.kwargs[0]["ssl"] is True


def test_fetch_hosts_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    session = DummySession([DummyResponse(401, {})])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudAuthError):
        asyncio.run(client.fetch_hosts())


def test_fetch_hosts_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    responses = [
        DummyResponse(429, {}, {"Retry-After": "1.5"}),
        DummyResponse(429, {}, {"Retry-After": "1.5"}),
        DummyResponse(429, {}, {"Retry-After": "1.5"}),
        DummyResponse(429, {}, {"Retry-After": "1.5"}),
    ]
    session = DummySession(responses)
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudRateLimitError):
        asyncio.run(client.fetch_hosts())

    assert sleep_calls == [1.5, 0.5, 1.5, 1.0, 1.5, 2.0]


def test_fetch_hosts_retries_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload: dict[str, Any] = {"data": []}
    session = DummySession([DummyResponse(500, {}), DummyResponse(200, payload)])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    result = asyncio.run(client.fetch_hosts())

    assert result == payload
    assert len(session.requests) == 2
    assert all(kwargs["ssl"] is True for kwargs in session.kwargs)


def test_fetch_hosts_unexpected_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    session = DummySession(
        [
            DummyResponse(502, {}),
            DummyResponse(502, {}),
            DummyResponse(502, {}),
            DummyResponse(502, {}),
        ]
    )
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudError):
        asyncio.run(client.fetch_hosts())


def test_fetch_hosts_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    error = ClientError("boom")
    session = FailingSession(error)
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudRequestError):
        asyncio.run(client.fetch_hosts())

    assert session.calls == 4


def test_fetch_hosts_does_not_force_ssl_for_custom_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload: dict[str, Any] = {"data": []}
    session = DummySession([DummyResponse(200, payload)])
    client = UiCloudClient(
        cast(ClientSession, session),
        "secret",
        hosts_url="https://example.invalid/custom",
    )

    result = asyncio.run(client.fetch_hosts())

    assert result == payload
    assert session.requests == ["https://example.invalid/custom/v1/hosts"]
    assert session.kwargs[0]["ssl"] is None
