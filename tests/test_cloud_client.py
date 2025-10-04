from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, cast

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
    def __init__(self, status: int, payload: Any = None, headers: Optional[dict[str, str]] = None) -> None:
        self.status = status
        self._payload = payload
        self.headers = headers or {}

    async def __aenter__(self) -> "DummyResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def json(self, content_type: Optional[str] = None) -> Any:
        return self._payload


class DummyResponseContext:
    def __init__(self, response: DummyResponse) -> None:
        self._response = response

    def __await__(self):  # pragma: no cover - exercised via async context
        async def _coro():
            return self._response

        return _coro().__await__()

    async def __aenter__(self) -> DummyResponse:
        return await self._response.__aenter__()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return await self._response.__aexit__(exc_type, exc, tb)


class DummySession:
    def __init__(self, responses: List[DummyResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[str] = []
        self.kwargs: list[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout=None,
    ) -> DummyResponse:
        self.requests.append(url)
        self.kwargs.append({"headers": headers, "timeout": timeout})
        if not self._responses:
            raise RuntimeError("No more responses queued")
        return DummyResponseContext(self._responses.pop(0))


class FailingSession:
    def __init__(self, error: Exception) -> None:
        self._error = error
        self.calls = 0

    def get(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout=None,
    ) -> DummyResponse:
        self.calls += 1
        raise self._error


async def _no_sleep(_seconds: float) -> None:
    return None


def test_async_get_hosts_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload = {"data": [], "httpStatusCode": 200}
    session = DummySession([DummyResponse(200, payload)])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    result = asyncio.run(client.async_get_hosts())

    assert result == payload
    assert session.requests == ["https://api.ui.com/v1/hosts"]


def test_async_get_hosts_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    session = DummySession([DummyResponse(401, {})])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudAuthError):
        asyncio.run(client.async_get_hosts())


def test_async_get_hosts_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    responses = [
        DummyResponse(429, {}, {"Retry-After": "1.5"}),
        DummyResponse(429, {}, {"Retry-After": "1.0"}),
        DummyResponse(429, {}, {"Retry-After": "1.0"}),
        DummyResponse(429, {}, {"Retry-After": "1.0"}),
    ]
    session = DummySession(responses)
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudRateLimitError):
        asyncio.run(client.async_get_hosts())

    assert sleep_calls[0] == 1.5
    assert len(sleep_calls) >= 1


def test_async_get_hosts_rate_limited_http_date(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    frozen_now = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)

    class FrozenDateTime:
        @classmethod
        def now(cls, tz=None):
            assert tz is timezone.utc or tz is None
            return frozen_now

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.cloud_client.datetime",
        FrozenDateTime,
    )

    retry_after_date = (frozen_now + timedelta(seconds=42)).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )
    responses = [
        DummyResponse(429, {}, {"Retry-After": retry_after_date}),
        DummyResponse(200, {"data": []}),
    ]
    session = DummySession(responses)
    client = UiCloudClient(cast(ClientSession, session), "secret")

    result = asyncio.run(client.async_get_hosts())

    assert result == {"data": [], "httpStatusCode": 200}
    assert sleep_calls
    assert sleep_calls[0] == 42.0


def test_async_get_hosts_retries_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    payload: dict[str, Any] = {"data": []}
    session = DummySession([DummyResponse(500, {}), DummyResponse(200, payload)])
    client = UiCloudClient(cast(ClientSession, session), "secret")

    result = asyncio.run(client.async_get_hosts())

    assert result == {"data": [], "httpStatusCode": 200}
    assert len(session.requests) == 2


def test_async_get_hosts_unexpected_error(monkeypatch: pytest.MonkeyPatch) -> None:
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
        asyncio.run(client.async_get_hosts())


def test_async_get_hosts_network_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asyncio, "sleep", _no_sleep)
    error = ClientError("boom")
    session = FailingSession(error)
    client = UiCloudClient(cast(ClientSession, session), "secret")

    with pytest.raises(UiCloudRequestError):
        asyncio.run(client.async_get_hosts())
