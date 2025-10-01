from __future__ import annotations

import asyncio
from typing import cast

import pytest
from aiohttp import ClientSession

from custom_components.unifi_gateway_refactored.const import ERROR_CODE_5XX
from custom_components.unifi_gateway_refactored.unifi_client import (
    UniFiApiClient,
    UniFiRequestError,
)


class FakeResponse:
    def __init__(
        self, status: int, body: str, headers: dict[str, str] | None = None
    ) -> None:
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def text(self) -> str:
        await asyncio.sleep(0)
        return self._body


class DummySession:
    def __init__(
        self,
        *,
        post_responses: list[object],
        request_responses: list[object],
    ) -> None:
        self.headers: dict[str, str] = {}
        self._post_responses = post_responses
        self._request_responses = request_responses

    def post(self, *args, **kwargs):
        response = self._post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def request(self, *args, **kwargs):
        response = self._request_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_client_retries_timeouts_and_succeeds() -> None:
    session = DummySession(
        post_responses=[FakeResponse(200, "{}")],
        request_responses=[
            asyncio.TimeoutError(),
            asyncio.TimeoutError(),
            FakeResponse(200, '{"data": [{"id": 1}]}', {"ETag": "abc"}),
        ],
    )

    async def _run() -> None:
        client = UniFiApiClient(
            session=cast(ClientSession, session),
            host="test",
            username="user",
            password="pass",
            request_timeout=1,
        )
        await client.async_login()
        data = await client.async_request_health(trace_id="test")
        assert data == [{"id": 1}]

    asyncio.run(_run())


def test_client_raises_for_server_error() -> None:
    session = DummySession(
        post_responses=[FakeResponse(200, "{}")],
        request_responses=[FakeResponse(503, "error")],
    )

    async def _run() -> None:
        client = UniFiApiClient(
            session=cast(ClientSession, session),
            host="test",
            username="user",
            password="pass",
            request_timeout=1,
        )
        await client.async_login()
        with pytest.raises(UniFiRequestError) as err:
            await client.async_request_health(trace_id="test")
        assert err.value.code == ERROR_CODE_5XX

    asyncio.run(_run())


def test_client_uses_etag_cache() -> None:
    first = FakeResponse(200, '{"data": [{"value": 1}]}', {"ETag": "etag"})
    second = FakeResponse(304, "", {"ETag": "etag"})
    session = DummySession(
        post_responses=[FakeResponse(200, "{}")],
        request_responses=[first, second],
    )

    async def _run() -> None:
        client = UniFiApiClient(
            session=cast(ClientSession, session),
            host="test",
            username="user",
            password="pass",
            request_timeout=1,
        )
        await client.async_login()
        result1 = await client.async_request_alerts(trace_id="test")
        result2 = await client.async_request_alerts(trace_id="test")
        assert result1 == [{"value": 1}]
        assert result2 == result1

    asyncio.run(_run())
