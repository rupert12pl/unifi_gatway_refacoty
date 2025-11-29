"""Tests for UniFi client HTTP handling."""
from __future__ import annotations

import logging
from typing import Any

import pytest

from custom_components.unifi_gateway_refactored.unifi_client import APIError, UniFiOSClient


class _DummyResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text
        self.headers: dict[str, Any] = {}
        self.cookies: dict[str, Any] = {}


class _DummySession:
    def __init__(self, response: _DummyResponse) -> None:
        self._response = response

    def request(self, method: str, url: str, **kwargs: Any) -> _DummyResponse:  # noqa: ARG002
        return self._response


def _make_client(session: _DummySession) -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._scheme = "https"
    client._host = "example.com"
    client._port = 443
    client._path_prefix = "/proxy/network"
    client._site_name = "default"
    client._timeout = 10
    client._session = session
    client._csrf = None
    client._unavailable_paths = {}
    client._username = None
    client._password = None
    return client


@pytest.mark.parametrize(
    "payload",
    ["{\"meta\": {\"rc\": \"error\", \"msg\": \"api.err.IdRequired\"}}", "api.err.IdRequired"],
)
def test_id_required_error_treated_as_expected(
    caplog: pytest.LogCaptureFixture, payload: str
) -> None:
    """HTTP 400 with IdRequired should be treated as expected noise."""

    response = _DummyResponse(400, payload)
    client = _make_client(_DummySession(response))

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(APIError) as err:
            client._request("GET", "stat/user")

    assert err.value.expected is True
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert any("failed" in record.getMessage() for record in caplog.records)
