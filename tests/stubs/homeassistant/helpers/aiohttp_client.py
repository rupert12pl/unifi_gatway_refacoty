"""aiohttp client helpers."""
from __future__ import annotations

from typing import Any, cast
from unittest.mock import MagicMock

from aiohttp import ClientSession


def async_get_clientsession(_hass: Any, *, verify_ssl: bool = True) -> ClientSession:
    """Return a mocked aiohttp session suitable for tests."""

    session = MagicMock(spec=ClientSession)
    session.verify_ssl = verify_ssl
    return cast(ClientSession, session)
