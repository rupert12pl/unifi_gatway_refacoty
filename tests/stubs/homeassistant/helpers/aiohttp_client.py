"""Stub for Home Assistant aiohttp client helper."""
from __future__ import annotations

import aiohttp

from homeassistant.core import HomeAssistant


def async_get_clientsession(hass: HomeAssistant, verify_ssl: bool = True) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(ssl=None if verify_ssl else False)
    session = aiohttp.ClientSession(connector=connector)
    hass.data.setdefault("_sessions", []).append(session)
    return session
