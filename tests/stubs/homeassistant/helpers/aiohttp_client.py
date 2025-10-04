"""Stub for Home Assistant aiohttp client helper used in tests."""

from __future__ import annotations

from typing import Any


def async_get_clientsession(_hass: Any, *, verify_ssl: bool | None = None):
    """Return a simple stub object for the aiohttp client session."""

    class _StubSession:
        async def get(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - unused in tests
            raise RuntimeError("HTTP client not available in stub")

    return _StubSession()


__all__ = ["async_get_clientsession"]
