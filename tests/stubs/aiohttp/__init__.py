"""Minimal aiohttp stub for unit tests."""

from __future__ import annotations

from typing import Any


class ClientError(Exception):
    """Base client error."""


class ContentTypeError(ClientError):
    """Raised when JSON decoding fails."""


class ClientTimeout:
    def __init__(self, total: float | None = None) -> None:
        self.total = total


class ClientResponse:
    status: int
    headers: dict[str, str]

    async def json(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("not implemented")


class ClientSession:
    def __init__(self, timeout: ClientTimeout | None = None) -> None:
        self.timeout = timeout

    async def __aenter__(self) -> "ClientSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def get(self, *args: Any, **kwargs: Any) -> Any:  # pragma: no cover - network disabled in tests
        raise RuntimeError("aiohttp client session is not available in tests")


__all__ = [
    "ClientError",
    "ClientResponse",
    "ContentTypeError",
    "ClientTimeout",
    "ClientSession",
]
