"""Stub implementations of aiohttp components for unit tests."""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Generator
from dataclasses import dataclass
from typing import Any, TypeVar


@dataclass(slots=True)
class BasicAuth:
    """Minimal stub of aiohttp.BasicAuth."""

    login: str
    password: str
    encoding: str = "utf-8"


class ClientTimeout:
    """Minimal stub of aiohttp.ClientTimeout."""

    def __init__(self, *, total: float | None = None) -> None:
        self.total = total


T_co = TypeVar("T_co", covariant=True)


class _AsyncContextManager(Awaitable[T_co]):
    """Minimal async context manager stub."""

    def __init__(self, enter: Callable[[], Awaitable[T_co]]) -> None:
        self._enter = enter

    def __await__(self) -> Generator[Any, Any, T_co]:  # pragma: no cover - stub
        return self._enter().__await__()

    async def __aenter__(self) -> T_co:  # pragma: no cover - stub
        return await self._enter()

    async def __aexit__(self, *_exc: Any) -> bool:  # pragma: no cover - stub
        return False


class ClientResponse:
    """Placeholder response returned by the client session."""

    status: int

    async def text(self) -> str:  # pragma: no cover - stub
        raise NotImplementedError

    async def json(self, *, content_type: str | None = None) -> Any:  # pragma: no cover - stub
        raise NotImplementedError


class ClientSession:
    """Placeholder type for type checking in tests."""

    def request(self, *_args: Any, **_kwargs: Any) -> _AsyncContextManager[ClientResponse]:
        raise NotImplementedError

