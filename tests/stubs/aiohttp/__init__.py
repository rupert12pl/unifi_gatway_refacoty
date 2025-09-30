"""Stub implementations of aiohttp components for unit tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


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


class ClientSession:
    """Placeholder type for type checking in tests."""

    async def request(self, *_args: Any, **_kwargs: Any) -> Any:  # pragma: no cover - stub
        raise NotImplementedError

