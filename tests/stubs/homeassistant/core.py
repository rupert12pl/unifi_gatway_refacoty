"""Core objects used by the integration tests."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HomeAssistant:
    """Very small subset of the Home Assistant core object."""

    data: dict[str, Any] = field(default_factory=dict)
    config_entries: Any = None

    def __post_init__(self) -> None:
        if self.config_entries is None:
            self.config_entries = DummyConfigEntries()
        self.async_create_task: Callable[[Awaitable[Any]], Any] = lambda coro: coro


class DummyConfigEntries:
    """Stub mimicking the config entries manager."""

    def __init__(self) -> None:
        self._entries: dict[str, Any] = {}

    def async_entries(self, domain: str) -> list[Any]:
        return [entry for entry in self._entries.values() if entry.get("domain") == domain]

    def async_get_entry(self, entry_id: str) -> Any | None:
        return self._entries.get(entry_id)

    def async_update_entry(self, entry: Any, *, data: dict[str, Any]) -> None:
        entry.data.update(data)

    async def async_reload(self, entry_id: str) -> None:
        return None

    async def async_forward_entry_setups(self, entry: Any, platforms: list[str]) -> None:
        entry.forwarded_platforms = platforms

    async def async_unload_platforms(self, entry: Any, platforms: list[str]) -> bool:
        return True

    def async_on_unload(self, callback: Callable[[], None]) -> Callable[[], None]:
        return callback

    def async_create_issue(self, *args: Any, **kwargs: Any) -> None:
        return None
