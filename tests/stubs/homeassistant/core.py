"""Core Home Assistant stubs for tests."""
from __future__ import annotations

import asyncio
from typing import Any, Callable


class EventBus:
    """Very small async event bus recorder."""

    def __init__(self) -> None:
        self._events: list[tuple[str, dict[str, Any] | None]] = []

    def async_fire(self, event_type: str, event_data: dict[str, Any] | None = None) -> None:
        self._events.append((event_type, event_data))


class ConfigEntriesManager:
    """Collection of config entries for tests."""

    def __init__(self) -> None:
        self._entries: dict[str, Any] = {}
        self.forwarded: list[tuple[Any, tuple[str, ...]]] = []

    def add(self, entry: Any) -> None:
        self._entries[entry.entry_id] = entry

    def async_entries(self, domain: str | None = None) -> list[Any]:
        if domain is None:
            return list(self._entries.values())
        return [
            entry for entry in self._entries.values() if getattr(entry, "domain", None) == domain
        ]

    async def async_forward_entry_setups(self, entry: Any, platforms: list[str]) -> None:
        self.forwarded.append((entry, tuple(platforms)))

    async def async_unload_platforms(self, entry: Any, platforms: list[str]) -> None:
        self.forwarded = [item for item in self.forwarded if item[0] != entry]

    def async_get_entry(self, entry_id: str) -> Any | None:
        return self._entries.get(entry_id)

    def async_update_entry(
        self,
        entry: Any,
        *,
        data: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        if data is not None:
            entry.data = data
        if options is not None:
            entry.options = options


class HomeAssistant:
    """Extremely small subset of the Home Assistant core API used in tests."""

    def __init__(self) -> None:
        self.bus = EventBus()
        self.data: dict[str, Any] = {}
        self.config_entries = ConfigEntriesManager()

    async def async_add_executor_job(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        return await asyncio.to_thread(func, *args, **kwargs)
