"""Core Home Assistant stubs for tests."""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine


class _ConfigEntriesManager:
    """Extremely small stub of Home Assistant's config entries manager."""

    async def async_forward_entry_setups(self, entry: Any, platforms: Any) -> bool:
        return True

    async def async_unload_platforms(self, entry: Any, platforms: Any) -> bool:
        return True

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


class EventBus:
    """Very small async event bus recorder."""

    def __init__(self) -> None:
        self._events: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def events(self) -> list[tuple[str, dict[str, Any] | None]]:
        """Return recorded events."""
        return self._events

    def async_fire(
        self, event_type: str, event_data: dict[str, Any] | None = None
    ) -> None:
        """Record an event fire call."""
        self._events.append((event_type, event_data))


class HomeAssistant:
    """Extremely small subset of the HomeAssistant core API used in tests."""

    def __init__(self) -> None:
        self.bus = EventBus()
        self.data: dict[str, Any] = {}
        self.config_entries = _ConfigEntriesManager()

    async def async_add_executor_job(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run a synchronous callable in a background thread."""
        return await asyncio.to_thread(func, *args, **kwargs)

    def async_create_task(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        """Schedule an asynchronous task."""
        return asyncio.create_task(coro)
