"""Minimal Home Assistant core stubs used in tests."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Any, Callable, Coroutine


class _ConfigEntriesManager:
    """Extremely small stub of Home Assistant's config entries manager."""

    async def async_forward_entry_setups(self, entry: Any, platforms: Any) -> bool:
        return True

    async def async_unload_platforms(self, entry: Any, platforms: Any) -> bool:
        return True


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


class _Config:
    """Configuration container mirroring the attributes used in tests."""

    def __init__(self) -> None:
        self.components: set[str] = set()


class HomeAssistant:
    """Extremely small subset of the HomeAssistant core API used in tests."""

    def __init__(self, config_dir: str | None = None) -> None:
        self.config_dir = config_dir
        self.bus = EventBus()
        self.data: dict[str, Any] = {}
        self.config = _Config()
        self.config_entries = _ConfigEntriesManager()
        self._tasks: set[asyncio.Task[Any]] = set()

    async def async_start(self) -> None:
        """Start the Home Assistant instance."""
        return None

    async def async_stop(self) -> None:
        """Stop the Home Assistant instance and cancel pending tasks."""
        for task in list(self._tasks):
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()

    async def async_add_executor_job(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run a synchronous callable in a background thread."""
        return await asyncio.to_thread(func, *args, **kwargs)

    def async_create_task(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        """Schedule an asynchronous task."""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def async_block_till_done(self) -> None:
        """Run the event loop until no tracked tasks remain."""
        while True:
            pending = [task for task in self._tasks if not task.done()]
            if not pending:
                break
            await asyncio.sleep(0)


__all__ = ["HomeAssistant", "EventBus"]
