"""Core Home Assistant stubs for tests."""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from .config_entries import ConfigEntries


class _Config:
    """Minimal configuration container."""

    def __init__(self) -> None:
        self.components: set[str] = set()


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

    def __init__(self, config_dir: str | None = None) -> None:
        self.bus = EventBus()
        self.data: dict[str, Any] = {}
        self.config = _Config()
        self.loop = asyncio.get_event_loop()
        self.config_dir = config_dir
        self.config_entries = ConfigEntries(self, {})

    async def async_add_executor_job(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run a synchronous callable in a background thread."""
        return await asyncio.to_thread(func, *args, **kwargs)

    def async_create_task(self, coro: Coroutine[Any, Any, Any]) -> asyncio.Task[Any]:
        """Schedule an asynchronous task."""
        return asyncio.create_task(coro)

    async def async_block_till_done(self) -> None:
        """Wait for pending tasks to finish."""

        await asyncio.sleep(0)

    async def async_start(self) -> None:
        """Stub out the Home Assistant startup."""

        return None

    async def async_stop(self) -> None:
        """Stub out the Home Assistant shutdown."""

        return None
