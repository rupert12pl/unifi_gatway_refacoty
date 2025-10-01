"""Core Home Assistant stubs for tests."""
from __future__ import annotations

import asyncio
from typing import Any, Callable


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

    async def async_add_executor_job(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Run a synchronous callable in a background thread."""
        return await asyncio.to_thread(func, *args, **kwargs)
