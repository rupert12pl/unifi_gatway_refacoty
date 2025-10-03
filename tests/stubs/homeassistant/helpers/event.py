from __future__ import annotations

from datetime import timedelta
from typing import Any, Awaitable, Callable


CallbackType = Callable[[], None]


def async_track_time_interval(
    hass: Any,
    action: Callable[[Any], Awaitable[None] | None],
    interval: timedelta,
) -> CallbackType:
    def _cancel() -> None:
        return None

    return _cancel
