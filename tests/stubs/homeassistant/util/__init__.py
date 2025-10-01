"""Utility package placeholder for Home Assistant stubs."""

from functools import wraps
from typing import Any, Callable


def Throttle(min_time):  # noqa: N802 - mimic Home Assistant naming
    """Return a decorator that ignores throttling in tests."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        return wrapper

    return decorator


__all__ = ["Throttle"]
