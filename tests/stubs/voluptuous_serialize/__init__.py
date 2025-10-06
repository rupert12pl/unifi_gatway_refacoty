"""Stub implementation of voluptuous_serialize for unit tests."""

from __future__ import annotations

from typing import Any, Callable, Mapping


def convert(schema: Any, custom_serializer: Callable[[Any], Any] | None = None) -> Mapping[str, Any]:
    """Return a simple mapping representing the provided schema."""

    if callable(custom_serializer):
        custom_serializer(schema)
    return {"schema": schema}


__all__ = ["convert"]
