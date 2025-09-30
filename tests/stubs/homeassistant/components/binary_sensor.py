"""Minimal stubs for binary sensor entities."""
from __future__ import annotations


class BinarySensorEntity:
    """Basic binary sensor entity stub."""

    _attr_should_poll = False

    def __init__(self, *args, **kwargs) -> None:
        self._attr_name = kwargs.get("name")
