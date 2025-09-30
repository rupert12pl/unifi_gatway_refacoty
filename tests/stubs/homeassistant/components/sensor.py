"""Minimal stubs for Home Assistant sensor entities."""
from __future__ import annotations


class SensorEntity:
    """Basic sensor entity stub."""

    _attr_should_poll = False

    def __init__(self, *args, **kwargs) -> None:
        self._attr_name = kwargs.get("name")


class SensorStateClass:
    """Subset of state classes."""

    MEASUREMENT = "measurement"
