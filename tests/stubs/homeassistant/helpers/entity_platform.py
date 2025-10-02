"""Stub for homeassistant.helpers.entity_platform."""

from typing import Callable, Iterable, Sequence

AddEntitiesCallback = Callable[[Sequence], None]


def async_add_entities_callback(entities: Iterable, update_before_add: bool = False) -> None:
    """Simple helper mirroring Home Assistant signature."""
    for _ in entities:
        pass
