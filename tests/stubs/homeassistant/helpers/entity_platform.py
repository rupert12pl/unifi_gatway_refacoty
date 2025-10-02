"""Stub for homeassistant.helpers.entity_platform."""

from typing import Iterable, Protocol, Sequence


class AddEntitiesCallback(Protocol):
    def __call__(self, entities: Sequence, update_before_add: bool = False) -> None:
        ...


def async_add_entities_callback(entities: Iterable, update_before_add: bool = False) -> None:
    """Simple helper mirroring Home Assistant signature."""
    for _ in entities:
        pass
