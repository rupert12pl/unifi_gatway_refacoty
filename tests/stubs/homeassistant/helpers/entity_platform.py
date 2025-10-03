"""Stub for homeassistant.helpers.entity_platform."""

from typing import Iterable, Protocol, Sequence


class AddEntitiesCallback(Protocol):
    """Protocol for adding entities to a platform."""

    def __call__(self, entities: Sequence, update_before_add: bool = False) -> None:
        """Add entities to the platform.

        Args:
            entities: Sequence of entities to add
            update_before_add: Whether to update entities before adding
        """


def async_add_entities_callback(
    entities: Iterable, update_before_add: bool = False
) -> None:
    """Add entities to a platform.

    Args:
        entities: The entities to add
        update_before_add: Whether to update entities before adding
    """
    for _ in entities:
        pass

    if update_before_add:
        return
