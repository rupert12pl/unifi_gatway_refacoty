"""Minimal entity registry stubs for tests."""

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class RegistryEntry:
    """Class holding entity data registered in the entity registry."""

    entity_id: str
    unique_id: Optional[str] = None
    config_entry_id: Optional[str] = None


class EntityRegistry:
    """Very small registry representation."""

    def __init__(self) -> None:
        """Initialize the entity registry."""
        self.entities: dict[str, RegistryEntry] = {}

    def async_get(self, entity_id: str) -> Optional[RegistryEntry]:
        """Get entity entry from the registry.

        Args:
            entity_id: Entity ID to look up

        Returns:
            Entity entry if found, None otherwise
        """
        return self.entities.get(entity_id)

    def async_get_entity_id(
        self, domain: str, platform: str, unique_id: str
    ) -> Optional[str]:
        """Return entity ID matching the provided unique identifier."""

        for entry in self.entities.values():
            if entry.unique_id == unique_id:
                return entry.entity_id
        return None


def async_get(hass: Any) -> EntityRegistry:  # pragma: no cover - compatibility
    """Return a new registry instance."""
    return EntityRegistry()


async def async_migrate_entries(
    hass: Any,
    domain: str,
    migrate_func: Callable[[RegistryEntry], Any],
) -> None:
    """Stub async migrate entries function."""


__all__ = ["EntityRegistry", "RegistryEntry", "async_get", "async_migrate_entries"]
