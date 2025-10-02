"""Stub for homeassistant.helpers.entity_registry."""

from dataclasses import dataclass
from typing import Any, Callable, Optional


@dataclass
class RegistryEntry:
    entity_id: str
    unique_id: Optional[str] = None
    config_entry_id: Optional[str] = None


class EntityRegistry:
    """Very small registry representation."""

    def __init__(self) -> None:
        self.entities: dict[str, RegistryEntry] = {}

    def async_get(self, entity_id: str) -> Optional[RegistryEntry]:
        return self.entities.get(entity_id)


def async_get(hass):  # pragma: no cover - compatibility
    return EntityRegistry()


async def async_migrate_entries(
    hass: Any,
    domain: str,
    migrate_func: Callable[[RegistryEntry], Any],
) -> None:
    return None


__all__ = ["EntityRegistry", "RegistryEntry", "async_get", "async_migrate_entries"]
