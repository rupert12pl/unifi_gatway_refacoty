"""Stubs for DataUpdateCoordinator used in tests."""
from __future__ import annotations

from typing import Any, Generic, Optional, TypeVar

T = TypeVar("T")


class UpdateFailed(Exception):
    """Raised when an update fails."""


class DataUpdateCoordinator(Generic[T]):
    """Simplified DataUpdateCoordinator."""

    def __init__(
        self,
        hass: Any,
        *,
        logger: Any,
        name: str,
        update_interval: Any | None = None,
    ) -> None:
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data: Optional[T] = None

    async def async_config_entry_first_refresh(self) -> None:
        self.data = await self._async_update_data()

    async def async_request_refresh(self) -> None:
        self.data = await self._async_update_data()

    async def _async_update_data(self) -> T:  # pragma: no cover - override in subclasses
        raise NotImplementedError


class CoordinatorEntity(Generic[T]):
    """Minimal CoordinatorEntity."""

    def __init__(self, coordinator: DataUpdateCoordinator[T]) -> None:
        self.coordinator = coordinator

    async def async_added_to_hass(self) -> None:  # pragma: no cover
        return None
