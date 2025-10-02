"""Stub implementations of Home Assistant's update coordinator utilities."""
from __future__ import annotations

from typing import Any, Callable, Generic, Optional, TypeVar


T = TypeVar("T")


class UpdateFailed(Exception):
    """Exception raised when an update cannot be completed."""


class DataUpdateCoordinator(Generic[T]):
    """Very small subset of Home Assistant's DataUpdateCoordinator for tests."""

    def __init__(
        self,
        hass: Any,
        *,
        logger: Any,
        name: str,
        update_interval: Optional[Any] = None,
    ) -> None:
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data: Optional[T] = None

    async def async_config_entry_first_refresh(self) -> None:
        """Simulate the first refresh by calling the async update method."""
        self.data = await self._async_update_data()

    async def async_request_refresh(self) -> None:
        """Trigger a refresh using the async update method."""
        self.data = await self._async_update_data()

    async def _async_update_data(self) -> T:  # pragma: no cover - to be overridden
        raise NotImplementedError

    def async_set_updated_data(self, data: T) -> None:
        """Directly set the stored data."""
        self.data = data

    def async_add_listener(self, update_callback: Callable[[], None]) -> Callable[[], None]:
        """Register an update listener and return a removal callback."""

        def _remove() -> None:
            return None

        return _remove


class CoordinatorEntity(Generic[T]):
    """Minimal CoordinatorEntity stub."""

    def __init__(self, coordinator: DataUpdateCoordinator[T]) -> None:
        self.coordinator = coordinator

    async def async_added_to_hass(self) -> None:  # pragma: no cover - compatibility
        return None


__all__ = ["DataUpdateCoordinator", "UpdateFailed", "CoordinatorEntity"]
