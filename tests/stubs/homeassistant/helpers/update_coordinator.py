"""Simplified DataUpdateCoordinator implementation for tests."""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class UpdateFailed(Exception):
    """Error raised when an update fails."""


class DataUpdateCoordinator(Generic[T]):
    """Minimal subset of Home Assistant's coordinator."""

    def __init__(
        self,
        hass: Any,
        logger: Any,
        *,
        name: str,
        update_interval: timedelta | None,
    ) -> None:
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data: T | None = None
        self.last_update_success = False

    async def async_config_entry_first_refresh(self) -> None:
        self.data = await self._async_update_data()
        self.last_update_success = True

    async def _async_update_data(self) -> T:
        raise NotImplementedError


class CoordinatorEntity(Generic[T]):
    """Entity subscribed to a DataUpdateCoordinator."""

    def __init__(self, coordinator: DataUpdateCoordinator[T]) -> None:
        self.coordinator = coordinator

    async def async_added_to_hass(self) -> None:
        return None

    def async_write_ha_state(self) -> None:
        return None
