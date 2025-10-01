from __future__ import annotations

from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class UpdateFailed(Exception):
    pass


class DataUpdateCoordinator(Generic[T]):
    def __init__(self, hass, logger, name: str, update_interval) -> None:
        self.hass = hass
        self.logger = logger
        self.name = name
        self.update_interval = update_interval
        self.data: T | None = None
        self.last_update_success = True
        self._listeners: list[Callable[[], None]] = []

    async def async_config_entry_first_refresh(self) -> None:
        await self.async_refresh()

    async def async_refresh(self) -> None:
        self.data = await self._async_update_data()
        self.last_update_success = True
        for listener in list(self._listeners):
            listener()

    async def _async_update_data(self) -> T:
        raise NotImplementedError

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        self._listeners.append(update_callback)
        return lambda: self.async_remove_listener(update_callback)

    def async_remove_listener(self, update_callback: Callable[[], None]) -> None:
        if update_callback in self._listeners:
            self._listeners.remove(update_callback)


class CoordinatorEntity(Generic[T]):
    def __init__(self, coordinator: DataUpdateCoordinator[T]) -> None:
        self.coordinator = coordinator
        coordinator.async_add_listener(self._handle_coordinator_update)

    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()

    def async_write_ha_state(self) -> None:
        return None

    def async_write_ha_state_if_changed(self) -> None:
        self.async_write_ha_state()
