from __future__ import annotations

import asyncio


class ConfigEntriesManager:
    async def async_forward_entry_setups(self, entry, platforms):
        return None

    async def async_unload_platforms(self, entry, platforms) -> bool:
        return True


class HomeAssistant:
    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        self.loop = loop or asyncio.get_event_loop()
        self.data: dict[str, dict] = {}
        self.config_entries = ConfigEntriesManager()

    async def async_start(self) -> None:
        return None

    async def async_stop(self) -> None:
        return None
