from __future__ import annotations

from typing import Any, Dict


class ConfigEntry:
    def __init__(self, **kwargs) -> None:
        self.data: Dict[str, Any] = kwargs.get("data", {})
        self.entry_id: str = kwargs.get("entry_id", "test")
        self.title: str = kwargs.get("title", "UniFi Gateway")
        self.options: Dict[str, Any] = kwargs.get("options", {})


class ConfigFlow:
    VERSION = 1
    DOMAIN: str | None = None
    hass: Any

    def __init_subclass__(cls, **kwargs) -> None:
        cls.DOMAIN = kwargs.get("domain")
        super().__init_subclass__()

    async def async_set_unique_id(self, unique_id: str) -> None:
        self._unique_id = unique_id

    def _abort_if_unique_id_configured(self) -> None:
        return None

    def async_show_form(self, *, step_id: str, data_schema, errors):
        return {"type": "form", "step_id": step_id, "errors": errors}

    def async_create_entry(self, *, title: str, data: dict):
        return {"type": "create_entry", "title": title, "data": data}
