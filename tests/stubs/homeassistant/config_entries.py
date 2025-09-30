"""Stubs for homeassistant.config_entries."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ConfigEntry:
    """Simplified ConfigEntry used in tests."""

    entry_id: str
    data: Dict[str, Any]
    title: str | None = None
    options: Dict[str, Any] = field(default_factory=dict)
    domain: str = "unifi_gateway_refactory"


class FlowResult(dict):
    """Simple FlowResult container."""


class ConfigFlow:
    """Minimal ConfigFlow base class."""

    VERSION = 1
    domain: str | None = None

    def __init_subclass__(cls, *, domain: str | None = None, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.domain = domain

    def __init__(self) -> None:
        self.context: dict[str, Any] = {}
        self._unique_id: str | None = None

    async def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any,
        errors: dict[str, str] | None = None,
    ) -> FlowResult:
        return FlowResult(
            {
                "type": "form",
                "step_id": step_id,
                "data_schema": data_schema,
                "errors": errors or {},
            }
        )

    def async_abort(self, *, reason: str) -> FlowResult:
        return FlowResult({"type": "abort", "reason": reason})

    async def async_create_entry(self, *, title: str, data: Dict[str, Any]) -> FlowResult:
        return FlowResult({"type": "create_entry", "title": title, "data": data})

    async def async_set_unique_id(self, unique_id: str) -> None:
        self._unique_id = unique_id

    def _abort_if_unique_id_configured(self) -> None:
        return None


class OptionsFlow:
    """Minimal OptionsFlow base class."""

    async def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any,
        errors: dict[str, str] | None = None,
    ) -> FlowResult:
        return FlowResult(
            {
                "type": "form",
                "step_id": step_id,
                "data_schema": data_schema,
                "errors": errors or {},
            }
        )

    async def async_create_entry(self, *, title: str, data: Dict[str, Any]) -> FlowResult:
        return FlowResult({"type": "create_entry", "title": title, "data": data})


__all__ = ["ConfigEntry", "ConfigFlow", "OptionsFlow", "FlowResult"]
