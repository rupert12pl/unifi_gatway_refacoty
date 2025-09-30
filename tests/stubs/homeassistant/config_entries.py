"""Stub for homeassistant.config_entries."""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ConfigEntry:
    """Simplified ConfigEntry."""

    entry_id: str = "test"
    title: str | None = None
    data: Dict[str, Any] = field(default_factory=dict)


__all__ = ["ConfigEntry"]
