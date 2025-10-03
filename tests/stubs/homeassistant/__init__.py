"""Minimal Home Assistant stubs for unit tests."""

from . import config_entries, loader  # noqa: F401
from .core import EventBus, HomeAssistant  # noqa: F401
from .exceptions import HomeAssistantError  # noqa: F401

__all__ = [
    "HomeAssistant",
    "EventBus",
    "HomeAssistantError",
    "config_entries",
    "loader",
]
