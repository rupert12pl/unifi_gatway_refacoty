"""Minimal Home Assistant stubs for unit tests."""
from .core import HomeAssistant, EventBus  # noqa: F401
from .exceptions import HomeAssistantError  # noqa: F401

__all__ = [
    "HomeAssistant",
    "EventBus",
    "HomeAssistantError",
]
