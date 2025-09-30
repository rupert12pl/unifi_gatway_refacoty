"""Common pytest fixtures."""
from __future__ import annotations

import asyncio
import inspect
import sys
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STUBS = PROJECT_ROOT / "tests" / "stubs"
for path in (STUBS, PROJECT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from typing import Any  # noqa: E402

import pytest  # noqa: E402
from _pytest.python import Function  # noqa: E402
from homeassistant.core import HomeAssistant  # noqa: E402


@pytest.fixture
def hass() -> HomeAssistant:
    """Return a minimal Home Assistant mock."""
    hass = MagicMock(spec=HomeAssistant)
    hass.data = {}
    hass.config_entries = MagicMock()
    hass.config_entries.async_entry_for_domain_unique_id.return_value = None
    hass.config_entries.async_update_entry.return_value = False
    hass.config_entries.async_schedule_reload = MagicMock()
    hass.async_create_task = MagicMock()
    return hass


def pytest_pyfunc_call(pyfuncitem: Function) -> bool | None:
    """Execute async tests without requiring external plugins."""

    if asyncio.iscoroutinefunction(pyfuncitem.obj):
        loop = asyncio.new_event_loop()
        try:
            signature = inspect.signature(pyfuncitem.obj)
            kwargs: dict[str, Any] = {
                name: pyfuncitem.funcargs[name]
                for name in signature.parameters
                if name in pyfuncitem.funcargs
            }
            loop.run_until_complete(pyfuncitem.obj(**kwargs))
        finally:
            loop.close()
        return True
    return None
