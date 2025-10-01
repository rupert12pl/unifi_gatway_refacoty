"""Test configuration for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STUBS_ROOT = Path(__file__).parent / "stubs"

for path in (PROJECT_ROOT, STUBS_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant


@pytest.fixture
def hass() -> "HomeAssistant":
    """Provide a HomeAssistant instance for coordinator tests."""

    from homeassistant.core import HomeAssistant

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return HomeAssistant(loop)
