"""Common pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from homeassistant.core import HomeAssistant

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


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
