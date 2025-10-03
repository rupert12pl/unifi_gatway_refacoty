"""Pytest configuration and shared fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

STUBS_PATH = Path(__file__).parent / "stubs"
if str(STUBS_PATH) not in sys.path:
    sys.path.insert(0, str(STUBS_PATH))

from homeassistant.core import HomeAssistant  # noqa: E402


@pytest.fixture
def hass() -> HomeAssistant:
    """Provide a stubbed HomeAssistant instance for tests."""
    return HomeAssistant()
