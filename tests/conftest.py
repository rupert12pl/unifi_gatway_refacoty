"""Pytest configuration for UniFi Gateway Refactory tests."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STUBS_PATH = Path(__file__).parent / "stubs"

for path in (PROJECT_ROOT, STUBS_PATH):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from homeassistant.core import HomeAssistant  # noqa: E402


@pytest.fixture
def event_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.run_until_complete(asyncio.sleep(0))
        loop.close()


@pytest.fixture
def hass(event_loop: asyncio.AbstractEventLoop) -> HomeAssistant:
    """Provide a HomeAssistant test instance."""

    instance = HomeAssistant()
    yield instance

    async def _cleanup() -> None:
        for session in instance.data.get("_sessions", []):
            await session.close()

    event_loop.run_until_complete(_cleanup())
