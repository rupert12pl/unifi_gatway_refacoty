"""Pytest configuration and shared fixtures."""
from __future__ import annotations

# ruff: noqa: E402

import asyncio
import sys
from collections.abc import Generator
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

STUBS_PATH = Path(__file__).parent / "stubs"
if str(STUBS_PATH) not in sys.path:
    sys.path.insert(0, str(STUBS_PATH))

import pytest
from homeassistant.core import HomeAssistant


def pytest_pyfunc_call(pyfuncitem):  # type: ignore[override]
    """Execute async test functions without requiring pytest-asyncio."""

    if inspect.iscoroutinefunction(pyfuncitem.obj):
        sig = inspect.signature(pyfuncitem.obj)
        kwargs = {
            name: pyfuncitem.funcargs[name]
            for name in sig.parameters
            if name in pyfuncitem.funcargs
        }
        loop = pyfuncitem.funcargs.get("event_loop")
        policy = asyncio.get_event_loop_policy()
        try:
            previous_loop = policy.get_event_loop()
        except RuntimeError:
            previous_loop = None
        created_loop = False
        if loop is None:
            loop = asyncio.new_event_loop()
            policy.set_event_loop(loop)
            created_loop = True
        else:
            policy.set_event_loop(loop)
        try:
            loop.run_until_complete(pyfuncitem.obj(**kwargs))
        finally:
            if created_loop:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            policy.set_event_loop(previous_loop)
        return True
    return None


@pytest.fixture
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Provide a dedicated event loop for tests."""

    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        yield loop
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
        asyncio.set_event_loop(None)


@pytest.fixture
def hass(event_loop: asyncio.AbstractEventLoop) -> Generator[HomeAssistant, None, None]:
    """Provide a stubbed HomeAssistant instance for tests."""

    instance = HomeAssistant(str(PROJECT_ROOT / "config"))
    import json

    from homeassistant import config_entries, loader

    # Initialize the integration loader cache
    instance.data[loader.DATA_INTEGRATIONS] = {}
    instance.data[loader.DATA_COMPONENTS] = set()
    instance.data[loader.DATA_CUSTOM_COMPONENTS] = {}
    instance.data[loader.DATA_PRELOAD_PLATFORMS] = set()
    instance.data[loader.DATA_MISSING_PLATFORMS] = set()

    # Load the manifest from the JSON file
    manifest_path = (
        PROJECT_ROOT / "custom_components" / "unifi_gateway_refactored" / "manifest.json"
    )
    with open(manifest_path) as f:
        manifest = json.load(f)

    # Set up the custom component path
    instance.config.components.add("unifi_gateway_refactored")
    instance.config.components.add("sensor")  # Add platform components
    instance.config.components.add("binary_sensor")
    instance.config.components.add("button")

    integration = loader.Integration(
        instance,
        "unifi_gateway_refactored",
        str(PROJECT_ROOT / "custom_components" / "unifi_gateway_refactored"),
        manifest,
    )
    instance.data[loader.DATA_INTEGRATIONS]["unifi_gateway_refactored"] = integration

    instance.config_entries = config_entries.ConfigEntries(instance, {})
    event_loop.run_until_complete(instance.async_start())
    try:
        yield instance
    finally:
        event_loop.run_until_complete(instance.async_stop())


@pytest.fixture
def mock_unifi_client():
    """Mock UniFiOSClient."""
    with patch("custom_components.unifi_gateway_refactored.UniFiOSClient") as mock:
        with patch(
            "custom_components.unifi_gateway_refactored.unifi_client.UniFiOSClient",
            new=mock,
        ):
            yield mock


@pytest.fixture
def mock_coordinator():
    """Mock UniFiGatewayDataUpdateCoordinator."""
    return MagicMock()


@pytest.fixture
def mock_callback():
    """Mock callback function."""
    return MagicMock()


@pytest.fixture(autouse=True)
def fast_asyncio_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid real delays during retry logic tests."""

    async def _sleep(_: float, *args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr("asyncio.sleep", _sleep)
