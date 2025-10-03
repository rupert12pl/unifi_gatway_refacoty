"""Pytest configuration for the UniFi Gateway integration tests."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable, Generator
from pathlib import Path
from typing import TypeVar
from unittest.mock import AsyncMock, MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STUBS_PATH = Path(__file__).parent / "stubs"

if str(STUBS_PATH) not in sys.path:
    sys.path.insert(0, str(STUBS_PATH))

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402  # isort: skip
from homeassistant.core import HomeAssistant  # noqa: E402  # isort: skip

_T = TypeVar("_T")


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Provide a dedicated event loop for tests."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


@pytest.fixture
def hass(
    event_loop: asyncio.AbstractEventLoop,
) -> Generator[HomeAssistant, None, None]:
    """Provide a stubbed HomeAssistant instance for tests."""
    instance = HomeAssistant(str(PROJECT_ROOT / "config"))
    import json

    from homeassistant import config_entries, loader

    instance.loop = event_loop

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
    with open(manifest_path) as file:
        manifest = json.load(file)

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
    yield instance
    event_loop.run_until_complete(instance.async_stop())


@pytest.fixture
def async_run(event_loop: asyncio.AbstractEventLoop) -> Callable[[Awaitable[_T]], _T]:
    """Provide a helper for running coroutines within tests."""

    def runner(awaitable: Awaitable[_T]) -> _T:
        return event_loop.run_until_complete(awaitable)

    return runner


@pytest.fixture
def mock_unifi_client():
    """Mock UniFiOSClient."""
    with patch("custom_components.unifi_gateway_refactored.UniFiOSClient") as mock:
        with patch(
            "custom_components.unifi_gateway_refactored.unifi_client.UniFiOSClient",
            mock,
        ):
            instance = mock.return_value
            instance.ping.return_value = True
            instance.instance_key.return_value = "instance"
            instance.get_controller_api_url.return_value = "https://example/api"
            instance.get_site.return_value = "default"
            instance.get_controller_url.return_value = "https://example"
            instance.get_healthinfo.return_value = []
            instance.get_alerts.return_value = []
            instance.get_devices.return_value = []
            instance.get_networks.return_value = []
            instance.get_wan_links.return_value = []
            instance.get_wlans.return_value = []
            instance.get_clients.return_value = []
            instance.get_last_speedtest.return_value = None
            instance.get_speedtest_status.return_value = {}
            instance.start_speedtest.return_value = None
            instance.ensure_speedtest_monitoring_enabled.return_value = None
            instance.maybe_start_speedtest.return_value = None
            yield mock


@pytest.fixture(autouse=True)
def fast_asyncio_sleep():
    """Ensure integration sleeps do not slow down tests."""
    with patch(
        "custom_components.unifi_gateway_refactored.__init__.asyncio.sleep",
        new=AsyncMock(return_value=None),
    ), patch(
        "custom_components.unifi_gateway_refactored.coordinator.asyncio.sleep",
        new=AsyncMock(return_value=None),
    ), patch(
        "custom_components.unifi_gateway_refactored.monitor.asyncio.sleep",
        new=AsyncMock(return_value=None),
    ), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_MAX_WAIT_S",
        1,
    ), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_POLL_INTERVAL",
        0.01,
    ):
        yield


@pytest.fixture(autouse=True)
def mock_coordinator_class():
    """Mock the UniFiGatewayDataUpdateCoordinator to avoid heavy I/O."""
    with patch(
        "custom_components.unifi_gateway_refactored.UniFiGatewayDataUpdateCoordinator"
    ) as mock_cls:
        with patch(
            "custom_components.unifi_gateway_refactored.coordinator."
            "UniFiGatewayDataUpdateCoordinator",
            mock_cls,
        ):
            instance = mock_cls.return_value
            instance.async_config_entry_first_refresh = AsyncMock(return_value=None)
            instance.async_request_refresh = AsyncMock(return_value=None)
            yield mock_cls


@pytest.fixture
def mock_coordinator():
    """Mock UniFiGatewayDataUpdateCoordinator."""
    return MagicMock()


@pytest.fixture
def mock_callback():
    """Mock callback function."""
    return MagicMock()
