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

from unittest.mock import MagicMock, patch
from homeassistant.core import HomeAssistant  # noqa: E402


@pytest.fixture
async def hass() -> HomeAssistant:
    """Provide a stubbed HomeAssistant instance for tests."""
    instance = HomeAssistant(str(PROJECT_ROOT / "config"))
    from homeassistant import config_entries, loader
    import json
    import custom_components.unifi_gateway_refactored

    # Initialize the integration loader cache
    instance.data[loader.DATA_INTEGRATIONS] = {}
    instance.data[loader.DATA_COMPONENTS] = set()
    instance.data[loader.DATA_CUSTOM_COMPONENTS] = {}
    instance.data[loader.DATA_PRELOAD_PLATFORMS] = set()
    instance.data[loader.DATA_MISSING_PLATFORMS] = set()

    # Load the manifest from the JSON file
    manifest_path = PROJECT_ROOT / "custom_components" / "unifi_gateway_refactored" / "manifest.json"
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
    await instance.async_start()
    yield instance
    await instance.async_stop()


@pytest.fixture
def mock_unifi_client():
    """Mock UniFiOSClient."""
    with patch("custom_components.unifi_gateway_refactored.unifi_client.UniFiOSClient") as mock:
        yield mock


@pytest.fixture
def mock_coordinator():
    """Mock UniFiGatewayDataUpdateCoordinator."""
    return MagicMock()


@pytest.fixture
def mock_callback():
    """Mock callback function."""
    return MagicMock()
