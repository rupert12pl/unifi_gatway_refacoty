"""Tests for the UniFi Gateway data coordinator."""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayDataUpdateCoordinator,
)
from custom_components.unifi_gateway_refactored.const import CONF_GW_MAC
from tests.stubs.homeassistant.config_entries import ConfigEntry


def test_persist_gw_mac_handles_missing_options(hass) -> None:
    """Coordinator should create a mutable options mapping when missing."""

    entry = ConfigEntry(entry_id="test-entry", data={}, options=None)
    coordinator = UniFiGatewayDataUpdateCoordinator(
        hass,
        MagicMock(),
        config_entry=entry,
    )

    asyncio.run(coordinator._async_persist_gw_mac("AA:BB:CC:DD:EE:FF"))

    assert entry.options == {CONF_GW_MAC: "aa:bb:cc:dd:ee:ff"}
