"""Tests for integration setup."""
from __future__ import annotations

from unittest.mock import AsyncMock

import custom_components.unifi_gateway_refactory as integration
import pytest
from custom_components.unifi_gateway_refactory.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SITE,
    CONF_USERNAME,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.issue_registry import ISSUES


class DummyCoordinator:
    def __init__(self, hass, entry, update_interval=None) -> None:
        self.hass = hass
        self.entry = entry
        self.update_interval = update_interval
        self.data = None
        self.async_config_entry_first_refresh = AsyncMock()


def test_async_setup_entry_creates_issue(
    monkeypatch: pytest.MonkeyPatch, hass, event_loop
) -> None:
    ISSUES.clear()
    entry = ConfigEntry(
        entry_id="entry",
        data={
            CONF_HOST: "gateway.local",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_SITE: "default",
        },
        options={}
    )
    hass.config_entries.add(entry)

    legacy = ConfigEntry(
        entry_id="legacy",
        data={},
        title="Legacy",
        options={},
        domain="unifigateway",
    )
    hass.config_entries.add(legacy)

    monkeypatch.setattr(
        integration,
        "UniFiGatewayDataUpdateCoordinator",
        DummyCoordinator,
    )

    event_loop.run_until_complete(integration.async_setup_entry(hass, entry))

    assert entry.entry_id in hass.data[integration.DOMAIN]
    assert hass.config_entries.forwarded  # platforms forwarded
    assert any(issue.issue_id == integration.ISSUE_LEGACY_DOMAIN for issue in ISSUES)


def test_async_unload_entry(monkeypatch: pytest.MonkeyPatch, hass, event_loop) -> None:
    ISSUES.clear()
    entry = ConfigEntry(entry_id="entry", data={}, options={})
    hass.config_entries.add(entry)

    dummy = DummyCoordinator(hass, entry)
    hass.data.setdefault(integration.DOMAIN, {})[entry.entry_id] = {
        integration.DATA_COORDINATOR: dummy
    }

    async def _forward(entry_obj, platforms):
        hass.config_entries.forwarded.append((entry_obj, tuple(platforms)))

    async def _unload(entry_obj, platforms):
        hass.config_entries.forwarded = []

    monkeypatch.setattr(hass.config_entries, "async_forward_entry_setups", _forward)
    monkeypatch.setattr(hass.config_entries, "async_unload_platforms", _unload)
    monkeypatch.setattr(integration, "UniFiGatewayDataUpdateCoordinator", DummyCoordinator)

    event_loop.run_until_complete(integration.async_setup_entry(hass, entry))
    assert entry.entry_id in hass.data[integration.DOMAIN]

    event_loop.run_until_complete(integration.async_unload_entry(hass, entry))
    assert entry.entry_id not in hass.data[integration.DOMAIN]
