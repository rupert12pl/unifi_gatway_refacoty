"""Tests for Home Assistant setup helpers."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from custom_components.unifi_gateway_refactored import (
    IntegrationRuntime,
    async_update_options,
)
from custom_components.unifi_gateway_refactored.const import (
    CONF_SCAN_INTERVAL,
    CONF_SITE,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
    DOMAIN,
)
from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayApi,
    UniFiGatewayCoordinator,
)


async def test_async_update_options_replaces_session_when_verify_ssl_changes(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify disabling SSL refreshes the API session and warns once."""

    entry = ConfigEntry(
        entry_id="test-entry",
        data={
            "host": "https://example.com",
            "username": "user",
            "password": "pass",
            CONF_SITE: DEFAULT_SITE,
        },
        options={},
    )
    entry.options = {
        CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
        CONF_VERIFY_SSL: False,
    }

    initial_session = MagicMock()
    new_session = MagicMock()

    api = UniFiGatewayApi(
        session=initial_session,
        host="https://example.com",
        username="user",
        password="pass",
        site=DEFAULT_SITE,
        verify_ssl=True,
    )
    coordinator = UniFiGatewayCoordinator(
        hass=hass,
        api=api,
        update_interval_seconds=DEFAULT_SCAN_INTERVAL,
    )
    runtime = IntegrationRuntime(
        coordinator=coordinator,
        api=api,
        options={
            CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
            CONF_VERIFY_SSL: True,
        },
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime

    def fake_get_clientsession(_hass: HomeAssistant, *, verify_ssl: bool) -> MagicMock:
        assert verify_ssl is False
        return new_session

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.async_get_clientsession",
        fake_get_clientsession,
    )

    warnings: list[HomeAssistant] = []

    def fake_log_ssl_warning(hass_obj: HomeAssistant) -> None:
        warnings.append(hass_obj)

    original_update = api.update_client_session

    def spy_update(session: MagicMock, *, verify_ssl: bool) -> None:
        original_update(session, verify_ssl=verify_ssl)
        assert session is new_session
        assert verify_ssl is False

    monkeypatch.setattr(
        api,
        "update_client_session",
        spy_update,
    )
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored._log_ssl_warning_once",
        fake_log_ssl_warning,
    )

    await async_update_options(hass, entry)

    assert runtime.options[CONF_VERIFY_SSL] is False
    assert runtime.coordinator.update_interval_seconds == DEFAULT_SCAN_INTERVAL
    assert runtime.api.verify_ssl is False
    assert warnings == [hass]
    assert runtime.api._session is new_session


async def test_async_update_options_no_change_does_not_replace_session(
    hass: HomeAssistant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure SSL session stays intact when the option is unchanged."""

    entry = ConfigEntry(
        entry_id="entry-two",
        data={
            "host": "https://example.com",
            "username": "user",
            "password": "pass",
            CONF_SITE: DEFAULT_SITE,
        },
        options={},
    )
    entry.options = {
        CONF_SCAN_INTERVAL: 15,
        CONF_VERIFY_SSL: True,
    }

    session = MagicMock()

    api = UniFiGatewayApi(
        session=session,
        host="https://example.com",
        username="user",
        password="pass",
        site=DEFAULT_SITE,
        verify_ssl=True,
    )
    coordinator = UniFiGatewayCoordinator(
        hass=hass,
        api=api,
        update_interval_seconds=DEFAULT_SCAN_INTERVAL,
    )
    runtime = IntegrationRuntime(
        coordinator=coordinator,
        api=api,
        options={
            CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
            CONF_VERIFY_SSL: True,
        },
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime

    def fail_get_clientsession(*_args: object, **_kwargs: object) -> None:
        pytest.fail("async_get_clientsession should not be called when SSL unchanged")

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.async_get_clientsession",
        fail_get_clientsession,
    )

    await async_update_options(hass, entry)

    assert runtime.options[CONF_SCAN_INTERVAL] == 15
    assert runtime.coordinator.update_interval_seconds == 15
    assert runtime.api.verify_ssl is True
    assert runtime.api._session is session
