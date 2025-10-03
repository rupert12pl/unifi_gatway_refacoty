"""Test the UniFi Gateway async wrapper and coordinator."""
import pytest
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from pytest_homeassistant_custom_component.common import MockConfigEntry

from itertools import chain, repeat

from custom_components.unifi_gateway_refactored.const import DOMAIN
from custom_components.unifi_gateway_refactored.unifi_client import ConnectivityError


def test_async_setup_retry_logic(hass: HomeAssistant, mock_unifi_client) -> None:
    """Test retry logic during setup."""
    # Simulate a slow device that fails twice before succeeding
    mock_unifi_client.return_value.ping.side_effect = chain(
        [
            ConnectivityError("Timeout"),
            ConnectivityError("Timeout"),
            True,
        ],
        repeat(True),
    )

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "1.1.1.1",
            CONF_USERNAME: "test",
            CONF_PASSWORD: "test"
        }
    )

    entry.add_to_hass(hass)
    loop = hass.loop
    loop.run_until_complete(hass.config_entries.async_setup(entry.entry_id))
    loop.run_until_complete(hass.async_block_till_done())

    # Verify that ping was called exactly 4 times (3 retries + coordinator check)
    assert mock_unifi_client.return_value.ping.call_count == 4

    # Verify that the client was stored in hass.data
    assert DOMAIN in hass.data
    assert entry.entry_id in hass.data[DOMAIN]
    assert "client" in hass.data[DOMAIN][entry.entry_id]

def test_setup_all_retries_failed(
    hass: HomeAssistant, mock_unifi_client
) -> None:
    """Test that setup fails after all retries fail."""
    # Simulate a device that always times out
    mock_unifi_client.return_value.ping.side_effect = ConnectivityError("Timeout")

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "1.1.1.1",
            CONF_USERNAME: "test",
            CONF_PASSWORD: "test"
        }
    )

    entry.add_to_hass(hass)
    with pytest.raises(ConfigEntryNotReady):
        hass.loop.run_until_complete(hass.config_entries.async_setup(entry.entry_id))
    hass.loop.run_until_complete(hass.async_block_till_done())

    # Verify that ping was called exactly 3 times
    assert mock_unifi_client.return_value.ping.call_count == 3

    # Verify that no client was stored
    assert DOMAIN in hass.data
    assert entry.entry_id not in hass.data[DOMAIN]
