from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any, Dict, Optional, cast

import pytest

from custom_components.unifi_gateway_refactored.cloud_client import (
    HostItem,
    UiCloudClient,
    UiCloudRateLimitError,
)
from custom_components.unifi_gateway_refactored.config_flow import OptionsFlow
from custom_components.unifi_gateway_refactored.const import (
    ATTR_REASON,
    CONF_API_KEY,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USERNAME,
)
from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayData,
    UniFiGatewayDataUpdateCoordinator,
)
from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewayWanIpv6Sensor,
)
from custom_components.unifi_gateway_refactored.utils import normalize_mac
from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient
from homeassistant import config_entries


class DummyClient:
    def __init__(self, mac: str) -> None:
        self._mac = mac

    def instance_key(self) -> str:
        return "dummy"

    def get_site(self) -> str:
        return "default"

    def get_controller_url(self) -> None:
        return None

    def get_controller_api_url(self) -> None:
        return None

    def get_gateway_mac(self) -> str:
        return self._mac


class DummyCloudClient:
    def __init__(self, payload: Dict[str, Any] | Exception) -> None:
        self._payload = payload
        self.calls = 0
        self.api_key = "dummy"

    async def async_get_hosts(self) -> Dict[str, Any]:
        self.calls += 1
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class DummyCoordinator(UniFiGatewayDataUpdateCoordinator):
    def __init__(
        self,
        hass,
        data: UniFiGatewayData,
        client: UniFiOSClient,
        cloud_client: DummyCloudClient,
        stored_gw_mac: str | None = None,
    ) -> None:
        self._test_data = data
        super().__init__(
            hass,
            client,
            ui_cloud_client=cast(UiCloudClient, cloud_client),
            config_entry=None,
            stored_gw_mac=stored_gw_mac,
        )

    def _fetch_data(self) -> UniFiGatewayData:
        return self._test_data


def _make_data(mac: str) -> UniFiGatewayData:
    return UniFiGatewayData(
        controller={"url": None, "api_url": None, "site": None},
        health=[],
        health_by_subsystem={},
        wan_health=[{"id": "wan1", "name": "WAN"}],
        alerts=[],
        devices=[],
        wan_links=[{"id": "wan1", "name": "WAN", "mac": mac}],
        networks=[],
        lan_networks=[],
        network_map={},
        wlans=[],
        clients=[],
    )


def test_normalize_mac_variants() -> None:
    assert normalize_mac("F4E2C6C23A63") == "f4:e2:c6:c2:3a:63"
    assert normalize_mac("f4-e2-c6-c2-3a-63") == "f4:e2:c6:c2:3a:63"
    assert normalize_mac("F4:E2:C6:C2:3A:63") == "f4:e2:c6:c2:3a:63"


def test_extract_ipv6_by_exact_gw_mac() -> None:
    items = cast(
        list[HostItem],
        [
            {
                "reportedState": {
                    "wans": [
                        {"mac": "78:45:58:D0:95:75", "ipv6": "2001:db8::1"}
                    ]
                }
            },
            {
                "reportedState": {
                    "wans": [
                        {"mac": "00:11:22:33:44:55", "ipv6": "2001:db8::2"}
                    ]
                }
            },
        ],
    )

    ipv6 = UniFiGatewayDataUpdateCoordinator._extract_ipv6_for_gw_mac(
        items,
        "78:45:58:D0:95:75",
        None,
        None,
        None,
    )

    assert ipv6 == "2001:db8::1"


def test_extract_ipv6_prefers_hw_mac_console() -> None:
    items = cast(
        list[HostItem],
        [
            {
                "hardware": {"mac": "11:11:11:11:11:11"},
                "reportedState": {
                    "hostname": "console-a",
                    "wans": [
                        {"mac": "78:45:58:d0:95:75", "ipv6": "2001:db8::a"}
                    ],
                },
            },
            {
                "hardware": {"mac": "22:22:22:22:22:22"},
                "reportedState": {
                    "hostname": "console-b",
                    "wans": [
                        {"mac": "78:45:58:d0:95:75", "ipv6": "2001:db8::b"}
                    ],
                },
            },
        ],
    )

    ipv6 = UniFiGatewayDataUpdateCoordinator._extract_ipv6_for_gw_mac(
        items,
        "78:45:58:d0:95:75",
        "22:22:22:22:22:22",
        None,
        None,
    )

    assert ipv6 == "2001:db8::b"


def test_no_ipv6_sets_unknown_reason(hass) -> None:
    mac = "78:45:58:d0:95:75"
    data = _make_data(mac)
    cloud_payload = {
        "httpStatusCode": 200,
        "data": [
            {"reportedState": {"wans": [{"mac": mac, "ipv6": ""}]}}
        ],
    }
    client = cast(UniFiOSClient, DummyClient(mac))
    cloud = DummyCloudClient(cloud_payload)
    coordinator = DummyCoordinator(hass, data, client, cloud, stored_gw_mac=mac)

    asyncio.run(coordinator.async_config_entry_first_refresh())

    sensor = UniFiGatewayWanIpv6Sensor(
        coordinator, client, "entry", data.wan_links[0]
    )
    assert sensor.native_value is None
    attrs = sensor.extra_state_attributes
    assert attrs[ATTR_REASON] == "no_ipv6_for_gw"
    assert attrs["gw_mac"] == mac
    assert sensor.available


def test_http_error_sets_unavailable_with_reason(hass) -> None:
    mac = "78:45:58:d0:95:75"
    data = _make_data(mac)
    cloud_payload = {"httpStatusCode": 500, "data": []}
    client = cast(UniFiOSClient, DummyClient(mac))
    cloud = DummyCloudClient(cloud_payload)
    coordinator = DummyCoordinator(hass, data, client, cloud, stored_gw_mac=mac)

    asyncio.run(coordinator.async_config_entry_first_refresh())

    sensor = UniFiGatewayWanIpv6Sensor(
        coordinator, client, "entry", data.wan_links[0]
    )
    attrs = sensor.extra_state_attributes
    assert attrs[ATTR_REASON] == "cloud_status_500"
    assert attrs["available"] is False
    assert sensor.available is False


def test_rate_limit_retry_uses_cache(hass) -> None:
    mac = "78:45:58:d0:95:75"
    data = _make_data(mac)
    client = cast(UniFiOSClient, DummyClient(mac))
    cloud = DummyCloudClient(UiCloudRateLimitError(1.0))
    coordinator = DummyCoordinator(hass, data, client, cloud, stored_gw_mac=mac)

    now = time.monotonic()
    coordinator._wan_ipv6_cache[mac] = (now, "2001:db8::1")

    asyncio.run(coordinator.async_config_entry_first_refresh())

    assert coordinator.data is not None
    data_after = coordinator.data
    assert data_after.wan_ipv6 == "2001:db8::1"
    attrs = data_after.wan_attrs
    assert attrs[ATTR_REASON] == "cloud_rate_limited"


def test_options_flow_saves_api_key_and_reload(hass, monkeypatch: pytest.MonkeyPatch) -> None:
    entry = SimpleNamespace(
        entry_id="1234",
        data={
            CONF_HOST: "udm.local",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_PORT: 443,
            CONF_TIMEOUT: 10,
            CONF_SITE_ID: "default",
        },
        options={},
    )

    async def fake_validate(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
        return {}

    async def fake_validate_key(_api_key: Optional[str]) -> None:
        return None

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate",
        fake_validate,
    )
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate_ui_api_key",
        fake_validate_key,
    )

    updated_options: Dict[str, Any] = {}

    class DummyConfigEntries:
        async def async_update_entry(self, entry_to_update, *, data=None, options=None):
            if options is not None:
                entry_to_update.options = dict(options)
                updated_options.update(options)

    hass.config_entries = DummyConfigEntries()  # type: ignore[attr-defined]

    flow = OptionsFlow(cast(config_entries.ConfigEntry, entry))
    flow.hass = hass  # type: ignore[assignment]

    asyncio.run(flow.async_step_init({CONF_API_KEY: "abc123"}))
    assert entry.options[CONF_API_KEY] == "abc123"
    assert updated_options[CONF_API_KEY] == "abc123"
