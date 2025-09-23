from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData
from custom_components.unifi_gateway_refactored.const import DEFAULT_SITE
from custom_components.unifi_gateway_refactored.sensor import (
    build_lan_unique_id,
    build_wan_unique_id,
    build_wlan_unique_id,
    resolve_site_key,
)


def test_unique_id_generation_no_duplicates() -> None:
    entry_id = "entry"
    site_key = "site"
    link = {"id": "wan1", "name": "WAN 1"}
    network = {"_id": "lan1", "name": "LAN"}
    wlan = {"name": "MySSID"}

    unique_ids = {
        build_wan_unique_id(entry_id, site_key, link, "status"),
        build_wan_unique_id(entry_id, site_key, link, "ip"),
        build_lan_unique_id(entry_id, site_key, network),
        build_wlan_unique_id(entry_id, site_key, wlan),
    }

    assert len(unique_ids) == 4
    assert build_wan_unique_id(
        entry_id, site_key, link, "status"
    ) == build_wan_unique_id(entry_id, site_key, link, "status")


class DummyClient:
    def __init__(self, site_id: str | None, site: str | None = None) -> None:
        self._site_id = site_id
        self._site = site or DEFAULT_SITE

    def site_id(self) -> str | None:
        return self._site_id

    def get_site(self) -> str:
        return self._site


def test_resolve_site_key_prefers_controller_site_id() -> None:
    client = DummyClient(site_id="Site-ID-123", site="mySite")
    data = UniFiGatewayData(controller={"site": "mySite", "site_id": "Site-ID-123"})

    site_key = resolve_site_key(client, data)

    assert site_key == "site-id-123"


def test_resolve_site_key_falls_back_to_site_name() -> None:
    client = DummyClient(site_id=None, site="MySite")
    data = UniFiGatewayData(controller={"site": "MySite"})

    site_key = resolve_site_key(client, data)

    assert site_key == "mysite"
