from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, List

from homeassistant.config_entries import ConfigEntry

from custom_components.unifi_gateway_refactored import sensor
from custom_components.unifi_gateway_refactored.const import DOMAIN
from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData


class DummyEntityRegistryEntry:
    def __init__(self, config_entry_id: str) -> None:
        self.config_entry_id = config_entry_id


class DummyEntityRegistry:
    def __init__(self, entity_id: str, entry: DummyEntityRegistryEntry) -> None:
        self._entity_id = entity_id
        self._entry = entry
        self.entity_id_requests: List[tuple[str, str, str]] = []

    def async_get_entity_id(self, domain: str, platform: str, unique_id: str) -> str | None:
        self.entity_id_requests.append((domain, platform, unique_id))
        return self._entity_id

    def async_get(self, entity_id: str) -> DummyEntityRegistryEntry | None:
        if entity_id == self._entity_id:
            return self._entry
        return None


class DummyClient:
    def instance_key(self) -> str:
        return "instance"

    def get_controller_api_url(self) -> str:
        return "https://controller/api"

    def get_controller_url(self) -> str:
        return "https://controller/ui"

    def get_site(self) -> str:
        return "default"


class DummyCoordinator:
    def __init__(self, data: UniFiGatewayData) -> None:
        self.data = data
        self._listeners: List[Any] = []
        self.refresh_requested = False

    def async_add_listener(self, listener: Any) -> Any:
        self._listeners.append(listener)
        return lambda: None

    async def async_request_refresh(self) -> None:
        self.refresh_requested = True


class EntityCollector:
    def __init__(self) -> None:
        self.static_entities: List[Any] = []
        self.dynamic_entities: List[Any] = []

    def __call__(self, entities: List[Any], update_before_add: bool = False) -> None:
        entity_list = list(entities)
        if update_before_add:
            self.dynamic_entities.extend(entity_list)
        else:
            self.static_entities.extend(entity_list)


def test_health_entities_recreated_when_entry_matches_registry(monkeypatch: Any) -> None:
    entry = ConfigEntry(entry_id="entry-1")
    data = UniFiGatewayData(
        controller={"url": "https://controller/ui", "api_url": "https://controller/api", "site": "default"},
        health=[{"subsystem": "wan", "status": "ok"}],
        wan_links=[],
        lan_networks=[],
        wlans=[],
    )
    coordinator = DummyCoordinator(data)
    client = DummyClient()
    hass = SimpleNamespace(
        data={
            DOMAIN: {
                entry.entry_id: {
                    "client": client,
                    "coordinator": coordinator,
                }
            }
        }
    )

    registry_entry = DummyEntityRegistryEntry(config_entry_id=entry.entry_id)
    registry = DummyEntityRegistry("sensor.unifi_gateway_entry", registry_entry)
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)

    collector = EntityCollector()

    asyncio.run(sensor.async_setup_entry(hass, entry, collector))

    assert any(isinstance(entity, sensor.HealthSensor) for entity in collector.dynamic_entities)
