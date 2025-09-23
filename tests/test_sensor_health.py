"""Tests for dynamic health sensor restoration behavior."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.helpers import load_stubs

load_stubs()

from homeassistant.config_entries import ConfigEntry

from custom_components.unifi_gateway_refactored import sensor


class DummyClient:
    """Minimal client stub exposing controller context methods."""

    def get_controller_api_url(self) -> str:
        return "https://controller.example/api"

    def get_controller_url(self) -> str:
        return "https://controller.example/ui"

    def get_site(self) -> str:
        return "default"


class DummyRegistry:
    """Entity registry stub to emulate existing registry entries."""

    def __init__(self, config_entry_id: str | None) -> None:
        self._entity_id = "sensor.test_health"
        self._entry = (
            SimpleNamespace(config_entry_id=config_entry_id)
            if config_entry_id is not None
            else None
        )
        self.requested_unique_ids: list[str] = []

    def async_get_entity_id(self, domain: str, platform: str, unique_id: str) -> str:
        assert domain == "sensor"
        assert platform == sensor.DOMAIN
        self.requested_unique_ids.append(unique_id)
        return self._entity_id

    def async_get(self, entity_id: str):
        assert entity_id == self._entity_id
        return self._entry


@pytest.fixture
def config_entry() -> ConfigEntry:
    return ConfigEntry(entry_id="entry")


@pytest.fixture(autouse=True)
def suppress_entity_state_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid hitting Home Assistant internals when entities update state."""

    monkeypatch.setattr(
        sensor._GatewayDynamicSensor, "_async_write_state", lambda self: None
    )


def test_build_health_entities_recreates_sensor_for_same_entry(
    monkeypatch: pytest.MonkeyPatch, config_entry: ConfigEntry
) -> None:
    """Dynamic health sensors should be recreated when owned by the same entry."""

    registry = DummyRegistry(config_entry.entry_id)
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)

    health_entities: dict[str, sensor.HealthSensor] = {}
    created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=[{"subsystem": "www", "status": "ok"}],
        health_entities=health_entities,
        client=DummyClient(),
    )

    uid = f"{config_entry.entry_id}-health-www"
    assert registry.requested_unique_ids == [uid]
    assert len(created) == 1
    assert uid in health_entities
    assert health_entities[uid] is created[0]


def test_build_health_entities_skips_foreign_registry_owner(
    monkeypatch: pytest.MonkeyPatch, config_entry: ConfigEntry
) -> None:
    """Health sensors belonging to another config entry should not be recreated."""

    registry = DummyRegistry("other-entry")
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)

    health_entities: dict[str, sensor.HealthSensor] = {}
    created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=[{"subsystem": "www", "status": "ok"}],
        health_entities=health_entities,
        client=DummyClient(),
    )

    assert created == []
    assert health_entities == {}
