"""Tests for dynamic health sensor restoration behavior."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.helpers import load_stubs

load_stubs()

# ruff: noqa: E402

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
    created_unique_ids: set[str] = set()
    created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=[{"subsystem": "www", "status": "ok"}],
        health_entities=health_entities,
        client=DummyClient(),
        site_key="site",
        created_unique_ids=created_unique_ids,
    )

    uid = f"{config_entry.entry_id}|site|health|{sensor._sanitize_stable_key('www')}"
    assert registry.requested_unique_ids == [uid]
    assert len(created) == 1
    assert uid in health_entities
    assert health_entities[uid] is created[0]


def test_build_health_entities_restores_sensor_after_restart(
    monkeypatch: pytest.MonkeyPatch, config_entry: ConfigEntry
) -> None:
    """Simulate Home Assistant restart with matching registry entry ownership."""

    registry = DummyRegistry(config_entry.entry_id)
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)

    payload = [{"subsystem": "www", "status": "ok"}]

    # First run populates the registry and active health entity mapping.
    initial_entities: dict[str, sensor.HealthSensor] = {}
    created_unique_ids: set[str] = set()
    first_created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=payload,
        health_entities=initial_entities,
        client=DummyClient(),
        site_key="site",
        created_unique_ids=created_unique_ids,
    )

    uid = f"{config_entry.entry_id}|site|health|{sensor._sanitize_stable_key('www')}"
    assert len(first_created) == 1
    assert uid in initial_entities

    # On restart, the mapping is empty but the registry still owns the entity.
    restarted_entities: dict[str, sensor.HealthSensor] = {}
    restarted_created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=payload,
        health_entities=restarted_entities,
        client=DummyClient(),
        site_key="site",
        created_unique_ids=created_unique_ids,
    )

    assert registry.requested_unique_ids == [uid, uid]
    assert len(restarted_created) == 1
    assert restarted_entities[uid] is restarted_created[0]


def test_build_health_entities_skips_foreign_registry_owner(
    monkeypatch: pytest.MonkeyPatch, config_entry: ConfigEntry
) -> None:
    """Health sensors belonging to another config entry should not be recreated."""

    registry = DummyRegistry("other-entry")
    monkeypatch.setattr(sensor.er, "async_get", lambda _hass: registry)

    health_entities: dict[str, sensor.HealthSensor] = {}
    created_unique_ids: set[str] = set()
    created = sensor._build_health_entities(
        hass=object(),
        entry=config_entry,
        health=[{"subsystem": "www", "status": "ok"}],
        health_entities=health_entities,
        client=DummyClient(),
        site_key="site",
        created_unique_ids=created_unique_ids,
    )

    assert created == []
    assert health_entities == {}
