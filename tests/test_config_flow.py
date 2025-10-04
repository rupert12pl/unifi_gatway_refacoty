"""Tests for the UniFi Gateway config and options flows."""

from __future__ import annotations

import asyncio
from typing import Any
from types import SimpleNamespace

import pytest

from custom_components.unifi_gateway_refactored.config_flow import (
    ConfigFlow,
    OptionsFlow,
)
from custom_components.unifi_gateway_refactored.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_TIMEOUT,
    CONF_USERNAME,
)


def run(coro):
    """Execute a coroutine synchronously for test assertions."""

    return asyncio.run(coro)


def test_user_step_strips_host_whitespace(
    hass, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure leading/trailing whitespace is removed from host entries."""

    captured: dict[str, Any] = {}

    def fake_show_form(
        self, *, step_id, data_schema=None, errors=None, description_placeholders=None
    ):
        captured["step_id"] = step_id
        captured["errors"] = errors or {}
        return {"type": "form", "step_id": step_id, "errors": errors or {}}

    monkeypatch.setattr(ConfigFlow, "async_show_form", fake_show_form, raising=False)

    flow = ConfigFlow()
    flow.hass = hass  # type: ignore[assignment]

    result = run(
        flow.async_step_user(
            {
                CONF_HOST: "  udm.local  ",
                CONF_USERNAME: "user",
                CONF_PASSWORD: "pass",
            }
        )
    )

    assert result["step_id"] == "advanced"
    assert captured.get("errors") == {}
    assert flow._cached[CONF_HOST] == "udm.local"


def test_user_step_requires_host(hass, monkeypatch: pytest.MonkeyPatch) -> None:
    """The user step should not continue when host is missing."""

    captured: dict[str, Any] = {}

    def fake_show_form(
        self, *, step_id, data_schema=None, errors=None, description_placeholders=None
    ):
        captured["step_id"] = step_id
        captured["errors"] = errors or {}
        return {"type": "form", "step_id": step_id, "errors": errors or {}}

    monkeypatch.setattr(ConfigFlow, "async_show_form", fake_show_form, raising=False)

    flow = ConfigFlow()
    flow.hass = hass  # type: ignore[assignment]

    result = run(
        flow.async_step_user(
            {
                CONF_HOST: "   ",
                CONF_USERNAME: "user",
                CONF_PASSWORD: "pass",
            }
        )
    )

    assert result["step_id"] == "user"
    assert captured.get("errors", {}).get("base") == "missing_host"
    assert CONF_HOST not in flow._cached


def test_options_flow_rejects_blank_host(
    hass, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Options flow should surface an error when host is blank."""

    entry = SimpleNamespace(
        entry_id="1234",
        data={CONF_HOST: "udm.local", CONF_USERNAME: "user", CONF_PASSWORD: "pass"},
        options={CONF_HOST: "udm.local", CONF_USERNAME: "user", CONF_PASSWORD: "pass"},
    )

    captured: dict[str, Any] = {}

    def fake_options_form(
        self, *, step_id, data_schema=None, errors=None, description_placeholders=None
    ):
        captured["step_id"] = step_id
        captured["errors"] = errors or {}
        return {"type": "form", "step_id": step_id, "errors": errors or {}}

    monkeypatch.setattr(OptionsFlow, "async_show_form", fake_options_form, raising=False)

    flow = OptionsFlow(entry)
    flow.hass = hass  # type: ignore[assignment]

    result = run(
        flow.async_step_init(
            {
                CONF_HOST: " ",
                CONF_USERNAME: "user",
                CONF_PASSWORD: "pass",
            }
        )
    )

    assert result["step_id"] == "init"
    assert captured.get("errors", {}).get("base") == "missing_host"


def test_advanced_step_normalizes_cached_host(
    hass, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure advanced step trims a cached host before validation."""

    validate_payload: dict[str, Any] = {}
    created_entry: dict[str, Any] = {}

    async def fake_validate(_hass: Any, data: dict[str, Any]) -> dict[str, Any]:
        validate_payload.update(data)
        return {}

    async def fake_validate_key(_api_key: str | None) -> None:
        return None

    async def fake_set_unique_id(
        self, unique_id: str, *, raise_on_progress: bool = False
    ) -> None:  # type: ignore[override]
        created_entry["unique_id"] = unique_id

    def fake_abort_if_unique_id_configured(self) -> None:  # type: ignore[override]
        return None

    def fake_create_entry(
        self, *, title: str, data: dict[str, Any]
    ) -> dict[str, Any]:  # type: ignore[override]
        created_entry["title"] = title
        created_entry["data"] = data
        return {"type": "create_entry", "title": title, "data": data}

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate",
        fake_validate,
    )
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate_ui_api_key",
        fake_validate_key,
    )
    monkeypatch.setattr(
        ConfigFlow, "async_set_unique_id", fake_set_unique_id, raising=False
    )
    monkeypatch.setattr(
        ConfigFlow,
        "_abort_if_unique_id_configured",
        fake_abort_if_unique_id_configured,
        raising=False,
    )
    monkeypatch.setattr(
        ConfigFlow, "async_create_entry", fake_create_entry, raising=False
    )

    flow = ConfigFlow()
    flow.hass = hass  # type: ignore[assignment]
    flow._cached = {
        CONF_HOST: "  udm.local  ",
        CONF_USERNAME: "user",
        CONF_PASSWORD: "pass",
        "port": 8443,
    }

    result = run(flow.async_step_advanced({}))

    assert result["type"] == "create_entry"
    assert created_entry["data"][CONF_HOST] == "udm.local"
    assert created_entry["title"] == "UniFi udm.local"
    assert created_entry["unique_id"] == "udm.local:8443"
    assert flow._cached[CONF_HOST] == "udm.local"
    assert validate_payload[CONF_HOST] == "udm.local"


def test_options_flow_normalizes_existing_host(
    hass, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure stored host values are normalized even if unchanged in the form."""

    entry = SimpleNamespace(
        entry_id="host-fix",
        data={
            CONF_HOST: "  udm.local  ",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
        },
        options={},
    )

    async def fake_validate(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {}

    async def fake_validate_key(_api_key: str | None) -> None:
        return None

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate",
        fake_validate,
    )
    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate_ui_api_key",
        fake_validate_key,
    )

    class DummyConfigEntries:
        def __init__(self) -> None:
            self._entries: dict[str, Any] = {entry.entry_id: entry}
            self.data_updates: list[dict[str, Any]] = []

        def async_update_entry(self, entry_to_update, *, data=None, options=None):
            if data is not None:
                snapshot = dict(data)
                entry_to_update.data = snapshot
                self.data_updates.append(snapshot)
            if options is not None:
                entry_to_update.options = dict(options)
            self._entries[entry_to_update.entry_id] = entry_to_update

        def async_get_entry(self, entry_id: str):
            return self._entries.get(entry_id)

    hass.config_entries = DummyConfigEntries()  # type: ignore[attr-defined]

    flow = OptionsFlow(entry)
    flow.hass = hass  # type: ignore[assignment]

    result = run(flow.async_step_init({CONF_TIMEOUT: 20}))

    assert result["type"] == "create_entry"
    assert result["data"][CONF_HOST] == "udm.local"
    assert hass.config_entries.data_updates[-1][CONF_HOST] == "udm.local"
