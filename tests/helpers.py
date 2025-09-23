"""Testing utilities and Home Assistant stubs for the integration."""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional

REDACTED = "REDACTED"


def _async_redact_data(value: Any, to_redact: set[str]) -> Any:
    """Recursively redact sensitive keys from ``value`` for testing."""

    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            if key in to_redact:
                redacted[key] = REDACTED
            else:
                redacted[key] = _async_redact_data(item, to_redact)
        return redacted
    if isinstance(value, list):
        return [_async_redact_data(item, to_redact) for item in value]
    if isinstance(value, tuple):
        return tuple(_async_redact_data(item, to_redact) for item in value)
    if isinstance(value, set):
        return {_async_redact_data(item, to_redact) for item in value}
    return value


def load_stubs() -> None:
    """Ensure minimal Home Assistant and library stubs are available for tests."""

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    if "homeassistant" not in sys.modules:
        sys.modules["homeassistant"] = types.ModuleType("homeassistant")

    if "homeassistant.const" not in sys.modules:
        const_stub = types.ModuleType("homeassistant.const")

        class Platform(Enum):
            SENSOR = "sensor"
            BINARY_SENSOR = "binary_sensor"

        const_stub.Platform = Platform
        sys.modules["homeassistant.const"] = const_stub

    if "requests" not in sys.modules:
        requests_stub = types.ModuleType("requests")

        class RequestException(Exception):
            pass

        class Session:  # pragma: no cover - minimal stub
            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                self.headers: Dict[str, Any] = {}

            def request(self, *_args: Any, **_kwargs: Any) -> Any:
                raise NotImplementedError

            def get(self, *_args: Any, **_kwargs: Any) -> Any:
                raise NotImplementedError

            def post(self, *_args: Any, **_kwargs: Any) -> Any:
                raise NotImplementedError

            def mount(self, *_args: Any, **_kwargs: Any) -> None:
                return None

        requests_stub.Session = Session
        requests_stub.RequestException = RequestException
        adapters_stub = types.ModuleType("requests.adapters")

        class HTTPAdapter:  # pragma: no cover - minimal stub
            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                return None

        adapters_stub.HTTPAdapter = HTTPAdapter
        requests_stub.adapters = adapters_stub
        sys.modules["requests"] = requests_stub
        sys.modules["requests.adapters"] = adapters_stub

    if "urllib3.util.retry" not in sys.modules:
        retry_stub = types.ModuleType("urllib3.util.retry")

        class Retry:  # pragma: no cover - minimal stub
            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                return None

        retry_stub.Retry = Retry
        sys.modules["urllib3.util.retry"] = retry_stub

    if "homeassistant.components" not in sys.modules:
        sys.modules["homeassistant.components"] = types.ModuleType("homeassistant.components")

    if "homeassistant.components.sensor" not in sys.modules:
        sensor_stub = types.ModuleType("homeassistant.components.sensor")

        class SensorEntity:  # pragma: no cover - simplified base
            _attr_should_poll = False

            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                self.hass = None

            def async_write_ha_state(self) -> None:  # pragma: no cover - no-op
                return None

        class SensorStateClass:  # pragma: no cover - minimal token
            MEASUREMENT = "measurement"

        sensor_stub.SensorEntity = SensorEntity
        sensor_stub.SensorStateClass = SensorStateClass
        sys.modules["homeassistant.components.sensor"] = sensor_stub

    if "homeassistant.components.diagnostics" not in sys.modules:
        diagnostics_stub = types.ModuleType("homeassistant.components.diagnostics")

        def async_redact_data(data: Dict[str, Any], to_redact: Iterable[str]) -> Dict[str, Any]:
            return _async_redact_data(data, set(to_redact))  # pragma: no cover - simple passthrough

        diagnostics_stub.async_redact_data = async_redact_data
        diagnostics_stub.REDACTED = REDACTED
        sys.modules["homeassistant.components.diagnostics"] = diagnostics_stub

    if "homeassistant.config_entries" not in sys.modules:
        entries_stub = types.ModuleType("homeassistant.config_entries")

        @dataclass
        class ConfigEntry:  # pragma: no cover - stub
            entry_id: str = "entry"

        entries_stub.ConfigEntry = ConfigEntry
        sys.modules["homeassistant.config_entries"] = entries_stub

    if "homeassistant.exceptions" not in sys.modules:
        exceptions_stub = types.ModuleType("homeassistant.exceptions")

        class ConfigEntryAuthFailed(Exception):
            pass

        class ConfigEntryNotReady(Exception):
            pass

        exceptions_stub.ConfigEntryAuthFailed = ConfigEntryAuthFailed
        exceptions_stub.ConfigEntryNotReady = ConfigEntryNotReady
        sys.modules["homeassistant.exceptions"] = exceptions_stub

    if "homeassistant.core" not in sys.modules:
        core_stub = types.ModuleType("homeassistant.core")

        class HomeAssistant:  # pragma: no cover - stub
            pass

        core_stub.HomeAssistant = HomeAssistant
        sys.modules["homeassistant.core"] = core_stub

    if "homeassistant.helpers" not in sys.modules:
        sys.modules["homeassistant.helpers"] = types.ModuleType("homeassistant.helpers")

    if "homeassistant.helpers.entity_platform" not in sys.modules:
        platform_stub = types.ModuleType("homeassistant.helpers.entity_platform")
        platform_stub.AddEntitiesCallback = Callable[[Iterable[Any]], None]
        sys.modules["homeassistant.helpers.entity_platform"] = platform_stub

    if "homeassistant.helpers.typing" not in sys.modules:
        typing_stub = types.ModuleType("homeassistant.helpers.typing")
        typing_stub.ConfigType = Dict[str, Any]
        sys.modules["homeassistant.helpers.typing"] = typing_stub

    if "homeassistant.helpers.entity_registry" not in sys.modules:
        er_stub = types.ModuleType("homeassistant.helpers.entity_registry")

        class _DummyRegistry:  # pragma: no cover - minimal registry helper
            def async_get_entity_id(self, *_args: Any, **_kwargs: Any) -> Optional[str]:
                return None

            def async_get(self, *_args: Any, **_kwargs: Any) -> Any:
                return None

        def async_get(_hass: Any) -> _DummyRegistry:  # pragma: no cover - helper
            return _DummyRegistry()

        async def async_migrate_entries(*_args: Any, **_kwargs: Any) -> None:  # pragma: no cover
            return None

        er_stub.async_get = async_get
        er_stub.async_migrate_entries = async_migrate_entries
        er_stub.RegistryEntry = object
        sys.modules["homeassistant.helpers.entity_registry"] = er_stub

    if "homeassistant.helpers.update_coordinator" not in sys.modules:
        coordinator_stub = types.ModuleType("homeassistant.helpers.update_coordinator")

        class CoordinatorEntity:  # pragma: no cover - simple coordinator entity
            def __class_getitem__(cls, _item: Any) -> type:
                return cls

            def __init__(self, coordinator: Any) -> None:
                self.coordinator = coordinator
                self.hass = None

            def async_write_ha_state(self) -> None:  # pragma: no cover - no-op
                return None

        class DataUpdateCoordinator:  # pragma: no cover - stub
            def __class_getitem__(cls, _item: Any) -> type:
                return cls

            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                self.data = None

            async def async_add_listener(self, _listener: Callable[[], None]) -> None:
                return None

        class UpdateFailed(Exception):
            pass

        coordinator_stub.CoordinatorEntity = CoordinatorEntity
        coordinator_stub.DataUpdateCoordinator = DataUpdateCoordinator
        coordinator_stub.UpdateFailed = UpdateFailed
        sys.modules["homeassistant.helpers.update_coordinator"] = coordinator_stub

