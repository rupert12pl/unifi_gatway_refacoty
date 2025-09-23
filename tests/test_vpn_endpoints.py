import asyncio
import importlib.util
import json
import sys
import types
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")

    class _DummySession:  # pragma: no cover - minimal placeholder
        def __init__(self, *args, **kwargs):
            pass

        def post(self, *args, **kwargs):  # pragma: no cover - not used in tests
            raise NotImplementedError

    requests_stub.Session = _DummySession
    requests_stub.RequestException = Exception
    requests_stub.adapters = types.ModuleType("requests.adapters")
    sys.modules["requests"] = requests_stub

if "requests.adapters" not in sys.modules:
    adapters_stub = sys.modules["requests"].adapters  # type: ignore[attr-defined]

    class _DummyHTTPAdapter:  # pragma: no cover - minimal placeholder
        def __init__(self, *args, **kwargs):
            pass

    adapters_stub.HTTPAdapter = _DummyHTTPAdapter
    sys.modules["requests.adapters"] = adapters_stub

if "urllib3.util.retry" not in sys.modules:
    urllib3_retry_stub = types.ModuleType("urllib3.util.retry")

    class _DummyRetry:  # pragma: no cover - minimal placeholder
        def __init__(self, *args, **kwargs):
            pass

    urllib3_retry_stub.Retry = _DummyRetry
    sys.modules["urllib3.util.retry"] = urllib3_retry_stub

PACKAGE_NAME = "custom_components.unifi_gateway_refactored"
MODULE_NAME = f"{PACKAGE_NAME}.unifi_client"

if "homeassistant" not in sys.modules:
    sys.modules["homeassistant"] = types.ModuleType("homeassistant")

if "homeassistant.const" not in sys.modules:
    const_stub = types.ModuleType("homeassistant.const")

    class Platform(Enum):  # pragma: no cover - minimal stub
        SENSOR = "sensor"
        BINARY_SENSOR = "binary_sensor"

    const_stub.Platform = Platform
    sys.modules["homeassistant.const"] = const_stub

if "homeassistant.helpers" not in sys.modules:
    sys.modules["homeassistant.helpers"] = types.ModuleType("homeassistant.helpers")

if "homeassistant.helpers.update_coordinator" not in sys.modules:
    helpers_stub = types.ModuleType("homeassistant.helpers.update_coordinator")

    class CoordinatorEntity:  # pragma: no cover - minimal stub
        def __class_getitem__(cls, _item):
            return cls

        def __init__(self, coordinator):
            self.coordinator = coordinator
            self.hass = None
            if hasattr(coordinator, "async_add_listener"):
                coordinator.async_add_listener(lambda: None)

        def async_write_ha_state(self) -> None:
            return

        def handle_coordinator_update(self) -> None:
            self.async_write_ha_state()

    class DataUpdateCoordinator:  # pragma: no cover - minimal stub
        def __class_getitem__(cls, _item):
            return cls

        def __init__(self, *args, **kwargs):
            self.data = None

        async def async_add_listener(self, listener):
            return None

    class UpdateFailed(Exception):
        pass

    helpers_stub.CoordinatorEntity = CoordinatorEntity
    helpers_stub.DataUpdateCoordinator = DataUpdateCoordinator
    helpers_stub.UpdateFailed = UpdateFailed
    sys.modules["homeassistant.helpers.update_coordinator"] = helpers_stub

if "homeassistant.components" not in sys.modules:
    sys.modules["homeassistant.components"] = types.ModuleType("homeassistant.components")

if "homeassistant.components.binary_sensor" not in sys.modules:
    binary_stub = types.ModuleType("homeassistant.components.binary_sensor")

    class BinarySensorDeviceClass(Enum):  # pragma: no cover - minimal stub
        CONNECTIVITY = "connectivity"

    class BinarySensorEntity:  # pragma: no cover - minimal stub
        def __init__(self, *args, **kwargs):
            self.hass = None
            self._attr_unique_id = None
            self._attr_name = None

        async def async_remove(self) -> None:
            return None

        @property
        def unique_id(self):  # pragma: no cover - simple stub property
            return self._attr_unique_id

        @property
        def name(self):  # pragma: no cover - simple stub property
            return self._attr_name

    binary_stub.BinarySensorDeviceClass = BinarySensorDeviceClass
    binary_stub.BinarySensorEntity = BinarySensorEntity
    sys.modules["homeassistant.components.binary_sensor"] = binary_stub

if "homeassistant.config_entries" not in sys.modules:
    entries_stub = types.ModuleType("homeassistant.config_entries")

    class ConfigEntry:  # pragma: no cover - minimal stub
        def __init__(self, entry_id: str = "entry") -> None:
            self.entry_id = entry_id

    entries_stub.ConfigEntry = ConfigEntry
    sys.modules["homeassistant.config_entries"] = entries_stub

if "homeassistant.core" not in sys.modules:
    core_stub = types.ModuleType("homeassistant.core")

    class HomeAssistant:  # pragma: no cover - minimal stub
        pass

    core_stub.HomeAssistant = HomeAssistant
    sys.modules["homeassistant.core"] = core_stub

if "custom_components" not in sys.modules:
    sys.modules["custom_components"] = types.ModuleType("custom_components")

if PACKAGE_NAME not in sys.modules:
    pkg_module = types.ModuleType(PACKAGE_NAME)
    pkg_module.__path__ = [str(ROOT / "custom_components" / "unifi_gateway_refactored")]
    sys.modules[PACKAGE_NAME] = pkg_module

module_path = ROOT / "custom_components" / "unifi_gateway_refactored" / "unifi_client.py"
spec = importlib.util.spec_from_file_location(MODULE_NAME, module_path)
unifi_client = importlib.util.module_from_spec(spec)
sys.modules[MODULE_NAME] = unifi_client
assert spec and spec.loader
spec.loader.exec_module(unifi_client)

UniFiOSClient = unifi_client.UniFiOSClient
VpnFamily = unifi_client.VpnFamily
VpnProbeError = unifi_client.VpnProbeError
VpnSnapshot = unifi_client.VpnSnapshot


@dataclass
class DummyResponse:
    status_code: int


def _build_client(responses: Dict[str, tuple[int, str]]) -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._scheme = "https"
    client._host = "gateway.local"
    client._port = 443
    client._timeout = 5
    client._ssl_verify = False
    client._use_proxy_prefix = True
    client._path_prefix = ""
    client._site_name = "default"
    client._site = "default"
    client._vpn_snapshot_cache = {}
    client._vpn_family_cache = {}
    client._vpn_family_override = None
    client._vpn_last_probe_errors = {}
    client._vpn_last_probe_summary = {}
    client._vpn_cache = None
    client._vpn_expected_errors_reported = False

    async def _mock_request(self, method: str, path: str, **kwargs):
        status, payload = responses.get(path, (404, json.dumps({"error": "not found"})))
        return DummyResponse(status), payload

    client._request = types.MethodType(_mock_request, client)
    return client


def _snapshot_connections(snapshot: VpnSnapshot) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "remote_users": snapshot.remote_users,
        "s2s_peers": snapshot.s2s_peers,
        "teleport_servers": snapshot.teleport_servers,
        "teleport_clients": snapshot.teleport_clients,
    }


def test_v2_snapshot_success():
    responses = {
        "v2/api/site/default/internet/vpn/remote-access/users": (
            200,
            json.dumps([
                {
                    "id": "ru-1",
                    "username": "alice",
                    "state": "CONNECTED",
                    "rx_bytes": 512,
                    "tx_bytes": 1024,
                    "remote_ip": "198.51.100.10",
                }
            ]),
        ),
        "v2/api/site/default/internet/vpn/site-to-site/peers": (
            200,
            json.dumps([
                {
                    "id": "s2s-1",
                    "name": "HQ",
                    "state": "up",
                    "peer_addr": "203.0.113.1",
                }
            ]),
        ),
        "v2/api/site/default/internet/vpn/teleport/servers": (
            200,
            json.dumps([
                {"id": "server-1", "name": "Teleport Hub", "state": "CONNECTED"}
            ]),
        ),
        "v2/api/site/default/internet/vpn/teleport/clients": (
            200,
            json.dumps([
                {"id": "client-1", "name": "Laptop", "state": "DISCONNECTED"}
            ]),
        ),
    }

    client = _build_client(responses)

    snapshot = asyncio.run(client.get_vpn_snapshot("default"))

    assert snapshot.family == VpnFamily.V2
    connections = _snapshot_connections(snapshot)
    assert len(connections["remote_users"]) == 1
    assert len(connections["s2s_peers"]) == 1
    assert snapshot.remote_users[0]["connected"] is True
    assert snapshot.remote_users[0]["kind"] == "remote_user"
    assert snapshot.attempts and all(attempt.ok for attempt in snapshot.attempts)
    assert snapshot.fallback_used is False


def test_legacy_snapshot_fallback():
    responses = {
        "v2/api/site/default/internet/vpn/remote-access/users": (404, "{}"),
        "v2/api/site/default/internet/vpn/site-to-site/peers": (404, "{}"),
        "v2/api/site/default/internet/vpn/teleport/servers": (404, "{}"),
        "v2/api/site/default/internet/vpn/teleport/clients": (404, "{}"),
        "api/s/default/list/remoteuser": (
            200,
            json.dumps([
                {
                    "id": "legacy-user-1",
                    "username": "bob",
                    "connected": True,
                    "rx_bytes": 2048,
                }
            ]),
        ),
        "api/s/default/stat/s2speer": (
            200,
            json.dumps([
                {
                    "id": "peer-legacy",
                    "peer_name": "Branch",
                    "state": "CONNECTED",
                }
            ]),
        ),
        "api/s/default/stat/s2s": (404, "{}"),
        "api/s/default/stat/teleport/servers": (404, "{}"),
        "api/s/default/stat/teleport/clients": (404, "{}"),
    }

    client = _build_client(responses)

    snapshot = asyncio.run(client.get_vpn_snapshot("default"))

    assert snapshot.family == VpnFamily.LEGACY
    assert snapshot.fallback_used is True
    assert snapshot.remote_users[0]["name"].lower().startswith("bob")
    assert any(attempt.status == 404 for attempt in snapshot.attempts)
    assert len(snapshot.s2s_peers) == 1


def test_snapshot_failure_aggregates_attempts():
    responses = {
        "v2/api/site/default/internet/vpn/remote-access/users": (404, "{}"),
        "v2/api/site/default/internet/vpn/site-to-site/peers": (404, "{}"),
        "v2/api/site/default/internet/vpn/teleport/servers": (404, "{}"),
        "v2/api/site/default/internet/vpn/teleport/clients": (404, "{}"),
        "api/s/default/list/remoteuser": (404, "{}"),
        "api/s/default/stat/remote-user": (404, "{}"),
        "api/s/default/stat/s2speer": (404, "{}"),
        "api/s/default/stat/s2s": (404, "{}"),
        "api/s/default/stat/teleport/servers": (404, "{}"),
        "api/s/default/stat/teleport/clients": (404, "{}"),
    }

    client = _build_client(responses)

    with pytest.raises(VpnProbeError) as errinfo:
        asyncio.run(client.get_vpn_snapshot("default"))

    error = errinfo.value
    assert len(error.attempts) == 3
    assert all(attempt.status in {404} for attempt in error.attempts)


def test_connection_unique_id_stability():
    from custom_components.unifi_gateway_refactored.binary_sensor import (
        VpnConnectionBinarySensor,
    )

    class DummyCoordinator:
        def __init__(self, data):
            self.data = data

        def async_add_listener(self, listener):  # pragma: no cover - coordinator stub
            return lambda: None

    snapshot = VpnSnapshot(
        family=VpnFamily.V2,
        site="default",
        remote_users=[
            {
                "id": "user-1",
                "kind": "remote_user",
                "name": "Alice",
                "connected": True,
            }
        ],
        s2s_peers=[],
        teleport_servers=[],
        teleport_clients=[],
        attempts=[],
    )

    coordinator = DummyCoordinator(data=SimpleNamespace(vpn_snapshot=snapshot))

    entity = VpnConnectionBinarySensor(
        coordinator,
        object(),
        entry_id="entry-1",
        unique_id="vpn|entry-1|default|remote_user|user-1",
        connection=snapshot.remote_users[0],
        snapshot=snapshot,
        controller_context={"controller_ui": "https://gateway"},
    )

    assert entity.unique_id == "vpn|entry-1|default|remote_user|user-1"
    assert entity.is_on is True
    assert entity.extra_state_attributes["kind"] == "remote_user"


def test_entity_manager_add_remove():
    from custom_components.unifi_gateway_refactored.binary_sensor import (
        VpnEntityManager,
    )

    class DummyHass:
        def __init__(self):
            self.tasks = []

        def async_create_task(self, coro):  # pragma: no cover - simple stub
            self.tasks.append(asyncio.ensure_future(coro))
            return self.tasks[-1]

    class DummyEntry:
        def __init__(self, entry_id: str) -> None:
            self.entry_id = entry_id

    class DummyClient:
        def get_controller_url(self) -> str:
            return "https://gateway"

        def get_controller_api_url(self) -> str:
            return "https://gateway/api"

        def get_site(self) -> str:
            return "default"

    class DummyCoordinator:
        def __init__(self, data):
            self.data = data

        def async_add_listener(self, listener):  # pragma: no cover - stub
            self._listener = listener
            return lambda: None

    snapshot1 = VpnSnapshot(
        family=VpnFamily.V2,
        site="default",
        remote_users=[
            {
                "id": "user-1",
                "kind": "remote_user",
                "name": "Alice",
                "connected": True,
            }
        ],
        s2s_peers=[],
        teleport_servers=[],
        teleport_clients=[],
        attempts=[],
    )

    snapshot2 = VpnSnapshot(
        family=VpnFamily.V2,
        site="default",
        remote_users=[
            {
                "id": "user-1",
                "kind": "remote_user",
                "name": "Alice",
                "connected": False,
            }
        ],
        s2s_peers=[
            {
                "id": "peer-1",
                "kind": "s2s_peer",
                "name": "Branch",
                "connected": True,
            }
        ],
        teleport_servers=[],
        teleport_clients=[],
        attempts=[],
    )

    snapshot3 = VpnSnapshot(
        family=VpnFamily.V2,
        site="default",
        remote_users=[],
        s2s_peers=[
            {
                "id": "peer-1",
                "kind": "s2s_peer",
                "name": "Branch",
                "connected": False,
            }
        ],
        teleport_servers=[],
        teleport_clients=[],
        attempts=[],
    )

    hass = DummyHass()
    entry = DummyEntry("entry-1")
    client = DummyClient()
    coordinator = DummyCoordinator(SimpleNamespace(vpn_snapshot=snapshot1))
    added: list = []

    def _add_entities(entities):
        added.extend(entities)

    manager = VpnEntityManager(hass, entry, client, coordinator, _add_entities)
    asyncio.run(manager.async_setup())

    assert len(manager._entities) == 1
    assert manager._entities[
        "vpn|entry-1|default|remote_user|user-1"
    ].is_on is True

    added.clear()
    coordinator.data = SimpleNamespace(vpn_snapshot=snapshot2)
    asyncio.run(manager._async_sync())

    assert len(manager._entities) == 2
    assert any(
        entity.unique_id == "vpn|entry-1|default|s2s_peer|peer-1" for entity in manager._entities.values()
    )
    assert len(added) == 1  # only the new peer entity should be added

    added.clear()
    coordinator.data = SimpleNamespace(vpn_snapshot=snapshot3)
    asyncio.run(manager._async_sync())

    assert len(manager._entities) == 1
    assert "vpn|entry-1|default|remote_user|user-1" not in manager._entities
