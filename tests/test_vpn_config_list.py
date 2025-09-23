import json
from typing import Any, Callable, Dict, List

from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData
from custom_components.unifi_gateway_refactored.sensor import UniFiGatewaySubsystemSensor
from custom_components.unifi_gateway_refactored.unifi_client import (
    UniFiOSClient,
    VpnAttempt,
    VpnConfigList,
)


class DummyResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = "" if payload is None else json.dumps(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class DummySession:
    def __init__(self, responses: Dict[str, DummyResponse]) -> None:
        self._responses = responses
        self.headers: Dict[str, Any] = {}
        self.requests: List[str] = []

    def get(self, url: str, **_kwargs: Any) -> DummyResponse:
        self.requests.append(url)
        return self._responses.get(url, DummyResponse(404, None))


def build_client(response_map: Dict[str, tuple[int, Any]]) -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._scheme = "https"
    client._host = "gateway.test"
    client._port = 443
    client._ssl_verify = True
    client._timeout = 5
    client._path_prefix = "/proxy/network"
    client._use_proxy_prefix = True
    client._site_name = "default"
    client._site = "default"
    client._session = DummySession({})

    responses: Dict[str, DummyResponse] = {}
    for path, (status, payload) in response_map.items():
        responses[client._join(path)] = DummyResponse(status, payload)

    client._session = DummySession(responses)
    return client


def test_remote_user_primary_endpoint() -> None:
    client = build_client(
        {
            "api/s/default/list/remoteuser": (200, [{"_id": "ru1", "name": "Alice"}]),
            "api/s/default/stat/s2speer": (404, None),
            "api/s/default/stat/s2s": (404, None),
            "api/s/default/stat/teleport/servers": (404, None),
            "api/s/default/stat/teleport/clients": (404, None),
            "v2/api/site/default/setting": (404, None),
        }
    )

    config = client.get_vpn_config_list()

    assert len(config.remote_users) == 1
    assert config.remote_users[0]["name"] == "Alice"
    assert any(
        attempt.path == "api/s/default/list/remoteuser" for attempt in config.attempts
    )
    assert config.winner_paths["remote_users"] == "api/s/default/list/remoteuser"


def test_v2_settings_fallback() -> None:
    settings_payload = {
        "data": [
            {
                "remote_access_vpn": [
                    {"remoteuser_id": "ru-2", "name": "Bob", "profile": "default"}
                ],
                "site_to_site_vpn": [
                    {"peer_name": "HQ", "peer_addr": "203.0.113.1"}
                ],
                "teleport": {
                    "servers": [{"name": "TeleportServer", "id": "srv-1"}],
                    "clients": [{"name": "TeleportClient", "id": "cl-1"}],
                },
            }
        ]
    }

    client = build_client(
        {
            "api/s/default/list/remoteuser": (404, None),
            "api/s/default/stat/remote-user": (400, {"meta": {"rc": "error"}}),
            "api/s/default/stat/s2speer": (404, None),
            "api/s/default/stat/s2s": (400, {"meta": {"rc": "error"}}),
            "api/s/default/stat/teleport/servers": (404, None),
            "api/s/default/stat/teleport/clients": (404, None),
            "v2/api/site/default/setting": (200, settings_payload),
        }
    )

    config = client.get_vpn_config_list()

    assert [item["name"] for item in config.remote_users] == ["Bob"]
    assert [item.get("remote") for item in config.s2s_peers] == ["203.0.113.1"]
    assert [item["name"] for item in config.teleport_servers] == ["TeleportServer"]
    assert [item["name"] for item in config.teleport_clients] == ["TeleportClient"]
    assert config.winner_paths["remote_users"] == "v2/api/site/default/setting#remote_access"
    assert config.winner_paths["s2s_peers"] == "v2/api/site/default/setting#site_to_site"
    assert config.winner_paths["teleport_servers"] == "v2/api/site/default/setting#teleport_servers"
    assert config.winner_paths["teleport_clients"] == "v2/api/site/default/setting#teleport_clients"


def test_all_endpoints_fail() -> None:
    client = build_client(
        {
            "api/s/default/list/remoteuser": (404, None),
            "api/s/default/stat/remote-user": (404, None),
            "api/s/default/stat/s2speer": (404, None),
            "api/s/default/stat/s2s": (404, None),
            "api/s/default/stat/teleport/servers": (404, None),
            "api/s/default/stat/teleport/clients": (404, None),
            "v2/api/site/default/setting": (400, {"meta": {"rc": "error"}}),
        }
    )

    config = client.get_vpn_config_list()

    assert not config.remote_users
    assert not config.s2s_peers
    assert not config.teleport_servers
    assert not config.teleport_clients
    assert len(config.attempts) == 9
    assert config.winner_paths == {}


def test_fetch_json_avoids_double_proxy_prefix() -> None:
    responses: Dict[str, DummyResponse] = {}
    client = build_client({})
    capture_session = DummySession(responses)
    client._session = capture_session

    client._fetch_json("api/s/default/stat/health")

    assert capture_session.requests == [
        "https://gateway.test:443/proxy/network/api/s/default/stat/health"
    ]


def test_vpn_sensor_attribute_snapshot() -> None:
    class DummyCoordinator:
        def __init__(self, data: UniFiGatewayData) -> None:
            self.data = data

        def async_add_listener(self, _listener: Callable[[], None]) -> None:
            return None

    class DummyClient:
        def instance_key(self) -> str:
            return "instance"

    config = VpnConfigList(
        remote_users=[{"id": "ru1", "name": "Alice", "enabled": True}],
        s2s_peers=[{"id": "s2s1", "name": "HQ", "enabled": True, "remote": "203.0.113.2"}],
        teleport_servers=[{"id": "srv1", "name": "TeleportServer"}],
        teleport_clients=[{"id": "cl1", "name": "TeleportClient"}],
        attempts=[
            VpnAttempt(
                path="api/s/default/list/remoteuser",
                status=200,
                ok=True,
                snippet="{}",
            )
        ],
        winner_paths={"remote_users": "api/s/default/list/remoteuser"},
    )

    diagnostics = {
        "counts": {
            "remote_users": 1,
            "s2s_peers": 1,
            "teleport_servers": 1,
            "teleport_clients": 1,
        },
        "attempts": [
            {
                "path": "api/s/default/list/remoteuser",
                "status": 200,
                "ok": True,
                "snippet": "{}",
            }
        ],
        "winner_paths": {"remote_users": "api/s/default/list/remoteuser"},
    }

    data = UniFiGatewayData(
        controller={
            "url": "https://controller.example/ui",
            "api_url": "https://controller.example/api",
            "site": "default",
        },
        health=[{"subsystem": "vpn", "status": "ok", "num_user": 1, "num_guest": 2}],
        health_by_subsystem={
            "vpn": {"subsystem": "vpn", "status": "ok", "num_user": 1, "num_guest": 2}
        },
        vpn_diagnostics=diagnostics,
        vpn_config_list=config,
    )

    coordinator = DummyCoordinator(data)
    sensor = UniFiGatewaySubsystemSensor(
        coordinator,
        DummyClient(),
        "vpn",
        "VPN",
        "mdi:folder-key-network",
    )

    attrs = sensor.extra_state_attributes

    assert attrs == {
        "status": "ok",
        "num_user": 1,
        "num_guest": 2,
        "num_user_total": 3,
        "vpn_diagnostics": diagnostics,
        "configured_vpn": {
            "remote_users": [
                {"id": "ru1", "name": "Alice", "enabled": True}
            ],
            "s2s_peers": [
                {"id": "s2s1", "name": "HQ", "enabled": True, "remote": "203.0.113.2"}
            ],
            "teleport_servers": [{"id": "srv1", "name": "TeleportServer"}],
            "teleport_clients": [{"id": "cl1", "name": "TeleportClient"}],
        },
        "attempts": [
            {
                "path": "api/s/default/list/remoteuser",
                "status": 200,
                "ok": True,
                "snippet": "{}",
            }
        ],
        "winner_paths": {"remote_users": "api/s/default/list/remoteuser"},
        "controller_ui": "https://controller.example/ui",
        "controller_api": "https://controller.example/api",
        "controller_site": "default",
    }
