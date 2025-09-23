import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

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

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "unifi_gateway_refactored"
    / "unifi_client.py"
)

spec = importlib.util.spec_from_file_location("unifi_client_test_module", MODULE_PATH)
unifi_client = importlib.util.module_from_spec(spec)
assert spec and spec.loader
sys.modules.setdefault("unifi_client_test_module", unifi_client)
spec.loader.exec_module(unifi_client)

UniFiOSClient = unifi_client.UniFiOSClient


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class DummyResponse:
    def __init__(self, status: int) -> None:
        self.status_code = status


def _build_client(responses: dict[str, tuple[int, str]]) -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._scheme = "https"
    client._host = "gateway.local"
    client._port = 443
    client._use_proxy_prefix = True
    client._timeout = 5
    client._ssl_verify = False
    client._site_name = "default"
    client._site = "default"
    client._site_id = "site-1"
    client._vpn_endpoints = None
    client._vpn_endpoint_winners = {}
    client._vpn_probe_candidates = {}
    client._session = None

    async def _mock_request(self, method: str, path: str, **kwargs):
        status, payload = responses.get(path, (404, load_fixture("error_404.json")))
        return DummyResponse(status), payload

    client._request = types.MethodType(_mock_request, client)
    return client


def test_discover_vpn_endpoints_prefers_first_success():
    responses = {
        "/v1/sites/site-1/vpn/remote-access/users": (404, load_fixture("error_404.json")),
        "/v2/api/site/default/internet/vpn/remote-access/users": (404, load_fixture("error_404.json")),
        "/api/s/default/stat/remote-user": (200, load_fixture("legacy_remote_user.json")),
        "/v1/sites/site-1/vpn/site-to-site/peers": (200, load_fixture("v1_s2s_peers.json")),
        "/v1/sites/site-1/vpn/teleport/servers": (204, ""),
        "/v1/sites/site-1/vpn/teleport/clients": (404, load_fixture("error_404.json")),
        "/v2/api/site/default/internet/vpn/teleport/clients": (404, load_fixture("error_404.json")),
        "/api/s/default/stat/teleport/clients": (200, json.dumps([])),
    }

    client = _build_client(responses)

    endpoints = asyncio.run(client._discover_vpn_endpoints(force=True))

    assert endpoints.remote_users == "/api/s/default/stat/remote-user"
    assert endpoints.s2s_peers == "/v1/sites/site-1/vpn/site-to-site/peers"
    assert endpoints.teleport_servers == "/v1/sites/site-1/vpn/teleport/servers"
    assert endpoints.teleport_clients == "/api/s/default/stat/teleport/clients"
    assert endpoints.probes_attempted == 8
    assert "remote_users" in client._vpn_probe_candidates
    assert client._vpn_endpoint_winners["remote_users"].endswith("stat/remote-user")
    assert "teleport_clients" in endpoints.last_errors


def test_get_vpn_state_normalizes_payloads():
    responses = {
        "/api/s/default/stat/remote-user": (200, load_fixture("legacy_remote_user.json")),
        "/v1/sites/site-1/vpn/site-to-site/peers": (200, load_fixture("v1_s2s_peers.json")),
        "/v1/sites/site-1/vpn/teleport/servers": (200, json.dumps([
            {"id": "server-1", "name": "Teleport Server", "state": "CONNECTED", "public_ip": "203.0.113.5"}
        ])),
        "/v1/sites/site-1/vpn/teleport/clients": (200, json.dumps([
            {"id": "client-1", "name": "Laptop", "state": "DOWN", "server_id": "server-1"}
        ])),
    }

    client = _build_client(responses)
    client._vpn_endpoints = asyncio.run(client._discover_vpn_endpoints(force=True))

    vpn_state = asyncio.run(client.get_vpn_state())

    assert vpn_state["counts"] == {
        "remote_users": 1,
        "s2s_peers": 1,
        "teleport_servers": 1,
        "teleport_clients": 1,
    }
    remote = vpn_state["remote_users"][0]
    assert remote["id"]
    assert remote["username"] == "alice"
    assert remote["connected"] is True
    assert remote["rx_bytes"] == 1024
    peer = vpn_state["s2s_peers"][0]
    assert peer["name"] == "HQ"
    assert peer["peer_addr"] == "203.0.113.1"
    diagnostics = vpn_state["diagnostics"]
    assert diagnostics["winner_paths"]["remote_users"].endswith("stat/remote-user")
    assert "families" in diagnostics
