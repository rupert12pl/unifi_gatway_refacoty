import importlib.util
import sys
import types
from pathlib import Path

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

APIError = unifi_client.APIError
UniFiOSClient = unifi_client.UniFiOSClient


def _build_client(responses: dict[str, object], openapi_candidates: list[str] | None = None) -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._site = "default"
    client._base = "https://example.com/proxy/network/api/s/default"
    client._host = "example.com"
    client._port = 443
    client._iid = "test-instance"
    client._vpn_optional_404_paths = {
        "stat/teleport",
        "stat/teleport/clients",
        "stat/teleport/servers",
    }
    client._vpn_last_probe_errors = {}
    client._vpn_last_probe_summary = {}
    client._active_probe_state = None
    client._vpn_cache = None

    def request(self, method: str, url: str, payload=None, expected_errors=None):
        assert method == "GET"
        marker = "/api/s/default/"
        assert marker in url, url
        path = url.split(marker, 1)[1]
        result = responses.get(path)
        if isinstance(result, Exception):
            raise result
        if result is not None:
            return result
        raise APIError(
            "HTTP 404: Not Found",
            status_code=404,
            url=url,
            body="Not Found",
        )

    client._request = types.MethodType(request, client)

    if openapi_candidates is None:
        client._discover_vpn_paths_from_openapi = lambda site: []
    else:
        client._discover_vpn_paths_from_openapi = lambda site: list(openapi_candidates)

    return client


def test_fetch_vpn_snapshot_legacy_remote_user():
    responses = {
        "stat/remoteuser": [
            {
                "_id": "user1",
                "username": "alice",
                "status": "CONNECTED",
                "rx_bytes": 123,
                "tx_bytes": 456,
            }
        ],
    }
    client = _build_client(responses)

    snapshot = client.fetch_vpn_snapshot()

    assert len(snapshot.remote_users) == 1
    remote = snapshot.remote_users[0]
    assert remote["username"] == "alice"
    assert remote["rx_bytes"] == 123
    assert remote["tx_bytes"] == 456
    assert remote.get("state") == "CONNECTED"

    diagnostics = snapshot.diagnostics
    summary = diagnostics["summary"]
    assert summary["probes_attempted"] == 8
    assert summary["probes_succeeded"] == 1
    assert summary["peers_collected"] == 1
    assert summary["fallback_used"] is False

    errors = diagnostics["errors"]
    assert len(errors) == 7
    assert any(error.startswith("list/remoteuser:") for error in errors)
    assert any(error.startswith("stat/vpn:") for error in errors)
    assert any(error.startswith("stat/s2s:") for error in errors)
    assert any(error.startswith("stat/s2speer:") for error in errors)


def test_fetch_vpn_snapshot_openapi_fallback():
    responses = {
        "stat/customvpn": [
            {
                "id": "peer-1",
                "vpn_type": "site_to_site",
                "status": "CONNECTED",
                "rx_bytes": 10,
                "tx_bytes": 20,
            }
        ]
    }
    client = _build_client(responses, openapi_candidates=["stat/customvpn"])

    snapshot = client.fetch_vpn_snapshot()

    assert not snapshot.remote_users
    assert len(snapshot.site_to_site) == 1
    peer = snapshot.site_to_site[0]
    assert peer.get("vpn_type") == "site_to_site"
    assert peer.get("state") == "CONNECTED"

    diagnostics = snapshot.diagnostics
    summary = diagnostics["summary"]
    assert summary["fallback_used"] is True
    assert summary["probes_succeeded"] == 1
    assert summary["peers_collected"] == 1
    assert summary["probes_attempted"] == 10

    errors = diagnostics["errors"]
    assert len(errors) == 9
    assert diagnostics.get("openapi_candidates") == ["stat/customvpn"]
    assert diagnostics.get("successful_paths") == ["stat/customvpn"]
