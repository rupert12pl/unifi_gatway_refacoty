from __future__ import annotations

import pytest

from custom_components.unifi_gateway_refactored.unifi_client import (
    ConnectivityError,
    UniFiOSClient,
)


def _install_http_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    class _DummyCookies:
        def clear(self) -> None:  # pragma: no cover - simple stub
            return None

    class _DummySession:
        def __init__(self) -> None:
            self.verify = True
            self.headers: dict[str, str] = {}
            self.cookies = _DummyCookies()

        def mount(self, *_args, **_kwargs) -> None:  # pragma: no cover - simple stub
            return None

        def close(self) -> None:  # pragma: no cover - simple stub
            return None

    class _DummyAdapter:  # pragma: no cover - simple stub
        def __init__(self, *_args, **_kwargs) -> None:
            return None

    class _DummyRetry:  # pragma: no cover - simple stub
        def __init__(self, *_args, **_kwargs) -> None:
            return None

    def _disable_warnings(_category) -> None:  # pragma: no cover - simple stub
        return None

    dummy_requests = types.ModuleType("requests")
    setattr(dummy_requests, "Session", _DummySession)
    exceptions_module = types.ModuleType("requests.exceptions")
    setattr(exceptions_module, "RequestException", Exception)
    setattr(dummy_requests, "exceptions", exceptions_module)

    dummy_adapters = types.ModuleType("requests.adapters")
    setattr(dummy_adapters, "HTTPAdapter", _DummyAdapter)

    dummy_packages = types.ModuleType("requests.packages")
    urllib3_package = types.ModuleType("requests.packages.urllib3")
    setattr(
        urllib3_package,
        "connectionpool",
        types.ModuleType("requests.packages.urllib3.connectionpool"),
    )
    setattr(dummy_packages, "urllib3", urllib3_package)

    setattr(dummy_requests, "adapters", dummy_adapters)
    setattr(dummy_requests, "packages", dummy_packages)

    dummy_urllib3 = types.ModuleType("urllib3")
    setattr(dummy_urllib3, "disable_warnings", _disable_warnings)
    urllib3_exceptions = types.ModuleType("urllib3.exceptions")
    setattr(urllib3_exceptions, "InsecureRequestWarning", Warning)
    setattr(dummy_urllib3, "exceptions", urllib3_exceptions)

    dummy_retry = types.ModuleType("urllib3.util.retry")
    setattr(dummy_retry, "Retry", _DummyRetry)

    monkeypatch.setitem(sys.modules, "requests", dummy_requests)
    monkeypatch.setitem(sys.modules, "requests.adapters", dummy_adapters)
    monkeypatch.setitem(sys.modules, "requests.packages", dummy_packages)
    monkeypatch.setitem(
        sys.modules,
        "requests.packages.urllib3",
        dummy_packages.urllib3,
    )
    monkeypatch.setitem(
        sys.modules,
        "requests.packages.urllib3.connectionpool",
        dummy_packages.urllib3.connectionpool,
    )
    monkeypatch.setitem(sys.modules, "urllib3", dummy_urllib3)
    monkeypatch.setitem(sys.modules, "urllib3.exceptions", dummy_urllib3.exceptions)
    monkeypatch.setitem(sys.modules, "urllib3.util.retry", dummy_retry)


def _stub_login_factory(fail_ports: set[int]):
    calls: list[tuple[str, int]] = []

    def _login(self: UniFiOSClient, host: str, port: int, ssl_verify: bool, timeout: int) -> None:
        calls.append(("login", port))
        if port in fail_ports:
            raise ConnectivityError(f"fail {port}")

    return calls, _login


def _stub_ensure(calls: list[tuple[str, int]]):
    def _ensure(self: UniFiOSClient) -> None:
        calls.append(("ensure", self._port))  # type: ignore[attr-defined]

    return _ensure


def test_client_falls_back_to_8443(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_http_stubs(monkeypatch)
    calls, login_stub = _stub_login_factory({443})
    monkeypatch.setattr(UniFiOSClient, "_login", login_stub)
    monkeypatch.setattr(UniFiOSClient, "_ensure_connected", _stub_ensure(calls))

    client = UniFiOSClient(
        host="127.0.0.1",
        username="user",
        password="pass",
        port=443,
    )

    assert client.port == 8443
    assert calls == [
        ("login", 443),
        ("login", 8443),
        ("ensure", 8443),
    ]


def test_client_respects_explicit_port_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_http_stubs(monkeypatch)
    calls, login_stub = _stub_login_factory(set())
    monkeypatch.setattr(UniFiOSClient, "_login", login_stub)
    monkeypatch.setattr(UniFiOSClient, "_ensure_connected", _stub_ensure(calls))

    client = UniFiOSClient(
        host="127.0.0.1",
        username="user",
        password="pass",
        port=8443,
    )

    assert client.port == 8443
    assert calls == [
        ("login", 8443),
        ("ensure", 8443),
    ]
