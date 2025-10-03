from __future__ import annotations

from typing import Any, MutableMapping

from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException

class Response:
    status_code: int
    text: str
    headers: MutableMapping[str, str]
    cookies: MutableMapping[str, Any]
    elapsed: Any
    url: str

    def json(self) -> Any: ...
    def raise_for_status(self) -> None: ...


class Session:
    headers: MutableMapping[str, str]
    cookies: MutableMapping[str, Any]

    def get(self, url: str, *args: Any, **kwargs: Any) -> Response: ...
    def post(self, url: str, *args: Any, **kwargs: Any) -> Response: ...
    def delete(self, url: str, *args: Any, **kwargs: Any) -> Response: ...
    def request(self, method: str, url: str, *args: Any, **kwargs: Any) -> Response: ...
    def close(self) -> None: ...
    def mount(self, prefix: str, adapter: HTTPAdapter) -> None: ...


class PreparedRequest: ...


def request(method: str, url: str, *args: Any, **kwargs: Any) -> Response: ...

def get(url: str, *args: Any, **kwargs: Any) -> Response: ...

def post(url: str, *args: Any, **kwargs: Any) -> Response: ...

def delete(url: str, *args: Any, **kwargs: Any) -> Response: ...


__all__ = [
    "PreparedRequest",
    "RequestException",
    "Response",
    "Session",
    "delete",
    "get",
    "post",
    "request",
]
