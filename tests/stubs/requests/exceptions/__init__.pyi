"""Requests exception stubs for typing tests."""

class RequestException(Exception): ...  # noqa: N818 - matches requests API


class HTTPError(RequestException): ...


class ConnectionError(RequestException): ...


class Timeout(RequestException): ...


class TooManyRedirects(RequestException): ...
