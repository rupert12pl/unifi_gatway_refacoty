"""Utility helpers for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def build_speedtest_button_unique_id(entry_id: str) -> str:
    """Return a stable unique ID for the Run Speedtest button entity."""

    return f"{entry_id}_run_speedtest"


def build_reset_button_unique_id(entry_id: str) -> str:
    """Return a stable unique ID for the Reset Gateway button entity."""

    return f"{entry_id}_reset_gateway"


def normalize_mac(mac: str | None) -> str | None:
    """Normalize MAC addresses to lowercase colon-delimited format."""

    if not mac:
        return None
    cleaned = mac.strip().lower().replace("-", ":")
    if not cleaned:
        return None
    if ":" not in cleaned and len(cleaned) == 12:
        cleaned = ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))
    elif ":" in cleaned:
        parts = [segment.zfill(2) for segment in cleaned.split(":") if segment]
        if len(parts) == 6:
            cleaned = ":".join(parts)
    stripped = cleaned.replace(":", "")
    if len(stripped) != 12:
        return None
    try:
        int(stripped, 16)
    except ValueError:
        return None
    return ":".join(stripped[i:i + 2] for i in range(0, 12, 2))


def normalize_host_port(host: Any, port: Any | None = None) -> tuple[str | None, int | None]:
    """Normalize host text and derive the port when embedded in the address."""

    def _coerce_port(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        if number <= 0 or number > 65535:
            return None
        return number

    resolved_port = _coerce_port(port)

    if not isinstance(host, str):
        return None, resolved_port

    text = host.strip()
    if not text:
        return None, resolved_port

    candidate = text
    if "//" not in candidate:
        # urlsplit requires a scheme or ``//`` prefix to treat the value as a netloc.
        candidate = f"//{candidate}"

    parsed = urlsplit(candidate, scheme="")

    hostname = parsed.hostname
    if hostname is None:
        # ``urlsplit`` returns the raw path when it cannot determine the hostname.
        path = parsed.path.lstrip("/")
        hostname = path.split("/")[0] if path else None

    derived_port = parsed.port
    if derived_port is not None:
        resolved_port = derived_port
    elif resolved_port is None:
        if parsed.scheme == "https":
            resolved_port = 443
        elif parsed.scheme == "http":
            resolved_port = 80

    return (hostname or None), resolved_port


__all__ = [
    "build_speedtest_button_unique_id",
    "build_reset_button_unique_id",
    "normalize_mac",
    "normalize_host_port",
]
