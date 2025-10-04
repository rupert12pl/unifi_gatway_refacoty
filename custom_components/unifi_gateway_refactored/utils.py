"""Utility helpers for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations


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


__all__ = [
    "build_speedtest_button_unique_id",
    "build_reset_button_unique_id",
    "normalize_mac",
]
