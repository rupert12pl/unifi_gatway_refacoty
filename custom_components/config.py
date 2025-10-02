"""Configuration helpers for the UniFi Gateway Dashboard Analyzer integration."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

from .const import (
    CONF_SPEEDTEST_INTERVAL,
    CONF_WIFI_GUEST,
    CONF_WIFI_IOT,
    DEFAULT_SPEEDTEST_ENTITIES,
    DEFAULT_SPEEDTEST_INTERVAL,
    DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
    LEGACY_CONF_SPEEDTEST_INTERVAL_MIN,
)

def split_entity_candidates(text: str) -> list[str]:
    """Split a string into entity candidates."""
    candidates = []
    for candidate in text.replace("\n", ",").split(","):
        cleaned = candidate.strip()
        if cleaned:
            candidates.append(cleaned)
    return candidates

DEFAULT_SPEEDTEST_ENTITY_IDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        candidate
        for raw in DEFAULT_SPEEDTEST_ENTITIES
        for candidate in split_entity_candidates(str(raw))
    )
) or (
    "sensor.speedtest_download",
    "sensor.speedtest_upload",
    "sensor.speedtest_ping",
)

def normalize_speedtest_entity_ids(raw: Any) -> list[str]:
    """Normalize speedtest entity identifiers from options/data into a stable list."""
    normalized: dict[str, None] = {}

    def _add_from_text(text: str) -> None:
        for candidate in split_entity_candidates(text):
            if candidate not in normalized:
                normalized[candidate] = None

    if isinstance(raw, str):
        _add_from_text(raw)
    elif isinstance(raw, (list, tuple, set)):
        for candidate in raw:
            if isinstance(candidate, str):
                _add_from_text(candidate)
            elif candidate is not None:
                text = str(candidate).strip()
                if text:
                    if text not in normalized:
                        normalized[text] = None

    if not normalized:
        return list(DEFAULT_SPEEDTEST_ENTITY_IDS)

    return list(normalized)

def normalize_wifi_option(value: Any) -> Optional[str]:
    """Normalize WiFi option value."""
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        cleaned = str(value).strip()
        return cleaned or None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    cleaned = str(value).strip()
    return cleaned or None

def coerce_int(value: Any) -> Optional[int]:
    """Safely convert value to integer."""
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None

def resolve_speedtest_interval_seconds(
    options: Mapping[str, Any], data: Mapping[str, Any]
) -> int:
    """Determine the configured speedtest interval in seconds with legacy support."""
    speedtest_interval_seconds: int | None = None
    
    # Check primary interval setting
    for source in (options, data):
        candidate = coerce_int(source.get(CONF_SPEEDTEST_INTERVAL))
        if candidate is not None:
            speedtest_interval_seconds = candidate
            break

    # Check legacy minutes setting
    legacy_minutes: int | None = None
    for source in (options, data):
        candidate = coerce_int(source.get(LEGACY_CONF_SPEEDTEST_INTERVAL_MIN))
        if candidate is not None:
            legacy_minutes = candidate
            break

    if legacy_minutes is not None:
        legacy_seconds = max(0, legacy_minutes) * 60
        if (
            legacy_minutes != DEFAULT_SPEEDTEST_INTERVAL_MINUTES
            or speedtest_interval_seconds is None
        ):
            speedtest_interval_seconds = legacy_seconds

    if speedtest_interval_seconds is None:
        speedtest_interval_seconds = DEFAULT_SPEEDTEST_INTERVAL

    return max(0, speedtest_interval_seconds)

def get_wifi_settings(options: Mapping[str, Any], data: Mapping[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """Get WiFi settings from config options and data."""
    wifi_guest = normalize_wifi_option(options.get(CONF_WIFI_GUEST))
    if wifi_guest is None:
        wifi_guest = normalize_wifi_option(data.get(CONF_WIFI_GUEST))

    wifi_iot = normalize_wifi_option(options.get(CONF_WIFI_IOT))
    if wifi_iot is None:
        wifi_iot = normalize_wifi_option(data.get(CONF_WIFI_IOT))

    return wifi_guest, wifi_iot