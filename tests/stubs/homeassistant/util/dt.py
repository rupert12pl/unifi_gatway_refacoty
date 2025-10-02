"""Simplified datetime utilities mimicking Home Assistant helpers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_datetime(value: str | None) -> Optional[datetime]:
    """Parse an ISO-formatted datetime string."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def as_utc(value: datetime) -> datetime:
    """Return a timezone-aware datetime in UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def as_local(value: datetime) -> datetime:
    """Return the provided datetime without modification (local timezone stub)."""
    return value


__all__ = ["parse_datetime", "as_utc", "as_local"]
