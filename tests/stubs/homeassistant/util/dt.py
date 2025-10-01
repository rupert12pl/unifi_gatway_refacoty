from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)


def now() -> datetime:
    return datetime.now(timezone.utc)
