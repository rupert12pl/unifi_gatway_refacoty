"""Diagnostics helpers stub."""

from __future__ import annotations

from typing import Any, Iterable

REDACTED = "REDACTED"


def async_redact_data(data: Any, keys_to_redact: Iterable[str]) -> Any:
    """Recursively redact sensitive keys from ``data``."""

    redaction_set = {key for key in keys_to_redact}

    def _redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (REDACTED if key in redaction_set else _redact(subvalue))
                for key, subvalue in value.items()
            }
        if isinstance(value, list):
            return [_redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(_redact(item) for item in value)
        if isinstance(value, set):
            return {_redact(item) for item in value}
        return value

    return _redact(data)


__all__ = ["async_redact_data", "REDACTED"]
