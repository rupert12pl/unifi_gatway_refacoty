"""Minimal stub implementations for Home Assistant config validation helpers."""

from __future__ import annotations

from typing import Type, cast

import voluptuous as vol

try:
    Invalid = cast(Type[Exception], vol.Invalid)  # type: ignore[attr-defined]
except AttributeError:  # pragma: no cover - stub fallback
    class _VoluptuousInvalid(Exception):
        pass

    Invalid = _VoluptuousInvalid


def boolean(value):
    """Coerce a value to boolean using Home Assistant style semantics."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 0:
            return False
        if value == 1:
            return True
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "on", "yes", "y", "1"}:
            return True
        if normalized in {"false", "off", "no", "n", "0"}:
            return False
    raise Invalid(f"Invalid boolean value: {value!r}")


def string(value):
    """Ensure the provided value is a string."""

    if isinstance(value, str):
        return value
    if value is None:
        raise Invalid("String value cannot be None")
    return str(value)


__all__ = ["boolean", "string"]
