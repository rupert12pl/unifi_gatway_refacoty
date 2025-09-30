"""Minimal subset of voluptuous used in tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Marker:
    key: str
    default: Any | None = None

    def __hash__(self) -> int:  # pragma: no cover - to satisfy dict usage
        return hash((self.key, self.default))

    def __str__(self) -> str:  # pragma: no cover
        return self.key


def Required(key: str, default: Any | None = None) -> Marker:
    return Marker(key, default)


def Optional(key: str, default: Any | None = None) -> Marker:
    return Marker(key, default)


class Schema:
    def __init__(self, schema: Any) -> None:
        self.schema = schema

    def __call__(self, value: Any) -> Any:  # pragma: no cover - passthrough
        return value


def All(*validators: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def _validator(value: Any) -> Any:
        result = value
        for validator in validators:
            result = validator(result)
        return result

    return _validator


def Clamp(*, min: int | None = None, max: int | None = None) -> Callable[[int], int]:
    def _validator(value: int) -> int:
        if min is not None and value < min:
            return min
        if max is not None and value > max:
            return max
        return value

    return _validator
