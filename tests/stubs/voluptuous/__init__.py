"""Stub voluptuous API used in tests."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class _Key:
    key: str
    required: bool
    default: Any = None

    def __hash__(self) -> int:
        return hash((self.key, self.required))


class Schema:
    """Simplified schema wrapper that returns data unchanged."""

    def __init__(self, schema: Any) -> None:
        self.schema = schema

    def __call__(self, data: Any) -> Any:
        return data


def Required(key: str, default: Any = None) -> _Key:
    return _Key(key, True, default)


def Optional(key: str, default: Any = None) -> _Key:
    return _Key(key, False, default)


def All(*validators: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def _validator(value: Any) -> Any:
        result = value
        for validator in validators:
            result = validator(result)
        return result

    return _validator


def Coerce(type_: Callable[[Any], Any]) -> Callable[[Any], Any]:
    def _validator(value: Any) -> Any:
        return type_(value)

    return _validator


def Range(*, min: int | float | None = None, max: int | float | None = None) -> Callable[[Any], Any]:
    def _validator(value: Any) -> Any:
        if min is not None and value < min:
            raise ValueError("value below minimum")
        if max is not None and value > max:
            raise ValueError("value above maximum")
        return value

    return _validator


def In(container: Iterable[Any]) -> Callable[[Any], Any]:
    def _validator(value: Any) -> Any:
        if value not in container:
            raise ValueError("value not allowed")
        return value

    return _validator

