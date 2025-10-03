"""Lightweight test doubles for ``voluptuous`` validators."""

from __future__ import annotations

import typing as _typing
from typing import Callable

TypingAny = _typing.Any


class Schema:
    """Minimal stand-in for :class:`voluptuous.Schema`."""

    def __init__(self, schema: TypingAny) -> None:
        """Store the provided schema without validation."""
        self.schema = schema

    def __call__(self, data: TypingAny) -> TypingAny:
        """Return data unchanged to mimic successful validation."""
        return data


class Required:
    """Represent a required key in a schema."""

    def __init__(self, key: TypingAny, default: TypingAny | None = None) -> None:
        """Record key metadata for compatibility with voluptuous."""
        self.key = key
        self.default = default


class Optional:
    """Represent an optional key in a schema."""

    def __init__(self, key: TypingAny, default: TypingAny | None = None) -> None:
        """Record key metadata for compatibility with voluptuous."""
        self.key = key
        self.default = default


def All(*validators: TypingAny) -> Callable[[TypingAny], TypingAny]:  # noqa: N802
    """Return a passthrough validator for chained validations."""
    _ = validators

    def _validator(value: TypingAny) -> TypingAny:
        """Return the provided value without applying validation."""
        return value

    return _validator


def Coerce(_type: TypingAny) -> Callable[[TypingAny], TypingAny]:  # noqa: N802
    """Return a validator that mimics ``voluptuous.Coerce`` semantics."""
    _ = _type

    def _validator(value: TypingAny) -> TypingAny:
        """Return the provided value without type coercion."""
        return value

    return _validator


def Clamp(  # noqa: N802
    *, min: TypingAny | None = None, max: TypingAny | None = None
) -> Callable[[TypingAny], TypingAny]:
    """Return a validator that mimics ``voluptuous.Clamp`` semantics."""
    _ = (min, max)

    def _validator(value: TypingAny) -> TypingAny:
        """Return the provided value without range enforcement."""
        return value

    return _validator


def Any(*validators: TypingAny) -> Callable[[TypingAny], TypingAny]:  # noqa: N802
    """Return a passthrough validator for ``voluptuous.Any``."""
    _ = validators

    def _validator(value: TypingAny) -> TypingAny:
        """Return the provided value without applying validation."""
        return value

    return _validator


def In(container: TypingAny) -> Callable[[TypingAny], TypingAny]:  # noqa: N802
    """Return a validator for membership checks in tests."""
    _ = container

    def _validator(value: TypingAny) -> TypingAny:
        """Return the provided value without membership validation."""
        return value

    return _validator
