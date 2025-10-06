from __future__ import annotations

from typing import Any as TypingAny, Callable


class Schema:
    def __init__(self, schema: TypingAny) -> None:
        self.schema = schema

    def __call__(self, data: TypingAny) -> TypingAny:
        return data


class Required:
    def __init__(self, key: TypingAny, default: TypingAny | None = None) -> None:
        self.key = key
        self.default = default


class Optional:
    def __init__(self, key: TypingAny, default: TypingAny | None = None) -> None:
        self.key = key
        self.default = default


def All(*validators: TypingAny) -> Callable[[TypingAny], TypingAny]:
    def _validator(value: TypingAny) -> TypingAny:
        return value

    return _validator


def Coerce(_type: TypingAny) -> Callable[[TypingAny], TypingAny]:
    def _validator(value: TypingAny) -> TypingAny:
        return value

    return _validator


def Clamp(
    *, min: TypingAny | None = None, max: TypingAny | None = None
) -> Callable[[TypingAny], TypingAny]:
    def _validator(value: TypingAny) -> TypingAny:
        return value

    return _validator


class _AnyValidator:
    def __init__(self, *validators: TypingAny) -> None:
        self.validators = validators

    def __call__(self, value: TypingAny) -> TypingAny:
        return value


def Any(*validators: TypingAny) -> _AnyValidator:
    return _AnyValidator(*validators)


def In(container: TypingAny) -> Callable[[TypingAny], TypingAny]:
    def _validator(value: TypingAny) -> TypingAny:
        return value

    return _validator


class validators:
    Any = _AnyValidator
