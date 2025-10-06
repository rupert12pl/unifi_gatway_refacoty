"""Lightweight stub of voluptuous_serialize for tests."""
from __future__ import annotations

from typing import Any

try:
    from voluptuous.schema_builder import Schema
except ImportError:  # pragma: no cover - stub fallback
    Schema = object  # type: ignore[assignment]


def convert(schema: Schema | Any) -> dict[str, Any]:
    """Return a minimal serialization for the provided schema.

    The real library returns a structure describing the schema; for tests we only
    need the function to be callable without raising and to produce a truthy
    value when provided a valid schema.
    """

    if hasattr(schema, "schema"):
        serialized = getattr(schema, "schema")
    else:
        serialized = schema
    return {"type": "schema", "schema": serialized}
