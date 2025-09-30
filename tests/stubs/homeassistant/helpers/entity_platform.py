"""Entity platform helper stubs."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

AddEntitiesCallback = Callable[[Iterable[Any]], None]
