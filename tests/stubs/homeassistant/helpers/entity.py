from __future__ import annotations

from dataclasses import dataclass
from typing import Set, Tuple


@dataclass
class DeviceInfo:
    identifiers: Set[Tuple[str, str]]
    manufacturer: str | None = None
    model: str | None = None
    name: str | None = None
    configuration_url: str | None = None
