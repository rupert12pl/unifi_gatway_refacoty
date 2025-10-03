from __future__ import annotations

from typing import Any

class HTTPAdapter:
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
    def close(self) -> None: ...
