from __future__ import annotations

from typing import Any, Dict

FlowResult = Dict[str, Any]


class AbortFlow(Exception):  # noqa: N818 - matches Home Assistant API
    """Raised to signal flow abort."""


__all__ = ["AbortFlow", "FlowResult"]
