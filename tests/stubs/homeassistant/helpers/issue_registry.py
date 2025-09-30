"""Issue registry stubs."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class IssueSeverity(str, Enum):
    """Enumeration of issue severities."""

    WARNING = "warning"


@dataclass
class Issue:
    """Simple issue representation."""

    issue_id: str
    domain: str
    data: dict[str, Any]


def async_create_issue(
    hass: Any,
    domain: str,
    issue_id: str,
    *,
    is_fixable: bool,
    severity: IssueSeverity,
    translation_key: str,
) -> Issue:
    issue = Issue(issue_id=issue_id, domain=domain, data={
        "is_fixable": is_fixable,
        "severity": severity,
        "translation_key": translation_key,
    })
    hass.data.setdefault("issues", {})[(domain, issue_id)] = issue
    return issue


def async_delete_issue(hass: Any, domain: str, issue_id: str) -> None:
    hass.data.get("issues", {}).pop((domain, issue_id), None)
