"""Stub issue registry for tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


class IssueSeverity:
    WARNING = "warning"
    ERROR = "error"


@dataclass
class IssueRecord:
    domain: str
    issue_id: str
    data: Dict[str, Any]


ISSUES: list[IssueRecord] = []


def async_create_issue(
    hass: Any,
    domain: str,
    issue_id: str,
    *,
    breaks_in_ha_version: str | None,
    is_fixable: bool,
    issue_domain: str,
    translation_key: str,
    severity: str,
    translation_placeholders: Dict[str, Any] | None = None,
) -> None:
    ISSUES.append(
        IssueRecord(
            domain=domain,
            issue_id=issue_id,
            data={
                "breaks_in_ha_version": breaks_in_ha_version,
                "is_fixable": is_fixable,
                "issue_domain": issue_domain,
                "translation_key": translation_key,
                "severity": severity,
                "translation_placeholders": translation_placeholders or {},
            },
        )
    )
