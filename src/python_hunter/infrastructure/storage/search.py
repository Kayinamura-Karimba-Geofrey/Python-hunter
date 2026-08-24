"""Scalable Search & Cursor Pagination Abstraction."""

from dataclasses import dataclass, field
from typing import Any, Sequence


@dataclass
class PageResult:
    """Cursor-paginated query result container."""

    items: list[Any]
    next_cursor: str | None
    has_more: bool


class ScalableSearchEngine:
    """Indexed search abstraction over findings and incidents with cursor-based pagination."""

    def search_findings(
        self,
        findings: list[dict[str, Any]],
        severity: str | None = None,
        cwe_id: str | None = None,
        cursor: int = 0,
        limit: int = 10,
    ) -> PageResult:
        filtered = findings
        if severity:
            filtered = [f for f in filtered if f.get("severity") == severity]
        if cwe_id:
            filtered = [f for f in filtered if f.get("cwe") == cwe_id]

        start = cursor
        end = start + limit
        page_items = filtered[start:end]
        has_more = end < len(filtered)
        next_cursor = str(end) if has_more else None

        return PageResult(items=page_items, next_cursor=next_cursor, has_more=has_more)
