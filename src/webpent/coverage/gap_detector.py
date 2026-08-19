"""Deterministic coverage-gap detection facade."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from webpent.coverage.coverage_map import CoverageMap


class CoverageGapDetector:
    """Return explicit gaps from the coverage projection only."""

    _OPEN = {
        "not_scanned",
        "blocked_by_precondition",
        "policy_block",
        "infrastructure_failure",
        "inconclusive",
        "human_review_only",
        "missing-validator",
    }

    def __init__(self, *, coverage_map: CoverageMap | None = None) -> None:
        self.coverage_map = coverage_map or CoverageMap()

    def detect(self, state: Mapping[str, Any]) -> list[dict[str, Any]]:
        projection = self.coverage_map.project(state)
        return [
            dict(entry)
            for entry in projection.get("entries", [])
            if isinstance(entry, Mapping) and str(entry.get("status")) in self._OPEN
        ]


__all__ = ["CoverageGapDetector"]
