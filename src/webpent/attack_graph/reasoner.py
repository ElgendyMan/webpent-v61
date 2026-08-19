"""Conservative graph reasoning facade for coverage and task planning."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class AttackGraphReasoner:
    """Extract only explicit relationships from an attack graph."""

    def explain_edge(self, graph: Mapping[str, Any], edge_id: str) -> dict[str, Any]:
        edges = graph.get("edges", []) if isinstance(graph, Mapping) else []
        for edge in edges:
            if isinstance(edge, Mapping) and str(edge.get("id")) == edge_id:
                return {
                    "edge_id": edge_id,
                    "kind": str(edge.get("kind", "")),
                    "source_id": str(edge.get("source_id", "")),
                    "target_id": str(edge.get("target_id", "")),
                    "confidence": str(edge.get("confidence", "unknown")),
                    "evidence_refs": list(edge.get("evidence_refs") or []),
                    "authoritative": False,
                }
        return {
            "edge_id": edge_id,
            "status": "unknown",
            "evidence_refs": [],
            "authoritative": False,
        }

    def gaps(self, graph: Mapping[str, Any]) -> tuple[str, ...]:
        raw = graph.get("coverage_gaps", []) if isinstance(graph, Mapping) else []
        return tuple(dict.fromkeys(str(item) for item in raw if str(item).strip()))


__all__ = ["AttackGraphReasoner"]
