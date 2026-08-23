"""Passive Attack Graph projection node.

The node is intentionally additive: it never performs network I/O, never
creates Findings, and returns an empty update unless explicitly enabled.
"""

from __future__ import annotations

import logging
from typing import Any

from webpent.shared.attack_graph import build_attack_graph

logger = logging.getLogger(__name__)


def _enabled() -> bool:
    """Read the feature flag fail-closed."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_attack_graph)
    except Exception:  # pragma: no cover - defensive configuration boundary
        logger.exception("Attack Graph flag lookup failed; keeping feature disabled")
        return False


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def attack_graph_node(state: dict[str, Any]) -> dict[str, Any]:
    """Project current evidence into a redacted, deterministic Attack Graph."""
    if not _enabled():
        return {}

    try:
        graph = build_attack_graph(
            state.get("mental_model"),
            relational_evidence=state.get("relational_evidence") or (),
            findings=state.get("findings") or (),
            hypotheses=state.get("hypotheses") or (),
            novel_behaviors=state.get("novel_behavior_observations") or (),
            causal_edges=state.get("causal_attack_edges") or (),
            coverage_gaps=state.get("research_failed_paths") or (),
            knowledge_gaps=state.get("knowledge_gaps") or (),
            runtime_capability_gaps=state.get("runtime_capability_gaps") or (),
            target_knowledge=state.get("target_knowledge") or {},
        )
    except Exception:
        logger.exception("Attack Graph projection failed; preserving legacy state")
        return {
            "coverage_gaps": [
                "Attack Graph projection failed; legacy findings pipeline preserved."
            ]
        }
    return {"attack_graph": graph, "causal_attack_graph": graph}


__all__ = ["attack_graph_node"]
