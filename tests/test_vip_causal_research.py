from __future__ import annotations

from webpent.graph.builder import (
    NODE_AUTONOMOUS_CONTROLLER,
    NODE_CAUSAL_RESEARCH,
    route_after_active_research,
    route_after_causal_research,
)
from webpent.models.research import CandidateAction
from webpent.shared.causal_research import build_causal_research_projection


def _candidate(*, engagement_id: str = "engagement-1") -> dict[str, object]:
    return CandidateAction(
        action_id="action-read-profile",
        action_class="read_only",
        objective="read profile metadata safely",
        hypothesis_id="hypothesis-profile",
        target_ref="https://target.test/profile",
        idempotency_key="fingerprint-read-profile",
        metadata={"source": "knowledge_gap", "engagement_id": engagement_id},
    ).model_dump(mode="json")


def _negative(*, engagement_id: str = "engagement-1") -> dict[str, object]:
    return {
        "evidence_id": "negative:profile-1",
        "hypothesis_id": "hypothesis-profile",
        "action_fingerprint": "fingerprint-read-profile",
        "identity_context": "anonymous",
        "tenant_context": "tenant-a",
        "method": "GET",
        "workflow_state": "logged_out",
        "reason": "no profile marker observed",
        "confidence": 0.9,
        "client_id": "client-1",
        "engagement_id": engagement_id,
    }


def test_causal_projection_links_finding_and_consults_negative_ledger() -> None:
    state = {
        "client_id": "client-1",
        "engagement_id": "engagement-1",
        "findings": [
            {
                "id": "finding-1",
                "title": "Observed profile issue",
                "url": "https://target.test/profile",
                "vuln_class": "idor",
                "confidence_level": "Needs Human Review",
                "hypothesis_id": "hypothesis-profile",
                "evidence": {"evidence_refs": ["replay:1"]},
                "evidence_contract": {
                    "causal_signal": True,
                    "negative_control_complete": True,
                },
            }
        ],
        "negative_evidence_ledger": [_negative()],
        "research_candidate_actions": [_candidate()],
    }

    result = build_causal_research_projection(state)

    assert result["causal_attack_edges"]
    finding_edge = next(
        edge
        for edge in result["causal_attack_edges"]
        if edge["kind"] == "observation_supports_hypothesis"
    )
    assert finding_edge["source_id"] == "finding:finding-1"
    assert finding_edge["target_id"] == "hypothesis:hypothesis-profile"
    assert finding_edge["causal_signal"] is True
    link = result["research_unified_decision_trace"][0]
    assert link["causal_edge_refs"]
    assert link["negative_evidence_reusable_count"] == 1
    assert result["causal_attack_graph"]["negative_evidence_consulted"] is True
    assert result["research_session"]["causal_attack_graph"]


def test_negative_ledger_is_fail_closed_across_engagements() -> None:
    state = {
        "client_id": "client-1",
        "engagement_id": "engagement-2",
        "negative_evidence_ledger": [_negative(engagement_id="engagement-1")],
        "research_candidate_actions": [_candidate(engagement_id="engagement-2")],
    }

    result = build_causal_research_projection(state)

    assert result["research_unified_decision_trace"][0]["negative_evidence_reusable_count"] == 0
    assert (
        result["research_candidate_actions"][0]["metadata"]["negative_evidence_consulted"]
        is True
    )


def test_active_research_always_passes_through_causal_projection() -> None:
    state = {"research_active_observations": [{"status": "inconclusive"}]}

    assert route_after_active_research(state) == NODE_CAUSAL_RESEARCH


def test_causal_projection_reenters_only_bounded_controller() -> None:
    state = {
        "research_candidate_actions": [_candidate()],
        "autonomous_controller_runs": 0,
        "smart_replanning": {"max_replan_rounds": 2},
    }

    assert route_after_causal_research(state) == NODE_AUTONOMOUS_CONTROLLER

    exhausted = {**state, "autonomous_controller_runs": 2}
    assert route_after_causal_research(exhausted) != NODE_AUTONOMOUS_CONTROLLER
