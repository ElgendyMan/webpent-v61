import pytest
from pydantic import ValidationError

from webpent.agents.smart_campaigns.agent import smart_campaigns_node
from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_contracts import (
    ResearchDecisionEngine,
    candidate_from_information_action,
    researcher_contract_for_action,
)
from webpent.shared.research_intelligence import ActionClass, InformationAction
from webpent.shared.research_nodes import next_best_action_node


def _candidate(**updates) -> CandidateAction:
    payload = {
        "action_id": "action:owner",
        "action_class": "identity_acquisition",
        "objective": "acquire an authorized owner context",
        "target_ref": "https://target.test/object/1",
        "gap_id": "gap:ownership",
        "expected_information_gain": 0.9,
        "likelihood": 0.8,
        "impact": 0.7,
        "evidence_potential": 0.9,
        "novelty": 0.6,
        "coverage_value": 0.9,
        "required_capabilities": ["http_read"],
        "capability": "http_read",
        "cost": 1.0,
    }
    payload.update(updates)
    return CandidateAction.model_validate(payload)


def test_specialized_researcher_contracts_are_mapped_and_advisory():
    action = InformationAction(
        action_id="action:workflow",
        action_class=ActionClass.WORKFLOW_REPLAY,
        objective="replay an observed workflow transition",
        target_ref="https://target.test/workflow",
    )
    contract = researcher_contract_for_action(action.action_class)
    candidate = candidate_from_information_action(action, gap_id="gap:workflow")

    assert contract is not None
    assert contract.researcher_id == "workflow-researcher"
    assert candidate.metadata["researcher_id"] == "workflow-researcher"
    assert candidate.metadata["researcher_evidence_focus"]
    assert candidate.metadata["advisory_only"] is True
    assert "requires_approval" not in candidate.metadata


def test_research_node_projection_preserves_specialized_researcher_metadata():
    result = next_best_action_node(
        {
            "smart_information_actions": [
                {
                    "action_id": "action:workflow",
                    "action_class": "workflow_replay",
                    "objective": "replay an observed workflow transition",
                    "target_ref": "https://target.test/workflow",
                    "method": "GET",
                    "capability": "http_read",
                    "expected_information_gain": 0.8,
                    "cost": 1.0,
                    "idempotency_key": "workflow:one",
                }
            ]
        }
    )

    candidate = result["research_candidate_actions"][0]
    assert candidate["metadata"]["researcher_id"] == "workflow-researcher"
    assert candidate["metadata"]["advisory_only"] is True
    assert candidate["metadata"]["utility_trace"]["version"] == "research-utility-v1"
    assert candidate["metadata"]["utility_trace"]["advisory_only"] is True


def test_research_context_is_checkpoint_safe_and_redacts_secret():
    context = ResearchContext.from_state(
        {
            "thread_id": "thread:test",
            "engagement_id": "engagement:test",
            "client_id": "client:test",
            "target_url": "https://target.test/?token=secret-value",
            "knowledge_gaps": [{"gap_id": "gap:one", "unknown": "owner"}],
        }
    )
    payload = context.as_dict()
    assert payload["checkpoint_safe"] is True
    assert payload["open_gap_ids"] == ["gap:one"]
    assert "secret-value" not in str(payload)


def test_candidate_action_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CandidateAction(
            action_id="action:test",
            action_class="discovery",
            objective="bounded discovery",
            unsupported_authority=True,
        )


def test_research_decision_exposes_bounded_utility_trace():
    engine = ResearchDecisionEngine()
    candidate = _candidate()
    decision = engine.score(
        candidate,
        available_capabilities={"http_read"},
        target_allowed=True,
    )

    payload = decision.as_dict()
    trace = payload["utility_trace"]
    assert payload["status"] == "ranked"
    assert trace["version"] == "research-utility-v1"
    assert trace["status"] == "ranked"
    assert trace["factors"] == {
        "likelihood": 0.8,
        "impact": 0.7,
        "evidence_potential": 0.9,
        "information_gain": 0.9,
        "novelty": 0.6,
        "coverage_value": 0.9,
    }
    assert trace["cost_terms"] == {
        "cost": 1.0,
        "failure_probability": 0.0,
        "scope_risk": 0.0,
        "rate_limit_cost": 0.0,
        "dependency_penalty": 0.0,
    }
    assert trace["base_score"] == decision.score
    assert trace["penalties"] == []
    assert trace["final_score"] == decision.score


def test_research_decision_engine_fails_closed_on_missing_capability_scope_and_budget():
    engine = ResearchDecisionEngine()
    candidate = _candidate()
    assert engine.score(candidate, available_capabilities={}).status == "blocked"
    assert engine.score(
        candidate,
        available_capabilities={"http_read"},
        target_allowed=False,
    ).reasons == ("target_scope_denied",)
    assert engine.score(
        candidate,
        available_capabilities={"http_read"},
        budget_remaining=0.0,
    ).reasons == ("budget_exhausted",)


def test_research_decision_engine_blocks_unmet_prerequisites_and_ranks_ready_alternative():
    engine = ResearchDecisionEngine()
    blocked = _candidate(
        action_id="action:blocked",
        prerequisites=["fact:owner-context"],
        expected_information_gain=1.0,
    )
    ready = _candidate(
        action_id="action:ready",
        prerequisites=["fact:surface-observed"],
        expected_information_gain=0.1,
    )

    blocked_decision = engine.score(
        blocked,
        available_capabilities={"http_read"},
        target_allowed=True,
        known_facts={"fact:surface-observed"},
    )
    ranked = engine.rank(
        [blocked, ready],
        available_capabilities={"http_read"},
        target_allowed=True,
        known_facts={"fact:surface-observed"},
    )

    assert blocked_decision.status == "blocked"
    assert blocked_decision.score == -1.0
    assert blocked_decision.reasons == ("missing_prerequisite:fact:owner-context",)
    assert ranked[0].candidate.action_id == "action:ready"
    assert all(
        item.candidate.action_id != "action:blocked" or item.status == "blocked"
        for item in ranked
    )


def test_research_decision_engine_penalizes_failed_revisit_until_new_evidence():
    engine = ResearchDecisionEngine()
    candidate = _candidate()
    first = engine.score(candidate, available_capabilities={"http_read"})
    failed = engine.score(
        candidate,
        available_capabilities={"http_read"},
        failed_path_fingerprints=[candidate.fingerprint()],
    )
    revisit = engine.score(
        candidate,
        available_capabilities={"http_read"},
        failed_path_fingerprints=[candidate.fingerprint()],
        new_evidence=True,
    )
    assert first.score > failed.score
    assert revisit.score == first.score
    assert "failed_path_revisit_penalty" in failed.reasons


def test_smart_campaigns_emits_typed_research_projection_without_execution():
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:test",
        "client_id": "client:test",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {"record_id": "surface:object:1", "url": "https://target.test/object/1"}
            ]
        },
        "relational_evidence": [],
        "authorization_matrix": {},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {"entries": []},
    }
    result = smart_campaigns_node(state)
    assert result["research_context"]["checkpoint_safe"] is True
    assert result["research_candidate_actions"]
    assert result["research_unified_decision_trace"]
    assert all(item["status"] == "ranked" for item in result["research_unified_decision_trace"])
    assert all(
        item["utility_trace"]["version"] == "research-utility-v1"
        for item in result["research_unified_decision_trace"]
    )
    assert result["campaign_task_outcomes"] == [] or all(
        item["status"] != "executed" for item in result["campaign_task_outcomes"]
    )


def test_smart_campaigns_replanning_penalizes_checkpointed_candidate_fingerprint():
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:replan",
        "client_id": "client:replan",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {"record_id": "surface:object:1", "url": "https://target.test/object/1"}
            ]
        },
        "relational_evidence": [],
        "authorization_matrix": {},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {"entries": []},
    }
    first = smart_campaigns_node(state)
    checkpointed = {
        **state,
        "research_unified_decision_trace": first["research_unified_decision_trace"],
        "research_candidate_actions": first["research_candidate_actions"],
        "research_decision_trace": first["research_decision_trace"],
    }
    replanned = smart_campaigns_node(checkpointed)
    owner = next(
        item
        for item in replanned["research_unified_decision_trace"]
        if item["candidate"]["action_class"] == "identity_acquisition"
    )
    assert "duplicate_without_new_evidence_penalty" in owner["reasons"]
    assert "duplicate_without_new_evidence" in owner["utility_trace"]["penalties"][0]


def test_negative_evidence_reorders_same_gap_without_suppressing_alternate_control():
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:negative-reorder",
        "client_id": "client:negative-reorder",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {"record_id": "surface:object:1", "url": "https://target.test/object/1"}
            ]
        },
        "relational_evidence": [],
        "authorization_matrix": {},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {"entries": []},
    }

    baseline = smart_campaigns_node(state)
    owner = next(
        item
        for item in baseline["research_candidate_actions"]
        if item["action_class"] == "identity_acquisition"
    )
    negative_state = {
        **state,
        "negative_evidence_ledger": [
            {
                "evidence_id": "negative:owner-path",
                "hypothesis_id": "hypothesis:ownership",
                "action_fingerprint": owner["fingerprint"],
                "client_id": state["client_id"],
                "engagement_id": state["engagement_id"],
                "reason": "owner path returned an inconclusive baseline",
            }
        ],
    }

    reordered = smart_campaigns_node(negative_state)
    ranked = reordered["research_unified_decision_trace"]
    assert ranked[0]["candidate"]["action_class"] == "negative_control"
    assert ranked[0]["candidate"]["action_id"].endswith(":denial")
    owner_decision = next(
        item for item in ranked if item["candidate"]["fingerprint"] == owner["fingerprint"]
    )
    assert owner_decision["status"] == "ranked"
    assert "failed_path_revisit_penalty" in owner_decision["reasons"]
    assert len(ranked) == 2
