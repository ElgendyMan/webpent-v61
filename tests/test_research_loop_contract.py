from __future__ import annotations

from webpent.agents.smart_campaigns.agent import _research_projections
from webpent.shared.research_intelligence import ResearchLoopContract


def _state() -> dict[str, object]:
    return {
        "engagement_id": "engagement-a",
        "client_id": "client-a",
        "mental_model": {"nodes": {}, "edges": []},
        "target_understanding": {},
        "findings": [],
        "hypotheses": [],
        "action_budget": {
            "limit": 4.0,
            "spent": 1.5,
            "remaining": 2.5,
            "iterations": 1,
            "iterations_limit": 3,
            "replans": 0,
            "replans_limit": 1,
            "status": "active",
        },
        "stop_decision": {
            "should_stop": False,
            "reason": "",
            "category": "normal",
            "safe_to_resume": True,
        },
        "memory_summary": {
            "records": 4,
            "retrievals": 2,
            "retrieval_items": 3,
            "feedback_records": 1,
            "retrieval_budget_remaining": 8,
            "items": ["Authorization: Bearer raw-secret"],
        },
    }


def test_research_loop_contract_is_stable_and_resume_safe() -> None:
    state = _state()
    first = ResearchLoopContract.from_state(
        state,
        target_knowledge={"schema_version": 1, "engagement_id": "engagement-a"},
        gap_ids=["gap:one"],
        selected_actions=["action:one"],
        outcomes=["executed", "executed", "infrastructure_failure"],
    ).as_dict()
    second = ResearchLoopContract.from_state(
        state,
        target_knowledge={"schema_version": 1, "engagement_id": "engagement-a"},
        gap_ids=["gap:one"],
        selected_actions=["action:one"],
        outcomes=["executed", "infrastructure_failure"],
    ).as_dict()

    assert first["target_knowledge_fingerprint"] == second["target_knowledge_fingerprint"]
    assert first["budget"]["remaining"] == 2.5
    assert first["stop"]["safe_to_resume"] is True
    assert first["outcome_taxonomy"] == ["executed", "infrastructure_failure"]
    assert first["memory"] == {
        "records": 4,
        "retrievals": 2,
        "retrieval_items": 3,
        "feedback_records": 1,
        "retrieval_budget_remaining": 8,
    }
    assert first["llm"] == {
        "count": 0,
        "accepted": 0,
        "needs_review": 0,
        "rejected": 0,
    }


def test_research_contract_records_only_bounded_llm_statuses() -> None:
    state = _state()
    contract = ResearchLoopContract.from_state(
        state,
        target_knowledge={},
        llm_trace=[
            {"status": "accepted", "decision_id": "ok"},
            {"status": "needs_review", "reasons": ["approval"]},
            {"status": "rejected", "untrusted_text": "api_key=raw-secret"},
            {"status": "unknown", "decision_id": "ignored"},
        ],
    ).as_dict()

    assert contract["llm"] == {
        "count": 3,
        "accepted": 1,
        "needs_review": 1,
        "rejected": 1,
    }
    rendered = repr(contract)
    assert "raw-secret" not in rendered
    assert "decision_id" not in rendered


def test_research_projections_update_knowledge_and_attack_graph_without_authority() -> None:
    state = _state()
    projection = _research_projections(
        state,
        knowledge_gaps=[{"gap_id": "gap:surface"}],
        selected_actions=["action:surface"],
        outcomes=[{"status": "blocked", "reason": "missing_capability"}],
        llm_trace=[{"status": "accepted", "decision_id": "advisory-only"}],
    )

    assert projection["target_knowledge"]["engagement_id"] == "engagement-a"
    assert projection["target_knowledge_version"] == 1
    assert projection["research_loop_contract"]["knowledge_updated"] is True
    assert projection["research_loop_contract"]["outcome_taxonomy"] == ["blocked"]
    assert projection["research_loop_contract"]["llm"]["accepted"] == 1
    assert isinstance(projection["attack_graph"], dict)
    assert "execute" not in projection["research_loop_contract"]


def test_research_contract_redacts_secret_like_values() -> None:
    state = _state()
    contract = ResearchLoopContract.from_state(
        state,
        target_knowledge={"note": "api_key=secret-value"},
        gap_ids=["gap:token=secret-value"],
        selected_actions=["action:cookie=secret-value"],
        outcomes=["unknown"],
    ).as_dict()

    rendered = repr(contract)
    assert "secret-value" not in rendered
    assert contract["outcome_taxonomy"] == ["unknown"]
