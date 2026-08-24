import pytest

from webpent.agents.specialists import (
    propose_access_control_tasks,
    propose_api_surface_tasks,
    propose_business_logic_tasks,
)

_BASE = {
    "engagement_id": "eng-1",
    "target_id": "target-1",
    "target_ref": "https://authorized.invalid",
    "objectives": ["review observed endpoint coverage", "compare workflow state transitions"],
    "required_capabilities": ["typed_browser", "typed_browser"],
}


def test_specialist_proposals_are_bounded_and_proposal_only() -> None:
    first = propose_api_surface_tasks(**_BASE)
    second = propose_api_surface_tasks(**_BASE)

    assert first == second
    assert len(first) == 2
    for proposal in first:
        assert proposal.proposal_only is True
        assert proposal.execution_authority == "ActionAuthority_required"
        assert proposal.candidate_action.requires_approval is True
        assert "proposal_only" in proposal.candidate_action.policy_tags
        assert proposal.candidate_action.metadata["engagement_id"] == "eng-1"
        assert proposal.research_task.operation == "plan"
        assert proposal.research_task.engagement_id == "eng-1"
        assert "central_sealed_replayable_proof_bundle" in proposal.research_task.required_evidence


def test_specialist_facades_keep_distinct_action_classes() -> None:
    access = propose_access_control_tasks(**{**_BASE, "objectives": ["compare role access"]})
    logic = propose_business_logic_tasks(**{**_BASE, "objectives": ["review illegal transition"]})

    assert access[0].candidate_action.action_class == "access_control_review"
    assert logic[0].candidate_action.action_class == "business_logic_review"
    assert access[0].specialist != logic[0].specialist


def test_specialist_requires_complete_scope() -> None:
    with pytest.raises(ValueError, match="specialist_scope_and_class_required"):
        propose_api_surface_tasks(
            engagement_id="",
            target_id="target-1",
            target_ref="authorized",
            objectives=["review"],
        )
