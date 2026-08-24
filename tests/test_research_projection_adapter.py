import pytest

from webpent.research_engine import (
    BudgetUsage,
    ProjectionPlanningAdapter,
    ProjectionPlanningInput,
    ResearchOrchestrator,
)


def test_projection_adapter_is_serializable_and_does_not_infer_proof() -> None:
    projection = ProjectionPlanningAdapter.from_sources(
        engagement_id="eng-1",
        target_id="target-1",
        target_brain={
            "engagement_id": "eng-1",
            "coverage_gaps": ["no_workflow_observations"],
            "knowledge_gaps": ["object_model_unknown"],
            "evidence_refs": ["evidence:observed"],
        },
        attack_graph={"engagement_id": "eng-1", "gaps": ["missing_permission_model"]},
        knowledge_gaps=["missing browser capability", "secret token must not pass"],
    )

    assert isinstance(projection, ProjectionPlanningInput)
    assert projection.has_application_model is True
    assert projection.has_target_backed_observation is False
    assert projection.has_negative_control is False
    assert "no_workflow_observations" in projection.planning_hints
    assert "missing browser capability" in projection.planning_hints
    assert all("token" not in item.lower() for item in projection.planning_hints)
    assert projection.as_dict()["target_id"] == "target-1"


def test_projection_adapter_rejects_cross_scope_sources() -> None:
    with pytest.raises(ValueError, match="projection_engagement_mismatch"):
        ProjectionPlanningAdapter.from_sources(
            engagement_id="eng-1",
            target_id="target-1",
            target_brain={"engagement_id": "eng-2", "coverage_gaps": ["gap"]},
        )


def test_orchestrator_consumes_projection_gaps_as_bounded_plan_tasks() -> None:
    projection = ProjectionPlanningAdapter.from_sources(
        engagement_id="eng-1",
        target_id="target-1",
        target_brain={"engagement_id": "eng-1", "coverage_gaps": ["workflow_missing"]},
        has_target_backed_observation=True,
    )

    plan = ResearchOrchestrator().plan_from_projections(projection)

    assert plan.engagement_id == "eng-1"
    assert plan.target_id == "target-1"
    assert plan.projection_hints == ("workflow_missing",)
    assert any(task.reason == "projection_gap" for task in plan.tasks)
    assert all(task.operation == "plan" for task in plan.tasks)
    assert plan.budget_decision.allowed is True


def test_orchestrator_budget_stop_remains_safe_with_projection_hints() -> None:
    projection = ProjectionPlanningInput(
        engagement_id="eng-1",
        target_id="target-1",
        planning_hints=("gap",),
    )
    plan = ResearchOrchestrator().plan(
        engagement_id=projection.engagement_id,
        target_id=projection.target_id,
        planning_hints=projection.planning_hints,
        usage=BudgetUsage(requests=5000),
    )

    assert plan.tasks == ()
    assert plan.stop_reason == "request_budget_exhausted"
    assert plan.projection_hints == ("gap",)
