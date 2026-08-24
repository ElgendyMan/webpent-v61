from __future__ import annotations

import pytest

from webpent.models.hypothesis import HypothesisStatus
from webpent.research_engine import (
    ConfidenceSignals,
    ResearchBudget,
    ResearchOrchestrator,
    ResearchState,
    ResearchTask,
    assess_confidence,
)
from webpent.research_engine.hypothesis_manager import HypothesisDraft, HypothesisManager


def test_orchestrator_is_target_scoped_and_bounded() -> None:
    plan = ResearchOrchestrator(ResearchBudget(max_requests=2)).plan(
        engagement_id="eng-1",
        target_id="target-1",
    )
    assert plan.tasks
    assert all(task.engagement_id == "eng-1" for task in plan.tasks)
    assert all(task.target_id == "target-1" for task in plan.tasks)
    assert len(plan.tasks) <= 2


def test_research_state_rejects_cross_scope_tasks() -> None:
    state = ResearchState(engagement_id="eng-1", target_id="target-1")
    task = ResearchTask(
        task_id="task-1",
        engagement_id="eng-2",
        target_id="target-1",
        objective="observe",
    )
    with pytest.raises(ValueError, match="scope_mismatch"):
        state.admit_task(task)


def test_confidence_never_allows_direct_promotion() -> None:
    assessment = assess_confidence(
        ConfidenceSignals(
            source_quality=1,
            reproducibility=1,
            evidence_completeness=1,
            negative_control=1,
            causal_signal=1,
        )
    )
    assert assessment.tier == "verified_pending_bundle"
    assert assessment.promotion_allowed is False
    assert assessment.reason == "central_sealed_replayable_bundle_required"


def test_hypothesis_manager_uses_existing_lifecycle_contract() -> None:
    hypothesis = HypothesisManager().create(
        HypothesisDraft(
            target_id="http://127.0.0.1:18000",
            vulnerability_class="not-a-known-class",
            reasoning="The response needs controlled validation.",
            evidence_needed=["target_observation"],
            validation_method="typed_replay",
            confidence=0.4,
        ),
        engagement_id="eng-1",
        hypothesis_id="00000000-0000-0000-0000-000000000001",
    )
    assert hypothesis.status == HypothesisStatus.UNEXPLORED.value
    assert hypothesis.vuln_class == "unknown"
    result = HypothesisManager().record_observation(hypothesis, {"outcome": "validated"})
    assert result.accepted is False
    assert hypothesis.status == HypothesisStatus.UNEXPLORED.value
