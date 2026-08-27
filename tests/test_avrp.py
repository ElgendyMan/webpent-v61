from __future__ import annotations

import pytest

from webpent.asros.quality_controller import ResearchQualityController
from webpent.asros.world_model import (
    BusinessIntent,
    EvidenceLineage,
    InvariantKind,
    SecurityInvariant,
    SecurityWorldModel,
)
from webpent.avrp import (
    AdvancedAttackChainReasoner,
    AdvancedResearchQualityReviewer,
    AttackChainHypothesis,
    AutonomousResearchLoopV2,
    EvidenceCorrelationEngine,
    ResearchMemoryState,
    ResearchOutcome,
    ResearchSelfImprovement,
)
from webpent.models.research import InformationObservation


def _chain(
    *, status: str = "hypothesis", refs: tuple[str, ...] = ("obs-1",)
) -> AttackChainHypothesis:
    return AttackChainHypothesis(
        chain_id="chain:test-001",
        vulnerability_class="broken_access_control",
        weakness="A protected object may be readable outside its ownership boundary.",
        supporting_condition="The object reference is available in a recorded observation.",
        privilege_boundary="owner versus requester boundary",
        business_impact="Potential unauthorized disclosure requires causal validation.",
        source_refs=refs,
        reasoning="The chain is a hypothesis until candidate/control evidence exists.",
        confidence=0.7,
        validation_requirement="Require candidate/control contrast and replayable evidence.",
        status=status,
    )


def test_state_snapshot_restore_is_scoped_and_replayable() -> None:
    state = ResearchMemoryState.new(target_ref="127.0.0.1:3000", engagement_id="eng-1")
    updated = state.apply_update(
        field_name="unknown_areas",
        value=["ownership boundary"],
        evidence_refs=["recorded:obs-1"],
        confidence=0.6,
        reason="The boundary remains unverified.",
        timestamp="2026-08-27T00:00:00+00:00",
    )
    snapshot = updated.snapshot()
    restored = ResearchMemoryState.restore(
        snapshot,
        expected_target_ref="127.0.0.1:3000",
        expected_engagement_id="eng-1",
    )
    assert restored.snapshot() == snapshot
    with pytest.raises(ValueError, match="target isolation"):
        ResearchMemoryState.restore(snapshot, expected_target_ref="127.0.0.1:4000")


def test_correlation_is_deterministic_and_redacted() -> None:
    observations = [
        InformationObservation(
            observation_id="obs-1",
            action_id="action-1",
            action_fingerprint="fingerprint-1",
            status="positive",
            evidence_refs=["recorded:obs-1"],
            metadata={
                "security_signals": ["object_identifier"],
                "object_identifier_ref": "account",
            },
        ),
        InformationObservation(
            observation_id="obs-2",
            action_id="action-2",
            action_fingerprint="fingerprint-2",
            status="negative",
            evidence_refs=["recorded:obs-2"],
            metadata={
                "security_signals": ["role_difference"],
                "role_difference_ref": "owner-requester",
            },
        ),
    ]
    engine = EvidenceCorrelationEngine()
    first = engine.correlate(observations, target_ref="127.0.0.1:3000")
    second = engine.correlate(observations, target_ref="127.0.0.1:3000")
    assert first == second
    assert first.relationships
    assert all("secret" not in str(item.model_dump()) for item in first.relationships)


def test_chain_reasoning_never_promotes_or_finds() -> None:
    hypothesis = object.__new__(object)
    with pytest.raises(TypeError):
        AdvancedAttackChainReasoner().reason([hypothesis])  # type: ignore[list-item]
    chain = _chain()
    review = AdvancedResearchQualityReviewer().review(chain)
    assert review.status == "blocked"
    assert review.finding_created is False
    assert review.policy_overridden is False
    assert review.qualification_effect is False


def test_self_improvement_is_same_scope_and_explainable() -> None:
    learner = ResearchSelfImprovement()
    outcomes = [
        ResearchOutcome(
            path_id="path-1",
            target_ref="127.0.0.1:3000",
            engagement_ref="eng-1",
            outcome="successful",
            evidence_refs=("recorded:obs-1",),
            reason="Recorded causal evidence was available.",
            value_score=0.8,
        ),
        ResearchOutcome(
            path_id="path-2",
            target_ref="other-target",
            engagement_ref="eng-1",
            outcome="successful",
            evidence_refs=("recorded:obs-2",),
            reason="Different scope must not update this target.",
            value_score=0.8,
        ),
    ]
    report = learner.learn(outcomes, target_ref="127.0.0.1:3000", engagement_ref="eng-1")
    assert report.analyzed_outcome_ids == ("path-1",)
    assert report.rejected_cross_scope == 1
    assert report.advisory_only is True
    assert all(item.hidden_state is False for item in report.updates)


def test_advisory_loop_continues_after_failures_and_is_advisory() -> None:
    lineage = EvidenceLineage(
        source="controlled-fixture", evidence_refs=("fixture:inv-1",), confidence=0.8
    )
    world = SecurityWorldModel(
        engagement_id="eng-loop-1",
        target_id="target-loop-1",
        knowledge_hash="d" * 64,
        business_intents=(
            BusinessIntent(
                intent_id="intent-loop-1",
                goal="read an owned record",
                workflow="record-read",
                lineage=lineage,
            ),
        ),
        invariants=(
            SecurityInvariant(
                invariant_id="inv-loop-1",
                statement="A subject can read only an owned record.",
                kind=InvariantKind.OWNERSHIP,
                subject="synthetic-subject",
                protected_resource="record/1",
                forbidden_conditions=("different-owner",),
                lineage=lineage,
            ),
        ),
    )
    memory = ResearchMemoryState.new(target_ref="target-loop-1", engagement_id="eng-loop-1")
    report = AutonomousResearchLoopV2().run(
        world,
        target_ref="target-loop-1",
        observations=[
            {
                "asset": "record/1",
                "metadata": {"vulnerability_classes": ["authorization"], "roles": ["owner"]},
                "evidence_refs": ["fixture:obs-1"],
            }
        ],
        behavioral_observations=[
            {
                "asset": "record/1",
                "role": "owner",
                "status": "observed",
                "source_refs": ["fixture:obs-1"],
            }
        ],
        attack_graph=[
            {
                "kind": "ownership",
                "steps": ["inspect recorded ownership relation"],
                "impact": 0.8,
                "confidence": 0.7,
                "required_capability": "analysis",
            }
        ],
        previous_failures=[
            {
                "hypothesis_id": "prior-hypothesis",
                "reason": "recorded path was blocked",
                "evidence_refs": ["fixture:failure-1"],
            }
        ],
        available_capabilities=["analysis"],
        memory_state=memory,
    )
    assert report.hypotheses
    assert report.selected_plan is not None
    assert report.selected_plan.decision == "selected"
    assert report.coverage is not None
    assert report.strategy_decision is not None
    assert report.strategy_decision.repeated_failure_count == 1
    assert report.updated_memory_state is not None
    assert report.execution_performed is False
    assert report.finding_created is False
    assert report.policy_overridden is False
    assert report.strategy_decision.advisory_only is True


def test_reviewer_composes_central_quality_flags_without_promotion() -> None:
    chain = _chain()
    controller = ResearchQualityController()
    insufficient = controller.review_after(
        hypothesis_id="test-001",
        evidence_refs=("recorded:candidate",),
        observation_count=2,
    )
    blocked_review = AdvancedResearchQualityReviewer().review(
        chain, post_execution_review=insufficient
    )
    assert blocked_review.status == "blocked"
    assert "causal_evidence_present" in blocked_review.missing_requirements
    complete = controller.review_after(
        hypothesis_id="test-001",
        evidence_refs=("recorded:candidate", "recorded:control"),
        causal_oracle_passed=True,
        negative_control_passed=True,
        proof_sealed=True,
        proof_replayable=True,
        observation_count=2,
    )
    ready = AdvancedResearchQualityReviewer().review(
        chain, post_execution_review=complete
    )
    assert ready.status == "advisory_ready"
    assert ready.finding_created is False
    assert ready.human_signoff is False
    assert ready.qualification_effect is False


def test_advisory_components_do_not_execute_io() -> None:
    with pytest.raises(TypeError):
        EvidenceCorrelationEngine().correlate(["not-a-mapping"], target_ref="tgt")  # type: ignore[list-item]
    blocked = _chain(status="blocked", refs=("obs-1",))
    review = AdvancedResearchQualityReviewer().review(blocked)
    assert review.status == "blocked"
    assert review.causal_evidence_present is False
    assert review.human_signoff is False
